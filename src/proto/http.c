/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http.h"

#include "codec.h"

#include "io/io.h"
#include "io/memory.h"
#include "io/stream.h"
#include "net/http.h"
#include "os/socket.h"
#include "utils/ascii.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>

const char *http_content_encoding_str[] = {
	[CENCODING_NONE] = NULL,
	[CENCODING_DEFLATE] = "deflate",
	[CENCODING_GZIP] = "gzip",
};

static int hex_digit(const unsigned char c)
{
	if ('0' <= c && c <= '9') {
		return c - '0';
	}
	if ('a' <= c && c <= 'f') {
		return 10 + (c - 'a');
	}
	if ('A' <= c && c <= 'F') {
		return 10 + (c - 'A');
	}
	return -1;
}

void http_conn_init(
	struct http_conn *restrict p, const int fd,
	const enum http_conn_state mode,
	const struct http_parsehdr_cb on_header, uint_least64_t *const byt_recv,
	uint_least64_t *const byt_sent)
{
	p->state = mode;
	p->mode = mode;
	p->http_status = HTTP_BAD_REQUEST;
	p->fd = fd;

	p->msg = (struct http_message){ 0 };
	p->next = NULL;
	p->expect_continue = false;

	p->hdr = (struct http_headers){ 0 };
	p->on_header = on_header;

	p->wpos = p->cpos = 0;
	p->cbuf = NULL;

	BUF_INIT(p->rbuf, 0);
	BUF_INIT(p->wbuf, 0);
	p->byt_recv = byt_recv;
	p->byt_sent = byt_sent;
}

/* parse_*: 0 on success, 1 if more data is needed, -1 on error */
static int parse_message(struct http_conn *restrict p)
{
	char *next = p->next;
	if (next == NULL) {
		next = (char *)p->rbuf.data;
		p->next = next;
	}

	struct http_message *restrict msg = &p->msg;
	next = http_parse(next, msg);
	if (next == NULL) {
		LOGD("http: failed parsing message");
		if (p->state == STATE_PARSE_REQUEST) {
			p->state = STATE_PARSE_ERROR;
			return 0;
		}
		return -1;
	}

	if (next == p->next) {
		if (p->rbuf.len + 1 >= p->rbuf.cap) {
			p->http_status = HTTP_ENTITY_TOO_LARGE;
			p->state = STATE_PARSE_ERROR;
			return 0;
		}
		return 1;
	}

	LOGVV_F("http_message: `%s' `%s' `%s'", msg->any.field1,
		msg->any.field2, msg->any.field3);

	const char *version = NULL;
	switch (p->state) {
	case STATE_PARSE_REQUEST:
		version = msg->req.version;
		break;
	case STATE_PARSE_RESPONSE:
		version = msg->rsp.version;
		break;
	default:
		FAILMSGF("unexpected http parser state: %d", p->state);
	}
	if (strncmp(version, "HTTP/1.", 7) != 0) {
		LOGD_F("http: unsupported protocol `%s'", version);
		if (p->state == STATE_PARSE_REQUEST) {
			p->state = STATE_PARSE_ERROR;
			return 0;
		}
		return -1;
	}

	p->next = next;
	p->state = STATE_PARSE_HEADER;
	return 0;
}

static bool parse_header_kv(
	const struct http_conn *restrict p, const char *restrict key,
	char *restrict value)
{
	LOGVV_F("http_header: \"%s: %s\"", key, value);
	return p->on_header.func(p->on_header.ctx, key, value);
}

static int parse_header(struct http_conn *restrict p)
{
	char *next = p->next;
	char *key, *value;

	next = http_parsehdr(next, &key, &value);
	if (next == NULL) {
		LOGD("http: failed parsing header");
		if (p->mode == STATE_PARSE_REQUEST) {
			p->state = STATE_PARSE_ERROR;
			return 0;
		}
		return -1;
	}

	if (next == p->next) {
		return 1;
	}

	p->next = next;

	/* NULL key indicates end of headers */
	if (key == NULL) {
		p->cbuf = NULL;
		p->state = STATE_PARSE_CONTENT;
		return 0;
	}

	if (!parse_header_kv(p, key, value)) {
		p->state = STATE_PARSE_ERROR;
		return 0;
	}
	return 0;
}

/* send a short message directly to the socket, bypassing the buffers */
static bool reply_short(struct http_conn *restrict p, const char *s)
{
	const size_t n = strlen(s);
	ASSERT(n < 256);
	LOG_BIN_F(VERBOSE, s, n, 0, "reply_short: [fd:%d] %zu bytes", p->fd, n);

	const ssize_t nsend = send(p->fd, s, n, 0);
	if (nsend < 0) {
		const int err = errno;
		LOGW_F("send: [fd:%d] (%d) %s", p->fd, err, strerror(err));
		return false;
	}
	if ((size_t)nsend != n) {
		LOGW_F("send: [fd:%d] short send %zu < %zu", p->fd,
		       (size_t)nsend, n);
		return false;
	}
	return true;
}

static int parse_content(struct http_conn *restrict p)
{
	/* only Content-Length based content is handled here */
	if (!p->hdr.content.has_length) {
		return 0;
	}

	const size_t content_length = p->hdr.content.length;
	if (content_length == 0) {
		return 0;
	}

	if (content_length > HTTP_MAX_CONTENT) {
		p->http_status = HTTP_ENTITY_TOO_LARGE;
		p->state = STATE_PARSE_ERROR;
		return 0;
	}

	/* Initialize content buffer on first call */
	if (p->cbuf == NULL) {
		p->cbuf = VBUF_NEW(content_length);
		if (p->cbuf == NULL) {
			LOGOOM();
			return -1;
		}

		/* Copy any content already in read buffer */
		const size_t pos = (unsigned char *)p->next - p->rbuf.data;
		const size_t len = p->rbuf.len - pos;
		VBUF_APPEND(p->cbuf, p->next, len);

		if (p->expect_continue) {
			if (!reply_short(p, "HTTP/1.1 100 Continue\r\n\r\n")) {
				return -1;
			}
		}
	}

	if (VBUF_LEN(p->cbuf) < content_length) {
		return 1;
	}
	return 0;
}

/* recv_*: 1 on success, 0 if no data, -1 on error or EOF */
static int recv_request(struct http_conn *restrict p)
{
	/* reserve 1 byte for the null terminator */
	size_t n = p->rbuf.cap - p->rbuf.len - 1;

	const int err = socket_recv(p->fd, p->rbuf.data + p->rbuf.len, &n);
	if (err != 0) {
		if (err == EAGAIN || err == EWOULDBLOCK) {
			return 0;
		}
		LOGD_F("recv: (%d) %s", err, strerror(err));
		return -1;
	}
	if (n == 0) {
		LOGD("recv: early EOF");
		return -1;
	}

	p->rbuf.len += n;
	p->rbuf.data[p->rbuf.len] = '\0';
	if (p->byt_recv != NULL) {
		*p->byt_recv += (uint_least64_t)n;
	}
	return 1;
}

static int recv_content(const struct http_conn *restrict p)
{
	unsigned char *b;
	size_t n;
	VBUF_SPACE(b, n, p->cbuf);

	const int err = socket_recv(p->fd, b, &n);
	if (err != 0) {
		if (err == EAGAIN || err == EWOULDBLOCK) {
			return 0;
		}
		LOGD_F("recv: (%d) %s", err, strerror(err));
		return -1;
	}
	if (n == 0) {
		LOGD("recv: early EOF");
		return -1;
	}

	p->cbuf->len += n;
	if (p->byt_recv != NULL) {
		*p->byt_recv += (uint_least64_t)n;
	}
	return 1;
}

int http_conn_recv(struct http_conn *restrict p)
{
	switch (p->state) {
	case STATE_PARSE_REQUEST:
	case STATE_PARSE_RESPONSE:
	case STATE_PARSE_HEADER: {
		const int r = recv_request(p);
		if (r < 0) {
			return -1;
		}
		if (r == 0) {
			return 1;
		}
		break;
	}
	case STATE_PARSE_CONTENT: {
		const int r = recv_content(p);
		if (r < 0) {
			return -1;
		}
		if (r == 0) {
			return 1;
		}
		break;
	}
	default:
		return -1;
	}

	for (;;) {
		int ret;
		switch (p->state) {
		case STATE_PARSE_REQUEST:
		case STATE_PARSE_RESPONSE:
			ret = parse_message(p);
			if (ret != 0) {
				return ret;
			}
			break;
		case STATE_PARSE_HEADER:
			ret = parse_header(p);
			if (ret != 0) {
				return ret;
			}
			break;
		case STATE_PARSE_CONTENT:
			ret = parse_content(p);
			if (ret != 0) {
				return ret;
			}
			p->state = STATE_PARSE_OK;
			/* fallthrough */
		case STATE_PARSE_ERROR:
		case STATE_PARSE_OK:
			return 0;
		default:
			FAILMSGF("unexpected http parser state: %d", p->state);
		}
	}
}

int http_conn_send(struct http_conn *restrict p, const int fd)
{
	{
		const unsigned char *buf = p->wbuf.data + p->wpos;
		size_t len = p->wbuf.len - p->wpos;
		const int err = socket_send(fd, buf, &len);
		if (err != 0) {
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == ENOBUFS || err == ENOMEM) {
				return 1;
			}
			return -1;
		}
		p->wpos += len;
		if (p->byt_sent != NULL) {
			*p->byt_sent += (uint_least64_t)len;
		}
		if (p->wpos < p->wbuf.len) {
			return 1;
		}
	}

	if (p->cbuf == NULL) {
		return 0;
	}

	{
		const unsigned char *buf;
		size_t len;
		VBUF_VIEW(buf, len, p->cbuf, p->cpos);
		const int err = socket_send(fd, buf, &len);
		if (err != 0) {
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == ENOBUFS || err == ENOMEM) {
				return 1;
			}
			return -1;
		}
		p->cpos += len;
		if (p->byt_sent != NULL) {
			*p->byt_sent += (uint_least64_t)len;
		}
		if (p->cpos < VBUF_LEN(p->cbuf)) {
			return 1;
		}
	}

	VBUF_FREE(p->cbuf);
	return 0;
}

void http_body_init(
	struct http_body *restrict d, const enum http_body_mode mode,
	const size_t content_length)
{
	*d = (struct http_body){ .mode = mode };
	switch (mode) {
	case HTTP_BODY_NONE:
		d->done = true;
		return;
	case HTTP_BODY_CONTENT_LENGTH:
		d->content_length = content_length;
		d->done = (content_length == 0);
		return;
	case HTTP_BODY_CHUNKED:
		d->chunk_state = HTTP_BODY_CHUNK_SIZE_LINE;
		return;
	case HTTP_BODY_EOF:
		return;
	}
	FAILMSG("unexpected http body mode");
}

static bool
parse_chunk_size_line(const char *restrict line, size_t *restrict out_size)
{
	uintmax_t v = 0;
	bool has_digit = false;
	const unsigned char *p = (const unsigned char *)line;
	for (; *p != '\0'; p++) {
		const int d = hex_digit(*p);
		if (d < 0) {
			break;
		}
		has_digit = true;
		if (v > (uintmax_t)(SIZE_MAX - (uintmax_t)d) / 16u) {
			return false;
		}
		v = v * 16u + (uintmax_t)d;
	}
	if (!has_digit) {
		return false;
	}
	for (; *p == ' ' || *p == '\t'; p++) {
	}
	if (*p != '\0' && *p != ';') {
		return false;
	}
	*out_size = (size_t)v;
	return true;
}

bool http_body_consume(
	struct http_body *restrict d, const unsigned char *restrict data,
	const size_t len, const struct http_body_data_cb on_data)
{
	if (len == 0) {
		return true;
	}
	switch (d->mode) {
	case HTTP_BODY_NONE:
		return false;
	case HTTP_BODY_CONTENT_LENGTH: {
		if (d->done) {
			return false;
		}
		const size_t remain = d->content_length - d->consumed;
		if (len > remain) {
			return false;
		}
		if (!on_data.func(on_data.ctx, data, len)) {
			return false;
		}
		d->consumed += len;
		if (d->consumed == d->content_length) {
			d->done = true;
		}
		return true;
	}
	case HTTP_BODY_EOF:
		if (!on_data.func(on_data.ctx, data, len)) {
			return false;
		}
		d->consumed += len;
		return true;
	case HTTP_BODY_CHUNKED:
		break;
	}

	for (size_t i = 0; i < len; i++) {
		const unsigned char c = data[i];
		switch (d->chunk_state) {
		case HTTP_BODY_CHUNK_SIZE_LINE:
		case HTTP_BODY_CHUNK_TRAILER_LINE:
			if (c == '\r') {
				continue;
			}
			if (c != '\n') {
				if (d->line_len + 1 >= sizeof(d->line)) {
					return false;
				}
				d->line[d->line_len++] = (char)c;
				continue;
			}
			d->line[d->line_len] = '\0';
			if (d->chunk_state == HTTP_BODY_CHUNK_SIZE_LINE) {
				size_t sz;
				if (!parse_chunk_size_line(d->line, &sz)) {
					return false;
				}
				d->chunk_left = sz;
				d->line_len = 0;
				if (sz == 0) {
					d->chunk_state =
						HTTP_BODY_CHUNK_TRAILER_LINE;
				} else {
					d->chunk_state = HTTP_BODY_CHUNK_DATA;
				}
				continue;
			}
			if (d->line_len == 0) {
				d->chunk_state = HTTP_BODY_CHUNK_DONE;
				d->done = true;
				return (i + 1 == len);
			}
			d->line_len = 0;
			continue;
		case HTTP_BODY_CHUNK_DATA: {
			const size_t remain = len - i;
			size_t n = d->chunk_left;
			if (n > remain) {
				n = remain;
			}
			if (!on_data.func(on_data.ctx, data + i, n)) {
				return false;
			}
			d->consumed += n;
			d->chunk_left -= n;
			i += n - 1;
			if (d->chunk_left == 0) {
				d->chunk_state = HTTP_BODY_CHUNK_DATA_CR;
			}
		}
			continue;
		case HTTP_BODY_CHUNK_DATA_CR:
			if (c != '\r') {
				return false;
			}
			d->chunk_state = HTTP_BODY_CHUNK_DATA_LF;
			continue;
		case HTTP_BODY_CHUNK_DATA_LF:
			if (c != '\n') {
				return false;
			}
			d->chunk_state = HTTP_BODY_CHUNK_SIZE_LINE;
			continue;
		case HTTP_BODY_CHUNK_DONE:
			return false;
		}
	}
	return true;
}

bool http_body_finish(struct http_body *restrict d)
{
	switch (d->mode) {
	case HTTP_BODY_NONE:
		return true;
	case HTTP_BODY_CONTENT_LENGTH:
	case HTTP_BODY_CHUNKED:
		return d->done;
	case HTTP_BODY_EOF:
		d->done = true;
		return true;
	}
	FAILMSG("unexpected http body mode");
}

bool parsehdr_accept_te(struct http_conn *restrict p, char *restrict value)
{
	value = strtrimspace(value);

	if (value[0] == '\0') {
		p->hdr.transfer.accept = TENCODING_NONE;
		return true;
	}

	if (strcmp(value, "chunked") == 0) {
		p->hdr.transfer.accept = TENCODING_CHUNKED;
		return true;
	}

	return false;
}

bool parsehdr_transfer_encoding(
	struct http_conn *restrict p, char *restrict value)
{
	value = strtrimspace(value);

	if (value[0] == '\0') {
		p->hdr.transfer.encoding = TENCODING_NONE;
		return true;
	}

	if (strcmp(value, "chunked") == 0) {
		p->hdr.transfer.encoding = TENCODING_CHUNKED;
		return true;
	}

	return false;
}

bool parsehdr_accept_encoding(struct http_conn *restrict p, char *restrict value)
{
	if (strcmp(value, "*") == 0) {
		p->hdr.accept_encoding = CENCODING_DEFLATE;
		return true;
	}

	const char *deflate = http_content_encoding_str[CENCODING_DEFLATE];
	for (char *token = strtok(value, ","); token != NULL;
	     token = strtok(NULL, ",")) {
		/* Remove quality value if present */
		char *q = strchr(token, ';');
		if (q != NULL) {
			*q = '\0';
		}

		token = strtrimspace(token);
		if (strcasecmp(token, deflate) == 0) {
			p->hdr.accept_encoding = CENCODING_DEFLATE;
			return true;
		}
	}

	/* Valid header, but no supported encoding — leave accept_encoding as CENCODING_NONE */
	return true;
}

bool parsehdr_content_length(
	struct http_conn *restrict p, const char *restrict value)
{
	char *endptr;
	const uintmax_t lenvalue = strtoumax(value, &endptr, 10);

	if (*endptr || lenvalue > SIZE_MAX) {
		return false;
	}

	const size_t content_length = (size_t)lenvalue;

	/* CONNECT method must not have Content-Length */
	if (strcmp(p->msg.req.method, "CONNECT") == 0) {
		return false;
	}

	p->hdr.content.has_length = true;
	p->hdr.content.length = content_length;
	return true;
}

bool parsehdr_content_encoding(
	struct http_conn *restrict p, const char *restrict value)
{
	for (size_t i = 0; i < CENCODING_MAX; i++) {
		if (http_content_encoding_str[i] == NULL) {
			continue;
		}
		if (strcasecmp(value, http_content_encoding_str[i]) == 0) {
			p->hdr.content.encoding = (enum content_encodings)i;
			return true;
		}
	}

	p->http_status = HTTP_UNSUPPORTED_MEDIA_TYPE;
	return false;
}

bool parsehdr_expect(struct http_conn *restrict p, char *restrict value)
{
	value = strtrimspace(value);

	if (strcasecmp(value, "100-continue") != 0) {
		p->http_status = HTTP_EXPECTATION_FAILED;
		return false;
	}

	p->expect_continue = true;
	return true;
}

bool parsehdr_connection(struct http_conn *restrict p, char *restrict value)
{
	p->hdr.connection = value;
	return true;
}

const char *parsehdr_connection_token(
	const char *restrict p, const char **restrict tok,
	size_t *restrict toklen)
{
	*tok = NULL;
	*toklen = 0;
	if (p == NULL) {
		return NULL;
	}
	/* skip OWS and comma separators (RFC 7230 token-list) */
	for (; *p == ' ' || *p == '\t' || *p == ','; p++) {
	}
	if (*p == '\0') {
		return p;
	}
	/* locate end of token */
	const char *const start = p;
	for (; *p != '\0' && *p != ',' && *p != ' ' && *p != '\t'; p++) {
	}
	*tok = start;
	*toklen = (size_t)(p - start);
	return p;
}

void http_resp_errpage(struct http_conn *restrict p, const uint_fast16_t code)
{
	p->wbuf.len = 0;
	VBUF_FREE(p->cbuf);

	const size_t cap = p->wbuf.cap - p->wbuf.len;
	char *buf = (char *)(p->wbuf.data + p->wbuf.len);
	const int len = http_error(buf, cap, code);
	if (len <= 0) {
		/* Can't generate error page, reply with code only */
		RESPHDR_BEGIN(p->wbuf, code);
		RESPHDR_CONN_CLOSE(p->wbuf);
		RESPHDR_FINISH(p->wbuf);
		return;
	}
	p->wbuf.len += len;
	LOG_STACK_F(VERBOSE, 0, "http: response error page %" PRIuFAST16, code);
}

struct stream *content_reader(
	const void *restrict buf, const size_t len,
	const enum content_encodings encoding)
{
	struct stream *r = NULL;

	switch (encoding) {
	case CENCODING_NONE:
		r = io_memreader(buf, len);
		break;
	case CENCODING_DEFLATE:
		r = codec_zlib_reader(io_memreader(buf, len));
		break;
	case CENCODING_GZIP:
		r = codec_gzip_reader(io_memreader(buf, len));
		break;
	default:
		FAILMSGF("unexpected content encoding: %d", encoding);
	}
	if (r == NULL) {
		return NULL;
	}

	/* Ensure direct_read capability for Lua compatibility */
	if (r->vftable->direct_read == NULL) {
		r = io_bufreader(r, IO_BUFSIZE);
	}
	return r;
}

struct stream *content_writer(
	struct vbuffer **restrict pvbuf, const size_t bufsize,
	const enum content_encodings encoding)
{
	VBUF_RESERVE(*pvbuf, bufsize);
	if (*pvbuf == NULL) {
		return NULL;
	}
	VBUF_RESET(*pvbuf);

	switch (encoding) {
	case CENCODING_NONE:
		return io_heapwriter(pvbuf);
	case CENCODING_DEFLATE:
		return codec_zlib_writer(io_heapwriter(pvbuf));
	default:
		break;
	}
	FAILMSGF("unexpected content encoding: %d", encoding);
}
