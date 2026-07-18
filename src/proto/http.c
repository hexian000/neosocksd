/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http.h"

#include "codec.h"

#include "io/io.h"
#include "io/memory.h"
#include "io/stream.h"
#include "net/http.h"
#include "net/mime.h"
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
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>

const char *const http_content_encoding_str[] = {
	[CENCODING_NONE] = NULL,
	[CENCODING_DEFLATE] = "deflate",
	[CENCODING_GZIP] = "gzip",
};

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
		if (p->rbuf.len + 1 >= p->rbuf.cap) {
			p->http_status = HTTP_ENTITY_TOO_LARGE;
			p->state = STATE_PARSE_ERROR;
			return 0;
		}
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

/* send a short message directly to the socket, bypassing the buffers;
 * loops on a short send (retrying immediately, not via the event loop)
 * since the caller has no mechanism to resume this later, and gives up
 * only on a hard error or persistent backpressure */
static bool reply_short(struct http_conn *restrict p, const char *s)
{
	const size_t n = strlen(s);
	ASSERT(n < 256);
	LOG_BIN_F(VERBOSE, s, n, 0, "reply_short: [fd:%d] %zu bytes", p->fd, n);

	size_t pos = 0;
	while (pos < n) {
		size_t len = n - pos;
		const int err = socket_send(p->fd, s + pos, &len);
		if (err != 0) {
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == ENOBUFS || err == ENOMEM) {
				LOGW_F("send: [fd:%d] blocked after %zu/%zu bytes",
				       p->fd, pos, n);
				return false;
			}
			LOGW_F("send: [fd:%d] (%d) %s", p->fd, err,
			       strerror(err));
			return false;
		}
		pos += len;
	}
	return true;
}

static int parse_content(struct http_conn *restrict p)
{
	/* Only Content-Length based content is handled here. A chunked body is
	 * deliberately left in rbuf for the caller to dechunk (proxy_pass does,
	 * via http_framer); callers that read cbuf must reject chunked
	 * themselves -- see the http_conn_recv() contract. */
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

		/* Copy any content already in read buffer, never more than
		 * declared: trailing bytes past content_length belong to a
		 * later message (or are bogus), not to this body. */
		const size_t pos =
			(size_t)((unsigned char *)p->next - p->rbuf.data);
		size_t len = p->rbuf.len - pos;
		if (len > content_length) {
			len = content_length;
		}
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
		LOGD_F("recv: [fd:%d] (%d) %s", p->fd, err, strerror(err));
		return -1;
	}
	if (n == 0) {
		LOGD_F("recv: [fd:%d] early EOF", p->fd);
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
		LOGD_F("recv: [fd:%d] (%d) %s", p->fd, err, strerror(err));
		return -1;
	}
	if (n == 0) {
		LOGD_F("recv: [fd:%d] early EOF", p->fd);
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
			continue;
		case STATE_PARSE_HEADER:
			ret = parse_header(p);
			if (ret != 0) {
				return ret;
			}
			continue;
		case STATE_PARSE_CONTENT:
			ret = parse_content(p);
			if (ret != 0) {
				return ret;
			}
			/* parse_content may have set STATE_PARSE_ERROR (e.g.
			 * Content-Length over HTTP_MAX_CONTENT); only advance to
			 * OK when the body actually completed */
			if (p->state == STATE_PARSE_CONTENT) {
				p->state = STATE_PARSE_OK;
			}
			return 0;
		case STATE_PARSE_ERROR:
		case STATE_PARSE_OK:
			return 0;
		}
		/* no default: -Wswitch guards new enumerators; this is
		 * unreachable for the current enum */
		FAILMSGF("unexpected http parser state: %d", p->state);
	}
}

int http_conn_send(struct http_conn *restrict p, const int fd, int *restrict err)
{
	*err = 0;
	{
		const unsigned char *buf = p->wbuf.data + p->wpos;
		size_t len = p->wbuf.len - p->wpos;
		const int serr = socket_send(fd, buf, &len);
		if (serr != 0) {
			if (serr == EAGAIN || serr == EWOULDBLOCK ||
			    serr == ENOBUFS || serr == ENOMEM) {
				return 1;
			}
			*err = serr;
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
		const int serr = socket_send(fd, buf, &len);
		if (serr != 0) {
			if (serr == EAGAIN || serr == EWOULDBLOCK ||
			    serr == ENOBUFS || serr == ENOMEM) {
				return 1;
			}
			*err = serr;
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

void http_reader_init(struct http_reader *restrict r)
{
	r->pos = 0;
	r->line_done = false;
}

enum http_reader_state http_reader_parse(
	struct http_reader *restrict r, char *restrict base,
	struct http_message *restrict msg, const bool is_request,
	const struct http_parsehdr_cb on_header)
{
	char *next = base + r->pos;
	if (!r->line_done) {
		char *const p = http_parse(next, msg);
		if (p == NULL) {
			return HTTP_READER_ERROR;
		}
		if (p == next) {
			return HTTP_READER_MORE;
		}
		const char *const version =
			is_request ? msg->req.version : msg->rsp.version;
		if (strncmp(version, "HTTP/1.", 7) != 0) {
			return HTTP_READER_ERROR;
		}
		r->line_done = true;
		r->pos = (size_t)(p - base);
		next = p;
	}
	for (;;) {
		char *key, *value;
		char *const p = http_parsehdr(next, &key, &value);
		if (p == NULL) {
			return HTTP_READER_ERROR;
		}
		if (p == next) {
			return HTTP_READER_MORE;
		}
		r->pos = (size_t)(p - base);
		next = p;
		if (key == NULL) {
			return HTTP_READER_OK; /* end of headers */
		}
		if (!on_header.func(on_header.ctx, key, value)) {
			return HTTP_READER_ERROR;
		}
	}
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
	size_t *restrict len, const struct http_body_data_cb on_data)
{
	const size_t total = *len;
	if (total == 0) {
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
		if (total > remain) {
			return false;
		}
		if (!on_data.func(on_data.ctx, data, total)) {
			return false;
		}
		d->consumed += total;
		if (d->consumed == d->content_length) {
			d->done = true;
		}
		return true;
	}
	case HTTP_BODY_EOF:
		if (!on_data.func(on_data.ctx, data, total)) {
			return false;
		}
		d->consumed += total;
		return true;
	case HTTP_BODY_CHUNKED:
		break;
	}

	for (size_t i = 0; i < total; i++) {
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
				/* trailing bytes past the terminator belong to
				 * whatever follows (e.g. a pipelined next
				 * message), not to this body -- report how
				 * much was actually consumed instead of
				 * treating leftovers as a parse failure */
				*len = i + 1;
				return true;
			}
			d->line_len = 0;
			continue;
		case HTTP_BODY_CHUNK_DATA: {
			const size_t remain = total - i;
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

size_t http_chunk_header(char *restrict buf, size_t datalen)
{
	static const char xdigits[] = "0123456789abcdef";
	ASSERT(datalen > 0);
	/* build the hex digits backwards, then emit big-endian */
	char hex[16];
	size_t ndigit = 0;
	do {
		hex[ndigit++] = xdigits[datalen & 0xf];
		datalen >>= 4;
	} while (datalen != 0);
	size_t pos = 0;
	while (ndigit > 0) {
		buf[pos++] = hex[--ndigit];
	}
	buf[pos++] = '\r';
	buf[pos++] = '\n';
	return pos;
}

void http_framer_init(
	struct http_framer *restrict f, const enum http_body_mode in_mode,
	const size_t content_length, const bool rechunk)
{
	http_body_init(&f->body, in_mode, content_length);
	f->rechunk = rechunk;
	f->done = false;
	f->sending_term = false;
	f->in_pos = f->in_len = 0;
	f->out_pos = f->out_end = 0;
	f->datalen = 0;
}

void http_framer_seed(
	struct http_framer *restrict f, const size_t pos, const size_t len)
{
	f->in_pos = pos;
	f->in_len = len;
}

static bool
framer_on_data(void *ctx, const unsigned char *restrict data, const size_t len)
{
	struct http_framer *restrict f = ctx;
	/* the input is throttled so the decoded output always fits */
	memcpy(f->out + HTTP_FRAMER_HDR_ROOM + f->datalen, data, len);
	f->datalen += len;
	return true;
}

enum http_framer_op http_framer_run(struct http_framer *restrict f)
{
	const struct http_body_data_cb cb = { .func = framer_on_data,
					      .ctx = f };
	for (;;) {
		if (f->out_pos < f->out_end) {
			return HTTP_FRAMER_SEND;
		}
		if (f->done) {
			return HTTP_FRAMER_DONE;
		}
		if (f->body.done) {
			if (f->rechunk && !f->sending_term) {
				memcpy(f->out, HTTP_CHUNK_TERMINATOR,
				       sizeof(HTTP_CHUNK_TERMINATOR) - 1);
				f->out_pos = 0;
				f->out_end = sizeof(HTTP_CHUNK_TERMINATOR) - 1;
				f->sending_term = true;
				return HTTP_FRAMER_SEND;
			}
			f->done = true;
			return HTTP_FRAMER_DONE;
		}
		if (f->in_pos >= f->in_len) {
			return HTTP_FRAMER_FILL;
		}
		size_t avail = f->in_len - f->in_pos;
		if (f->body.mode == HTTP_BODY_CONTENT_LENGTH) {
			const size_t remain =
				f->body.content_length - f->body.consumed;
			if (avail > remain) {
				avail = remain; /* discard surplus past CL */
			}
		}
		f->datalen = 0;
		size_t consumed = avail;
		if (!http_body_consume(
			    &f->body, f->in + f->in_pos, &consumed, cb)) {
			return HTTP_FRAMER_ERROR;
		}
		f->in_pos += consumed;
		if (f->body.done) {
			/* surplus past the body (a pipelined next message) is
			 * left unread and discarded -- no keep-alive here */
			f->in_pos = f->in_len;
		}
		if (f->datalen == 0) {
			continue; /* framing-only bytes produced no output */
		}
		if (f->rechunk) {
			char hdr[HTTP_CHUNK_HEADER_MAX];
			const size_t hlen = http_chunk_header(hdr, f->datalen);
			memcpy(f->out + HTTP_FRAMER_HDR_ROOM - hlen, hdr, hlen);
			f->out[HTTP_FRAMER_HDR_ROOM + f->datalen] = '\r';
			f->out[HTTP_FRAMER_HDR_ROOM + f->datalen + 1] = '\n';
			f->out_pos = HTTP_FRAMER_HDR_ROOM - hlen;
			f->out_end = HTTP_FRAMER_HDR_ROOM + f->datalen + 2;
		} else {
			f->out_pos = HTTP_FRAMER_HDR_ROOM;
			f->out_end = HTTP_FRAMER_HDR_ROOM + f->datalen;
		}
		return HTTP_FRAMER_SEND;
	}
}

size_t http_framer_pending(
	const struct http_framer *restrict f,
	const unsigned char **restrict buf)
{
	*buf = f->out + f->out_pos;
	return f->out_end - f->out_pos;
}

void http_framer_drained(struct http_framer *restrict f, const size_t n)
{
	f->out_pos += n;
	if (f->out_pos >= f->out_end) {
		f->out_pos = f->out_end = 0;
	}
}

void http_framer_inbuf(
	struct http_framer *restrict f, unsigned char **restrict buf,
	size_t *restrict cap)
{
	*buf = f->in;
	size_t want = sizeof(f->in);
	if (f->body.mode == HTTP_BODY_CONTENT_LENGTH) {
		const size_t remain = f->body.content_length - f->body.consumed;
		if (want > remain) {
			want = remain;
		}
	}
	*cap = want;
}

void http_framer_filled(struct http_framer *restrict f, const size_t n)
{
	f->in_pos = 0;
	f->in_len = n;
}

bool http_framer_eof(struct http_framer *restrict f)
{
	if (f->body.mode != HTTP_BODY_EOF) {
		return false;
	}
	(void)http_body_finish(&f->body);
	return true;
}

bool parsehdr_accept_te(struct http_conn *restrict p, char *restrict value)
{
	/* comma-split by hand rather than with the non-reentrant strtok(); each
	 * element is a transfer-coding (or the "trailers" keyword) with an
	 * optional ";q=..." weight */
	for (char *token = value; token != NULL;) {
		char *const comma = strchr(token, ',');
		if (comma != NULL) {
			*comma = '\0';
		}
		/* drop the quality value if present */
		char *const semi = strchr(token, ';');
		if (semi != NULL) {
			*semi = '\0';
		}
		const char *const coding = strtrimspace(token);
		if (strcasecmp(coding, "chunked") == 0) {
			p->hdr.transfer.accept = TENCODING_CHUNKED;
			return true;
		}
		token = (comma != NULL) ? comma + 1 : NULL;
	}

	/* RFC 9110 §10.1.4: TE only advertises what the client is willing to
	 * accept, so a coding we do not offer (or the "trailers" keyword) must
	 * never fail the request — leave accept as TENCODING_NONE */
	return true;
}

bool parsehdr_transfer_encoding(
	struct http_conn *restrict p, char *restrict value)
{
	value = strtrimspace(value);

	if (value[0] == '\0') {
		p->hdr.transfer.encoding = TENCODING_NONE;
		return true;
	}

	/* RFC 9112 §7: transfer-coding names are case-insensitive tokens */
	if (strcasecmp(value, "chunked") == 0) {
		/* RFC 9112 §6.3: Content-Length + Transfer-Encoding: chunked
		 * is an ambiguous framing and must be rejected */
		if (p->hdr.content.has_length) {
			return false;
		}
		p->hdr.transfer.encoding = TENCODING_CHUNKED;
		return true;
	}

	return false;
}

bool parsehdr_accept_encoding(struct http_conn *restrict p, char *restrict value)
{
	const char *const deflate =
		http_content_encoding_str[CENCODING_DEFLATE];
	/* comma-split by hand rather than with the non-reentrant strtok(); each
	 * element is a content-coding with an optional ";q=..." weight */
	for (char *token = value; token != NULL;) {
		char *const comma = strchr(token, ',');
		if (comma != NULL) {
			*comma = '\0';
		}
		/* drop the quality value if present */
		char *const semi = strchr(token, ';');
		if (semi != NULL) {
			*semi = '\0';
		}
		const char *const coding = strtrimspace(token);
		/* RFC 9110 §12.5.3: `*` is a wildcard for any encoding, whether
		 * it is the whole value or one token among a comma-separated
		 * list (e.g. "gzip, *") */
		if (strcmp(coding, "*") == 0 ||
		    strcasecmp(coding, deflate) == 0) {
			p->hdr.accept_encoding = CENCODING_DEFLATE;
			return true;
		}
		token = (comma != NULL) ? comma + 1 : NULL;
	}

	/* Valid header, but no supported encoding — leave accept_encoding as CENCODING_NONE */
	return true;
}

bool http_parse_content_length(const char *restrict value, size_t *restrict out)
{
	/* RFC 9110 §8.6: Content-Length = 1*DIGIT, no sign of either kind;
	 * strtoumax alone would accept a leading '-' (wrapping to a huge
	 * value) or '+', and an empty value (consuming nothing) as 0 */
	if (!isdigit((unsigned char)value[0])) {
		return false;
	}

	char *endptr;
	errno = 0;
	const uintmax_t lenvalue = strtoumax(value, &endptr, 10);

	/* Reject a value that overflows uintmax_t itself (strtoumax sets ERANGE
	 * and returns UINTMAX_MAX) as well as one that merely exceeds SIZE_MAX.
	 * On an LP64 target uintmax_t == size_t, so the two bounds coincide and
	 * the `> SIZE_MAX` guard alone would let a 2^64 value slip through. */
	if (errno == ERANGE || *endptr != '\0' ||
	    lenvalue > (uintmax_t)SIZE_MAX) {
		return false;
	}

	*out = (size_t)lenvalue;
	return true;
}

bool parsehdr_content_length(
	struct http_conn *restrict p, const char *restrict value)
{
	/* RFC 9112 §6.3: reject a duplicate Content-Length, or one that
	 * conflicts with an already-seen Transfer-Encoding: chunked */
	if (p->hdr.content.has_length ||
	    p->hdr.transfer.encoding == TENCODING_CHUNKED) {
		return false;
	}

	size_t content_length;
	if (!http_parse_content_length(value, &content_length)) {
		return false;
	}

	/* CONNECT method must not have Content-Length. p->msg is a union whose
	 * req.method aliases rsp.version, so only test it in request mode. */
	if (p->mode == STATE_PARSE_REQUEST &&
	    strcmp(p->msg.req.method, "CONNECT") == 0) {
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

bool http_connection_lists(
	const char *restrict connection, const char *restrict key)
{
	const size_t keylen = strlen(key);
	const char *tok;
	size_t toklen;
	for (const char *next =
		     parsehdr_connection_token(connection, &tok, &toklen);
	     tok != NULL;
	     next = parsehdr_connection_token(next, &tok, &toklen)) {
		if (toklen == keylen && strncasecmp(tok, key, keylen) == 0) {
			return true;
		}
	}
	return false;
}

bool http_header_field_valid(
	const char *restrict key, const char *restrict value)
{
	for (const unsigned char *c = (const unsigned char *)key; *c != '\0';
	     c++) {
		if (!isalnum(*c) && strchr("!#$%&'*+-.^_`|~", *c) == NULL) {
			return false;
		}
	}
	for (const unsigned char *c = (const unsigned char *)value; *c != '\0';
	     c++) {
		if (iscntrl(*c) && *c != '\t') {
			return false;
		}
	}
	return true;
}

bool http_hostport_normalize(
	char *restrict buf, const size_t cap, const char *restrict host)
{
	const size_t hlen = strlen(host);
	if (hlen >= cap) {
		return false;
	}
	memcpy(buf, host, hlen + 1);
	const char *const portcheck = (buf[0] == '[') ? strchr(buf, ']') : buf;
	if (portcheck == NULL) {
		return false;
	}
	if (strchr(portcheck, ':') != NULL) {
		return true;
	}
	if (hlen + 3 >= cap) {
		return false;
	}
	memcpy(buf + hlen, ":80", 4);
	return true;
}

bool http_append(struct buffer *restrict buf, const char *restrict s)
{
	const size_t n = strlen(s);
	if (n > buf->cap - buf->len) {
		return false;
	}
	BUF_APPEND(*buf, s, n);
	return true;
}

bool http_append_headers(
	struct buffer *restrict buf, const struct http_header_kv *restrict hdr,
	const size_t n, const char *restrict connection)
{
	for (size_t i = 0; i < n; i++) {
		if (http_connection_lists(connection, hdr[i].key)) {
			continue;
		}
		if (!http_append(buf, hdr[i].key) || !http_append(buf, ": ") ||
		    !http_append(buf, hdr[i].value) ||
		    !http_append(buf, "\r\n")) {
			return false;
		}
	}
	return true;
}

bool http_append_framing(
	struct buffer *restrict buf, const bool chunked, const bool clen_known,
	const size_t content_length)
{
	if (chunked) {
		return http_append(buf, "Transfer-Encoding: chunked\r\n");
	}
	if (clen_known) {
		char cl[sizeof("Content-Length: \r\n") + 20];
		(void)snprintf(
			cl, sizeof(cl), "Content-Length: %zu\r\n",
			content_length);
		return http_append(buf, cl);
	}
	return true;
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
	/* http_error is snprintf-style: its return can exceed cap on
	 * truncation, so add only the bytes actually written */
	if (cap > 0) {
		p->wbuf.len += ((size_t)len < cap) ? (size_t)len : cap - 1;
	}
	LOG_STACK_F(VERBOSE, 0, "http: response error page %" PRIuFAST16, code);
}

#if WITH_RULESET
bool check_rpcall_mime(char *restrict s)
{
	if (s == NULL) {
		return false;
	}
	char *type, *subtype;
	s = mime_parse(s, &type, &subtype);
	if (s == NULL || strcmp(type, MIME_RPCALL_TYPE) != 0 ||
	    strcmp(subtype, MIME_RPCALL_SUBTYPE) != 0) {
		return false;
	}
	const char *version = NULL;
	char *key, *value;
	for (;;) {
		s = mime_parseparam(s, &key, &value);
		if (s == NULL) {
			return false;
		}
		if (key == NULL) {
			break;
		}
		if (strcmp(key, "version") == 0) {
			version = value;
		}
	}
	return version != NULL && strcmp(version, MIME_RPCALL_VERSION) == 0;
}
#endif /* WITH_RULESET */

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
	case CENCODING_GZIP:
		return codec_gzip_writer(io_heapwriter(pvbuf));
	default:
		break;
	}
	FAILMSGF("unexpected content encoding: %d", encoding);
}
