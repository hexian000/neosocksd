/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "httputil.h"

#include "sockutil.h"
#include "util.h"

#include "codec.h"
#include "io/io.h"
#include "io/memory.h"
#include "io/stream.h"
#include "net/http.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <sys/socket.h>
#include <sys/types.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

const char *content_encoding_str[] = {
	[CENCODING_NONE] = NULL,
	[CENCODING_DEFLATE] = "deflate",
	[CENCODING_GZIP] = "gzip",
};

void http_resp_errpage(struct http_parser *restrict p, const uint16_t code)
{
	p->wbuf.len = 0;
	p->cbuf = VBUF_FREE(p->cbuf);
	const size_t cap = p->wbuf.cap - p->wbuf.len;
	char *buf = (char *)(p->wbuf.data + p->wbuf.len);
	const int len = http_error(buf, cap, code);
	if (len <= 0) {
		/* can't generate error page, reply with code only */
		RESPHDR_BEGIN(p->wbuf, code);
		RESPHDR_FINISH(p->wbuf);
		return;
	}
	p->wbuf.len += len;
	LOG_STACK_F(VERBOSE, 0, "http: response error page %" PRIu16, code);
}

static bool reply_short(struct http_parser *restrict p, const char *s)
{
	const size_t n = strlen(s);
	ASSERT(n < 256);
	LOG_BIN_F(VERBOSE, s, n, "reply_short: fd=%d %zu bytes", p->fd, n);
	const ssize_t nsend = send(p->fd, s, n, 0);
	if (nsend < 0) {
		const int err = errno;
		LOGE_F("send: %s", strerror(err));
		return false;
	}
	if ((size_t)nsend != n) {
		LOGE("send: short send");
		return false;
	}
	return true;
}

struct stream *content_reader(
	const void *buf, size_t len, const enum content_encodings encoding)
{
	struct stream *r = NULL;
	switch (encoding) {
	case CENCODING_NONE:
		r = io_memreader(buf, len);
		break;
	case CENCODING_DEFLATE:
		r = codec_zlib_reader(io_memreader(buf, len));
		break;
	case CENCODING_GZIP: {
		const void *p = gzip_unbox(buf, &len);
		r = codec_inflate_reader(io_memreader(p, len));
	} break;
	default:
		FAIL();
	}
	if (r == NULL) {
		return NULL;
	}
	/* lua reader requires direct_read */
	if (r->vftable->direct_read == NULL) {
		r = io_bufreader(r, IO_BUFSIZE);
	}
	return r;
}

struct stream *content_writer(
	struct vbuffer **restrict pvbuf, const size_t bufsize,
	const enum content_encodings encoding)
{
	*pvbuf = VBUF_RESERVE(*pvbuf, bufsize);
	*pvbuf = VBUF_RESET(*pvbuf);
	switch (encoding) {
	case CENCODING_NONE:
		return io_heapwriter(pvbuf);
	case CENCODING_DEFLATE:
		return codec_zlib_writer(io_heapwriter(pvbuf));
	default:
		break;
	}
	FAIL();
}

static int parse_message(struct http_parser *restrict p)
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
	LOGV_F("http_message: `%s' `%s' `%s'", msg->any.field1, msg->any.field2,
	       msg->any.field3);
	const char *version = NULL;
	switch (p->state) {
	case STATE_PARSE_REQUEST:
		version = msg->req.version;
		break;
	case STATE_PARSE_RESPONSE:
		version = msg->rsp.version;
		break;
	default:
		FAIL();
	}
	if (strncmp(version, "HTTP/1.", 7) != 0) {
		LOGD_F("http: unsupported protocol `%s'", version);
		return -1;
	}
	p->next = next;
	p->state = STATE_PARSE_HEADER;
	return 0;
}

static bool
parse_header_kv(struct http_parser *restrict p, const char *key, char *value)
{
	LOGV_F("http_header: \"%s: %s\"", key, value);
	return p->on_header.func(p->on_header.ctx, key, value);
}

static int parse_header(struct http_parser *restrict p)
{
	char *next = p->next;
	char *key, *value;
	next = http_parsehdr(next, &key, &value);
	if (next == NULL) {
		LOGD("http: failed parsing header");
		return -1;
	}
	if (next == p->next) {
		return 1;
	}
	p->next = next;
	if (key == NULL) {
		p->cbuf = NULL;
		p->state = STATE_PARSE_CONTENT;
		return 0;
	}
	/* save the header */
	if (!parse_header_kv(p, key, value)) {
		p->state = STATE_PARSE_ERROR;
		return 0;
	}
	return 0;
}

static int parse_content(struct http_parser *restrict p)
{
	if (!p->hdr.content.has_length) {
		/* not implemented */
		return 0;
	}
	const size_t content_length = p->hdr.content.length;
	if (content_length > HTTP_MAX_CONTENT) {
		p->http_status = HTTP_ENTITY_TOO_LARGE;
		p->state = STATE_PARSE_ERROR;
		return 0;
	}
	if (content_length > 0 && p->cbuf == NULL) {
		p->cbuf = VBUF_NEW(content_length);
		if (p->cbuf == NULL) {
			LOGOOM();
			return -1;
		}
		const size_t pos = (unsigned char *)p->next - p->rbuf.data;
		const size_t len = p->rbuf.len - pos;
		p->cbuf = VBUF_APPEND(p->cbuf, p->next, len);
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

static bool recv_request(struct http_parser *restrict p)
{
	size_t n = p->rbuf.cap - p->rbuf.len - 1;
	const int err = socket_recv(p->fd, p->rbuf.data + p->rbuf.len, &n);
	if (err != 0) {
		LOGE_F("recv: fd=%d %s", p->fd, strerror(err));
		return false;
	}
	if (n == 0) {
		LOGE_F("recv: fd=%d EOF", p->fd);
		return false;
	}
	p->rbuf.len += n;
	p->rbuf.data[p->rbuf.len] = '\0';
	return true;
}

static bool recv_content(struct http_parser *restrict p)
{
	struct vbuffer *restrict cbuf = p->cbuf;
	size_t n = cbuf->cap - cbuf->len;
	const int err = socket_recv(p->fd, cbuf->data + cbuf->len, &n);
	if (err != 0) {
		LOGE_F("recv: fd=%d %s", p->fd, strerror(err));
		return false;
	}
	if (n == 0) {
		LOGE_F("recv: fd=%d EOF", p->fd);
		return false;
	}
	cbuf->len += n;
	return true;
}

int http_parser_recv(struct http_parser *restrict p)
{
	switch (p->state) {
	case STATE_PARSE_REQUEST:
	case STATE_PARSE_RESPONSE:
	case STATE_PARSE_HEADER:
		if (!recv_request(p)) {
			return -1;
		}
		break;
	case STATE_PARSE_CONTENT:
		if (!recv_content(p)) {
			return -1;
		}
		break;
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
			FAIL();
		}
	}
}

void http_parser_init(
	struct http_parser *restrict p, const int fd,
	const enum http_parser_state mode,
	const struct http_parsehdr_cb on_header)
{
	p->state = mode;
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
}
