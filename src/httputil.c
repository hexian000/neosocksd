/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file httputil.c
 * @brief HTTP parsing and utility functions implementation
 *
 * Implements streaming HTTP parser with support for content encoding,
 * transfer encoding, and various HTTP features. The parser operates
 * in phases: message line, headers, and content body.
 */

#include "httputil.h"

#include "sockutil.h"

#include "codec.h"
#include "io/io.h"
#include "io/memory.h"
#include "io/stream.h"
#include "net/http.h"
#include "utils/ascii.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/** String representations of content encoding types */
const char *content_encoding_str[] = {
	[CENCODING_NONE] = NULL,
	[CENCODING_DEFLATE] = "deflate",
	[CENCODING_GZIP] = "gzip",
};

void http_resp_errpage(struct http_parser *restrict p, const uint16_t code)
{
	/* Reset buffers for error response */
	p->wbuf.len = 0;
	p->cbuf = VBUF_FREE(p->cbuf);

	/* Try to generate full error page */
	const size_t cap = p->wbuf.cap - p->wbuf.len;
	char *buf = (char *)(p->wbuf.data + p->wbuf.len);
	const int len = http_error(buf, cap, code);
	if (len <= 0) {
		/* Can't generate error page, reply with code only */
		RESPHDR_BEGIN(p->wbuf, code);
		RESPHDR_FINISH(p->wbuf);
		return;
	}
	p->wbuf.len += len;
	LOG_STACK_F(VERBOSE, 0, "http: response error page %" PRIu16, code);
}

/**
 * @brief Send short response message immediately
 *
 * Sends a complete short message (like status responses) directly
 * to the socket without buffering. Used for protocol responses
 * that need immediate delivery.
 *
 * @param p Parser instance containing socket fd
 * @param s String message to send
 * @return true if message sent successfully
 */
static bool reply_short(struct http_parser *restrict p, const char *s)
{
	const size_t n = strlen(s);
	ASSERT(n < 256);
	LOG_BIN_F(VERBOSE, s, n, 0, "reply_short: fd=%d %zu bytes", p->fd, n);

	/* Send message directly to socket */
	const ssize_t nsend = send(p->fd, s, n, 0);
	if (nsend < 0) {
		const int err = errno;
		LOGW_F("send: fd=%d [%d] %s", p->fd, err, strerror(err));
		return false;
	}
	if ((size_t)nsend != n) {
		LOGW_F("send: fd=%d short send %zu < %zu", p->fd, (size_t)nsend,
		       n);
		return false;
	}
	return true;
}

bool http_resp_established(struct http_parser *restrict p)
{
	const char msg[] = "HTTP/1.1 200 Connection established\r\n\r\n";
	return reply_short(p, msg);
}

struct stream *content_reader(
	const void *buf, size_t len, const enum content_encodings encoding)
{
	struct stream *r = NULL;

	/* Create appropriate reader based on encoding */
	switch (encoding) {
	case CENCODING_NONE:
		r = io_memreader(buf, len);
		break;
	case CENCODING_DEFLATE:
		r = codec_zlib_reader(io_memreader(buf, len));
		break;
	case CENCODING_GZIP: {
		/* Remove gzip header and create inflate reader */
		const void *p = gzip_unbox(buf, &len);
		r = codec_inflate_reader(io_memreader(p, len));
	} break;
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
	/* Ensure buffer has adequate initial size */
	*pvbuf = VBUF_RESIZE(*pvbuf, bufsize);

	/* Create appropriate writer based on encoding */
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

/**
 * @brief Parse HTTP message line (request or response)
 *
 * Parses the first line of an HTTP message, which contains either
 * the request line (method, URI, version) or response line (version,
 * status, reason phrase). Validates HTTP version compatibility.
 *
 * @param p Parser instance
 * @return 0 on success, 1 if more data needed, -1 on error
 */
static int parse_message(struct http_parser *restrict p)
{
	/* Initialize parsing position if needed */
	char *next = p->next;
	if (next == NULL) {
		next = (char *)p->rbuf.data;
		p->next = next;
	}

	/* Parse the message line */
	struct http_message *restrict msg = &p->msg;
	next = http_parse(next, msg);
	if (next == NULL) {
		LOGD("http: failed parsing message");
		return -1;
	}

	/* Check if we need more data */
	if (next == p->next) {
		if (p->rbuf.len + 1 >= p->rbuf.cap) {
			p->http_status = HTTP_ENTITY_TOO_LARGE;
			p->state = STATE_PARSE_ERROR;
			return 0;
		}
		return 1; /* Need more data */
	}

	/* Log parsed message components */
	LOGVV_F("http_message: `%s' `%s' `%s'", msg->any.field1,
		msg->any.field2, msg->any.field3);

	/* Validate HTTP version */
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
		return -1;
	}

	/* Advance to header parsing phase */
	p->next = next;
	p->state = STATE_PARSE_HEADER;
	return 0;
}

/**
 * @brief Process a parsed header key-value pair
 *
 * Invokes the registered header callback to process each parsed header.
 * This allows custom handling of headers by the application.
 *
 * @param p Parser instance
 * @param key Header name
 * @param value Header value
 * @return true if header processed successfully
 */
static bool parse_header_kv(
	const struct http_parser *restrict p, const char *key, char *value)
{
	LOGVV_F("http_header: \"%s: %s\"", key, value);
	return p->on_header.func(p->on_header.ctx, key, value);
}

/**
 * @brief Parse HTTP headers
 *
 * Parses HTTP headers one by one until the empty line that separates
 * headers from content. Each header is processed through the registered
 * callback function. When headers are complete, transitions to content
 * parsing phase.
 *
 * @param p Parser instance
 * @return 0 on success, 1 if more data needed, -1 on error
 */
static int parse_header(struct http_parser *restrict p)
{
	char *next = p->next;
	char *key, *value;

	/* Parse next header line */
	next = http_parsehdr(next, &key, &value);
	if (next == NULL) {
		LOGD("http: failed parsing header");
		return -1;
	}

	/* Check if we need more data */
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

	/* Process the header through callback */
	if (!parse_header_kv(p, key, value)) {
		p->state = STATE_PARSE_ERROR;
		return 0;
	}
	return 0;
}

/**
 * @brief Parse HTTP content body
 *
 * Handles content body parsing based on Content-Length header.
 * Allocates content buffer and copies any remaining data from
 * the read buffer. Sends 100-Continue response if expected.
 *
 * @param p Parser instance
 * @return 0 when complete, 1 if more data needed, -1 on error
 */
static int parse_content(struct http_parser *restrict p)
{
	/* Only handle Content-Length based content for now */
	if (!p->hdr.content.has_length) {
		/* Chunked encoding and other methods not implemented */
		return 0;
	}

	const size_t content_length = p->hdr.content.length;

	/* Check content size limits */
	if (content_length > HTTP_MAX_CONTENT) {
		p->http_status = HTTP_ENTITY_TOO_LARGE;
		p->state = STATE_PARSE_ERROR;
		return 0;
	}

	/* Initialize content buffer on first call */
	if (content_length > 0 && p->cbuf == NULL) {
		p->cbuf = VBUF_NEW(content_length);
		if (p->cbuf == NULL) {
			LOGOOM();
			return -1;
		}

		/* Copy any content already in read buffer */
		const size_t pos = (unsigned char *)p->next - p->rbuf.data;
		const size_t len = p->rbuf.len - pos;
		p->cbuf = VBUF_APPEND(p->cbuf, p->next, len);

		/* Send 100-Continue if client expects it */
		if (p->expect_continue) {
			if (!reply_short(p, "HTTP/1.1 100 Continue\r\n\r\n")) {
				return -1;
			}
		}
	}

	/* Check if we have all content */
	if (VBUF_LEN(p->cbuf) < content_length) {
		return 1; /* Need more data */
	}
	return 0;
}

/**
 * @brief Receive data into request buffer
 *
 * Reads available data from the socket into the parser's read buffer.
 * Maintains null termination for string parsing operations.
 *
 * @param p Parser instance
 * @return true if data received successfully
 */
static bool recv_request(struct http_parser *restrict p)
{
	/* Calculate available space (reserve 1 byte for null terminator) */
	size_t n = p->rbuf.cap - p->rbuf.len - 1;

	/* Receive data from socket */
	const int err = socket_recv(p->fd, p->rbuf.data + p->rbuf.len, &n);
	if (err != 0) {
		LOGD_F("recv: fd=%d [%d] %s", p->fd, err, strerror(err));
		return false;
	}
	if (n == 0) {
		LOGD_F("recv: fd=%d early EOF", p->fd);
		return false;
	}

	/* Update buffer length and maintain null termination */
	p->rbuf.len += n;
	p->rbuf.data[p->rbuf.len] = '\0';
	return true;
}

/**
 * @brief Receive data into content buffer
 *
 * Reads data directly into the content buffer when parsing the
 * HTTP message body. Used after headers are parsed and content
 * length is known.
 *
 * @param p Parser instance
 * @return true if data received successfully
 */
static bool recv_content(const struct http_parser *restrict p)
{
	struct vbuffer *restrict cbuf = p->cbuf;

	/* Calculate available space in content buffer */
	size_t n = cbuf->cap - cbuf->len;

	/* Receive data directly into content buffer */
	const int err = socket_recv(p->fd, cbuf->data + cbuf->len, &n);
	if (err != 0) {
		LOGW_F("recv: fd=%d [%d] %s", p->fd, err, strerror(err));
		return false;
	}
	if (n == 0) {
		LOGW_F("recv: fd=%d early EOF", p->fd);
		return false;
	}

	/* Update content buffer length */
	cbuf->len += n;
	return true;
}

/**
 * @brief Main HTTP parser receive and process function
 *
 * Receives data from socket and processes it through the parser
 * state machine. Handles all parsing phases: message line, headers,
 * and content. Returns when parsing is complete, more data is needed,
 * or an error occurs.
 *
 * @param p Parser instance
 * @return 0 on completion, 1 if more data needed, -1 on error
 */
int http_parser_recv(struct http_parser *restrict p)
{
	/* Receive data based on current parsing phase */
	switch (p->state) {
	case STATE_PARSE_REQUEST:
	case STATE_PARSE_RESPONSE:
	case STATE_PARSE_HEADER:
		/* Receive into main read buffer for header parsing */
		if (!recv_request(p)) {
			return -1;
		}
		break;
	case STATE_PARSE_CONTENT:
		/* Receive directly into content buffer */
		if (!recv_content(p)) {
			return -1;
		}
		break;
	default:
		return -1;
	}

	/* Process received data through state machine */
	for (;;) {
		int ret;
		switch (p->state) {
		case STATE_PARSE_REQUEST:
		case STATE_PARSE_RESPONSE:
			/* Parse HTTP message line */
			ret = parse_message(p);
			if (ret != 0) {
				return ret;
			}
			break;
		case STATE_PARSE_HEADER:
			/* Parse HTTP headers */
			ret = parse_header(p);
			if (ret != 0) {
				return ret;
			}
			break;
		case STATE_PARSE_CONTENT:
			/* Parse HTTP content body */
			ret = parse_content(p);
			if (ret != 0) {
				return ret;
			}
			/* Content parsing complete */
			p->state = STATE_PARSE_OK;
			/* fallthrough */
		case STATE_PARSE_ERROR:
		case STATE_PARSE_OK:
			/* Parsing finished (success or error) */
			return 0;
		default:
			FAILMSGF("unexpected http parser state: %d", p->state);
		}
	}
}

bool parsehdr_accept_te(struct http_parser *restrict p, char *restrict value)
{
	value = strtrimspace(value);

	/* Empty value means no transfer encoding accepted */
	if (value[0] == '\0') {
		p->hdr.transfer.accept = TENCODING_NONE;
		return true;
	}

	/* Check for chunked transfer encoding */
	if (strcmp(value, "chunked") == 0) {
		p->hdr.transfer.accept = TENCODING_CHUNKED;
		return true;
	}

	return false;
}

bool parsehdr_transfer_encoding(
	struct http_parser *restrict p, char *restrict value)
{
	value = strtrimspace(value);

	/* Empty value means no transfer encoding */
	if (value[0] == '\0') {
		p->hdr.transfer.encoding = TENCODING_NONE;
		return true;
	}

	/* Check for chunked transfer encoding */
	if (strcmp(value, "chunked") == 0) {
		p->hdr.transfer.encoding = TENCODING_CHUNKED;
		return true;
	}

	return false;
}

bool parsehdr_accept_encoding(
	struct http_parser *restrict p, char *restrict value)
{
	/* Wildcard accepts deflate encoding */
	if (strcmp(value, "*") == 0) {
		p->hdr.accept_encoding = CENCODING_DEFLATE;
		return true;
	}

	/* Parse comma-separated encoding list */
	const char *deflate = content_encoding_str[CENCODING_DEFLATE];
	for (char *token = strtok(value, ","); token != NULL;
	     token = strtok(NULL, ",")) {
		/* Remove quality value if present */
		char *q = strchr(token, ';');
		if (q != NULL) {
			*q = '\0';
		}

		/* Check for supported encoding */
		token = strtrimspace(token);
		if (strcasecmp(token, deflate) == 0) {
			p->hdr.accept_encoding = CENCODING_DEFLATE;
			return true;
		}
	}

	return false;
}

bool parsehdr_content_length(
	struct http_parser *restrict p, const char *restrict value)
{
	/* Parse numeric value */
	char *endptr;
	const uintmax_t lenvalue = strtoumax(value, &endptr, 10);

	/* Validate parsing and range */
	if (*endptr || lenvalue > SIZE_MAX) {
		return false;
	}

	const size_t content_length = (size_t)lenvalue;

	/* CONNECT method must not have Content-Length */
	if (strcmp(p->msg.req.method, "CONNECT") == 0) {
		return false;
	}

	/* Store parsed content length */
	p->hdr.content.has_length = true;
	p->hdr.content.length = content_length;
	return true;
}

bool parsehdr_content_encoding(
	struct http_parser *restrict p, const char *restrict value)
{
	/* Check against all supported encodings */
	for (size_t i = 0; i < CENCODING_MAX; i++) {
		if (content_encoding_str[i] == NULL) {
			continue;
		}
		if (strcasecmp(value, content_encoding_str[i]) == 0) {
			p->hdr.content.encoding = (enum content_encodings)i;
			return true;
		}
	}

	/* Unsupported encoding */
	p->http_status = HTTP_UNSUPPORTED_MEDIA_TYPE;
	return false;
}

bool parsehdr_expect(struct http_parser *restrict p, char *restrict value)
{
	value = strtrimspace(value);

	/* Only 100-continue is supported */
	if (strcasecmp(value, "100-continue") != 0) {
		p->http_status = HTTP_EXPECTATION_FAILED;
		return false;
	}

	/* Set flag for 100-continue handling */
	p->expect_continue = true;
	return true;
}

void http_parser_init(
	struct http_parser *restrict p, const int fd,
	const enum http_parser_state mode,
	const struct http_parsehdr_cb on_header)
{
	/* Initialize parser state */
	p->state = mode;
	p->http_status = HTTP_BAD_REQUEST;
	p->fd = fd;

	/* Initialize message and parsing state */
	p->msg = (struct http_message){ 0 };
	p->next = NULL;
	p->expect_continue = false;

	/* Initialize headers and callback */
	p->hdr = (struct http_headers){ 0 };
	p->on_header = on_header;

	/* Initialize buffer positions */
	p->wpos = p->cpos = 0;
	p->cbuf = NULL;

	/* Initialize fixed buffers */
	BUF_INIT(p->rbuf, 0);
	BUF_INIT(p->wbuf, 0);
}
