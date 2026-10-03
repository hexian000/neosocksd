/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http.h"

#include "codec.h"

#include "io/memory.h"
#include "io/stream.h"
#include "net/http.h"
#include "net/mime.h"
#include "os/socket.h"
#include "utils/buffer.h"
#include "utils/ctype_ascii.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

const char *const http_content_encoding_str[] = {
	[CENCODING_NONE] = NULL,
	[CENCODING_DEFLATE] = "deflate",
	[CENCODING_GZIP] = "gzip",
};

/* Compares at most n bytes, folding only A-Z: libc strncasecmp() folds
 * through the LC_CTYPE locale, which a Turkish one makes map 'I' away from
 * 'i', while HTTP tokens are case-insensitive in ASCII alone. */
static bool
token_equal_n(const char *restrict a, const char *restrict b, const size_t n)
{
	for (size_t i = 0; i < n; i++) {
		const unsigned char ca = (unsigned char)a[i];
		const unsigned char cb = (unsigned char)b[i];
		if (tolower(ca) != tolower(cb)) {
			return false;
		}
		if (ca == '\0') {
			break;
		}
	}
	return true;
}

bool http_token_equal(const char *restrict a, const char *restrict b)
{
	return token_equal_n(a, b, SIZE_MAX);
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
			/* RFC 9112 §3: a request-line that does not fit is an
			 * over-long request-target, answered 414 */
			p->http_status = HTTP_URI_TOO_LONG;
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
	if (!http_version_is_1x(version)) {
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

/* RFC 9110 §7.2 / RFC 3986 §3.2: Host is uri-host [ ":" port ],
 * with no userinfo. Validate syntax only; it need not name a dialable peer. */
static bool host_valid(const char *value)
{
	if (*value == '[') {
		const char *end = strchr(++value, ']');
		if (end == NULL) {
			return false;
		}
		if (*value == 'v' || *value == 'V') {
			value++;
			const char *version = value;
			while (value < end && isxdigit((unsigned char)*value)) {
				value++;
			}
			if (value == version || value == end || *value != '.') {
				return false;
			}
			value++;
			if (value == end) {
				return false;
			}
			for (; value < end; value++) {
				if (!isalnum((unsigned char)*value) &&
				    strchr("-._~!$&'()*+,;=:", *value) ==
					    NULL) {
					return false;
				}
			}
		} else {
			char literal[INET6_ADDRSTRLEN];
			const size_t len = (size_t)(end - value);
			if (len >= sizeof(literal)) {
				return false;
			}
			memcpy(literal, value, len);
			literal[len] = '\0';
			struct in6_addr addr;
			if (inet_pton(AF_INET6, literal, &addr) != 1) {
				return false;
			}
		}
		value = end + 1;
	} else {
		for (; *value != '\0' && *value != ':'; value++) {
			if (*value == '%') {
				if (!isxdigit((unsigned char)value[1]) ||
				    !isxdigit((unsigned char)value[2])) {
					return false;
				}
				value += 2;
			} else if (
				!isalnum((unsigned char)*value) &&
				strchr("-._~!$&'()*+,;=", *value) == NULL) {
				return false;
			}
		}
	}
	if (*value == ':') {
		value++;
		for (; isdigit((unsigned char)*value); value++) {
		}
	}
	return *value == '\0';
}

static bool parse_header_kv(
	struct http_conn *restrict p, const char *restrict key,
	char *restrict value)
{
	LOGVV_F("http_header: \"%s: %s\"", key, value);
	if (p->mode == STATE_PARSE_REQUEST && http_token_equal(key, "Host")) {
		if (p->hdr.has_host || !host_valid(value)) {
			return false;
		}
		p->hdr.has_host = true;
	}
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
			/* RFC 6585 §5: the header section does not fit */
			p->http_status = HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE;
			p->state = STATE_PARSE_ERROR;
			return 0;
		}
		return 1;
	}

	p->next = next;

	/* NULL key indicates end of headers */
	if (key == NULL) {
		/* HTTP/1.0 can omit Host; later HTTP/1.x versions must send it. */
		if (p->mode == STATE_PARSE_REQUEST &&
		    p->msg.req.version[7] != '0' && !p->hdr.has_host) {
			p->state = STATE_PARSE_ERROR;
			return 0;
		}
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
		if (p->byt_sent != NULL) {
			*p->byt_sent += (uint_least64_t)len;
		}
	}
	return true;
}

static int parse_content(struct http_conn *restrict p)
{
	/* Only Content-Length based content is handled here. A chunked or a
	 * close-delimited response body is deliberately left unframed in rbuf;
	 * callers that read cbuf must reject those themselves -- see the
	 * http_conn_recv() contract. */
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
		/* keep `next` the consumed mark for the whole message, so what
		 * remains in rbuf past it is a later message's bytes */
		p->next += len;

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
	p->cbuf->data[p->cbuf->len] = '\0';
	if (p->byt_recv != NULL) {
		*p->byt_recv += (uint_least64_t)n;
	}
	return 1;
}

int http_conn_parse(struct http_conn *restrict p)
{
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

	return http_conn_parse(p);
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

bool parsehdr_transfer_encoding(
	struct http_conn *restrict p, char *restrict value)
{
	/* RFC 9112 §6.1: the value lists the transfer-codings in the order they
	 * were applied; RFC 9110 §5.6.1: empty list elements are ignored.
	 * comma-split by hand rather than with the non-reentrant strtok() */
	size_t num_chunked = 0;
	bool has_unknown = false;
	bool final_chunked = false;
	for (char *token = value; token != NULL;) {
		char *const comma = strchr(token, ',');
		if (comma != NULL) {
			*comma = '\0';
		}
		const char *const coding = strtrimspace(token);
		if (coding[0] != '\0') {
			/* RFC 9112 §7: transfer-coding names are
			 * case-insensitive tokens */
			final_chunked = http_token_equal(coding, "chunked");
			if (final_chunked) {
				num_chunked++;
			} else {
				has_unknown = true;
			}
		}
		token = (comma != NULL) ? comma + 1 : NULL;
	}

	if (num_chunked == 0 && !has_unknown) {
		/* An empty Transfer-Encoding value carries no transfer-coding, so
		 * it must not clobber one already recorded from a prior TE line:
		 * downgrading an established `chunked` framing to NONE here would
		 * leave the chunked body bytes unframed and attributed to whatever
		 * follows (request smuggling). Leave the recorded coding as-is (it
		 * stays TENCODING_NONE when no prior line set one). */
		return true;
	}

	/* RFC 9112 §6.3: a request whose final transfer-coding is not chunked
	 * cannot be framed, which is a 400 whatever the codings are. Only the
	 * field lines seen so far are judged, so a split "gzip" then "chunked"
	 * is rejected at its first line. */
	if (!final_chunked) {
		return false;
	}
	/* RFC 9112 §6.1: chunked applies at most once, whether it is repeated
	 * within this list or already recorded from a prior field line */
	if (num_chunked > 1 || p->hdr.transfer.encoding == TENCODING_CHUNKED) {
		return false;
	}
	/* RFC 9112 §6.3: Content-Length + Transfer-Encoding: chunked
	 * is an ambiguous framing and must be rejected */
	if (p->hdr.content.has_length) {
		return false;
	}
	/* RFC 9112 §6.1: the framing is sound but a coding applied before
	 * chunked is one this parser cannot decode */
	if (has_unknown) {
		p->http_status = HTTP_NOT_IMPLEMENTED;
		return false;
	}
	p->hdr.transfer.encoding = TENCODING_CHUNKED;
	return true;
}

bool parsehdr_accept_encoding(struct http_conn *restrict p, char *restrict value)
{
	const char *const deflate =
		http_content_encoding_str[CENCODING_DEFLATE];
	/* RFC 9110 §12.5.3: a `*` matches "any available content-coding not
	 * explicitly listed", so an explicit `deflate;q=0` must suppress
	 * deflate even when a `*` elsewhere in the list would otherwise select
	 * it — and this holds whichever token comes first. A single-pass
	 * "return on the first match" cannot express that, so scan the whole
	 * list and track two signals: whether deflate was explicitly refused
	 * (`deflate;q=0`) and whether any acceptable token selects it (`deflate`
	 * with q>0, or `*` with q>0). Choose deflate only if selected and not
	 * explicitly refused, independent of token order. */
	bool deflate_refused = false;
	bool selected = false;
	/* comma-split by hand rather than with the non-reentrant strtok(); each
	 * element is a content-coding with an optional ";q=..." weight */
	for (char *token = value; token != NULL;) {
		char *const comma = strchr(token, ',');
		if (comma != NULL) {
			*comma = '\0';
		}
		/* split off the optional ";q=..." weight */
		char *const semi = strchr(token, ';');
		bool acceptable = true;
		if (semi != NULL) {
			*semi = '\0';
			/* RFC 9110 §12.5.3: a weight of q=0 means the coding is
			 * NOT acceptable, so honor it rather than dropping the
			 * whole weight. A qvalue is zero iff every digit is 0
			 * (0, 0.0, 0.000, ...); scanned digit-wise so it is
			 * locale-independent (no '.'-vs-',' surprise). */
			const char *q = strtrimspace(semi + 1);
			if ((q[0] == 'q' || q[0] == 'Q') && q[1] == '=') {
				acceptable = false;
				for (q += 2; *q != '\0'; q++) {
					if ('1' <= *q && *q <= '9') {
						acceptable = true;
						break;
					}
					if (*q != '0' && *q != '.') {
						break; /* end of the qvalue */
					}
				}
			}
		}
		const char *const coding = strtrimspace(token);
		if (http_token_equal(coding, deflate)) {
			/* an explicit deflate token governs deflate directly: a
			 * q=0 here refuses it outright and no later `*` can undo
			 * that */
			if (acceptable) {
				selected = true;
			} else {
				deflate_refused = true;
			}
		} else if (acceptable && strcmp(coding, "*") == 0) {
			/* the wildcard selects deflate, whether it is the whole
			 * value or one token among a list (e.g. "gzip, *") --
			 * but only if deflate was not explicitly refused, which
			 * the final check enforces */
			selected = true;
		}
		token = (comma != NULL) ? comma + 1 : NULL;
	}

	/* RFC 9110 §5.3: repeated Accept-Encoding lines are one combined value, so
	 * a `deflate;q=0` on any line refuses deflate for the whole request -- keep
	 * the refusal sticky across lines rather than only within this one. */
	if (deflate_refused) {
		p->hdr.accept_deflate_refused = true;
	}
	if (p->hdr.accept_deflate_refused) {
		p->hdr.accept_encoding = CENCODING_NONE;
	} else if (selected) {
		p->hdr.accept_encoding = CENCODING_DEFLATE;
	}
	/* otherwise leave accept_encoding as CENCODING_NONE: a valid header with
	 * no acceptable supported coding, or deflate explicitly refused */
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
	/* RFC 9110 §5.3: repeated Content-Encoding lines combine into one ordered
	 * coding list. Only a single supported coding can be decoded, so a second
	 * coding line is a stack this decoder cannot apply -- reject it, the same
	 * as the equivalent comma-joined multi-coding on one line. */
	if (p->hdr.content.encoding != CENCODING_NONE) {
		p->http_status = HTTP_UNSUPPORTED_MEDIA_TYPE;
		return false;
	}
	for (size_t i = 0; i < CENCODING_MAX; i++) {
		if (http_content_encoding_str[i] == NULL) {
			continue;
		}
		if (http_token_equal(value, http_content_encoding_str[i])) {
			p->hdr.content.encoding = (enum content_encodings)i;
			return true;
		}
	}

	p->http_status = HTTP_UNSUPPORTED_MEDIA_TYPE;
	return false;
}

enum parsehdr_result parsehdr_representation(
	struct http_conn *restrict p, const char *restrict key,
	char *restrict value)
{
	if (http_token_equal(key, "Transfer-Encoding")) {
		return parsehdr_transfer_encoding(p, value) ? PARSEHDR_OK :
							      PARSEHDR_ERROR;
	}
	if (http_token_equal(key, "Content-Length")) {
		return parsehdr_content_length(p, value) ? PARSEHDR_OK :
							   PARSEHDR_ERROR;
	}
	if (http_token_equal(key, "Content-Type")) {
		p->hdr.content.type = value;
		return PARSEHDR_OK;
	}
	if (http_token_equal(key, "Content-Encoding")) {
		return parsehdr_content_encoding(p, value) ? PARSEHDR_OK :
							     PARSEHDR_ERROR;
	}
	return PARSEHDR_UNHANDLED;
}

bool parsehdr_expect(struct http_conn *restrict p, char *restrict value)
{
	value = strtrimspace(value);

	if (!http_token_equal(value, "100-continue")) {
		p->http_status = HTTP_EXPECTATION_FAILED;
		return false;
	}

	/* RFC 9110 §10.1.1 and §15.2: an HTTP/1.0 request's 100-continue is
	 * ignored, since an HTTP/1.0 client cannot take a 1xx response */
	if (strcmp(p->msg.req.version, "HTTP/1.0") == 0) {
		return true;
	}
	p->expect_continue = true;
	return true;
}

bool http_connection_join(
	char *restrict store, const size_t cap, size_t *restrict len,
	const char *restrict value)
{
	const size_t vlen = strlen(value);
	const size_t sep = (*len > 0) ? 1 : 0;
	if (*len + sep + vlen + 1 > cap) {
		return false;
	}
	if (sep > 0) {
		store[(*len)++] = ',';
	}
	memcpy(store + *len, value, vlen + 1);
	*len += vlen;
	return true;
}

bool parsehdr_connection(struct http_conn *restrict p, char *restrict value)
{
	/* The common single-line case is referenced in place, unchanged. A second
	 * line switches to the combine store: seed it with the first line (still
	 * referenced by `connection`), then append this and any further lines so
	 * every consumer sees one ordered token list (RFC 9110 §5.3). */
	if (p->hdr.connection == NULL) {
		p->hdr.connection = value;
		return true;
	}
	char *const store = p->hdr.connection_store;
	if (p->hdr.connection != store) {
		p->hdr.connection_stored = 0;
		if (!http_connection_join(
			    store, sizeof(p->hdr.connection_store),
			    &p->hdr.connection_stored, p->hdr.connection)) {
			return false;
		}
		p->hdr.connection = store;
	}
	return http_connection_join(
		store, sizeof(p->hdr.connection_store),
		&p->hdr.connection_stored, value);
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
		if (toklen == keylen && token_equal_n(tok, key, keylen)) {
			return true;
		}
	}
	return false;
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

struct io_stream *content_reader(
	const void *restrict buf, const size_t len,
	const enum content_encodings encoding)
{
	struct io_stream *r = NULL;

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

	/* the ruleset Lua loader pulls the body through io_stream_direct_read,
	 * which has no fallback for a stream lacking the slot; every reader
	 * constructed above provides one */
	ASSERT(r->vftable->direct_read != NULL);
	return r;
}

struct io_stream *content_reader_vbuf(
	const struct vbuffer *restrict cbuf,
	const enum content_encodings encoding)
{
	return content_reader(
		cbuf != NULL ? VBUF_DATA(cbuf) : "",
		cbuf != NULL ? VBUF_LEN(cbuf) : 0, encoding);
}

struct io_stream *content_writer(
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
