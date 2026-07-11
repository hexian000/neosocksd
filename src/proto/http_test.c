/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * http_test - white-box unit tests for proto/http.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   proto/http.c     module under test
 *   proto/codec.c    leaf (transfer codecs)
 * Leaf libraries: csnippets (io/stream).
 * http.c has no stateful collaborator module to mock; the mock section only
 * holds a portability shim. Randomized HTTP parsing is fuzzed by main_test
 * (fuzz_http_req, fuzz_http_resp, fuzz_parsehdr).
 */

#include "http.h"

#include "io/stream.h"
#include "utils/buffer.h"
#include "utils/testing.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - portability shim only (http.c has no collaborator to mock).
 * ---------------------------------------------------------------------- */

#if !defined(_GNU_SOURCE)
static void *test_memmem(
	const void *haystack, const size_t haystack_len, const void *needle,
	const size_t needle_len)
{
	if (needle_len == 0) {
		return (void *)haystack;
	}
	if (haystack_len < needle_len) {
		return NULL;
	}
	const unsigned char *const h = haystack;
	const unsigned char *const n = needle;
	for (size_t i = 0; i + needle_len <= haystack_len; i++) {
		if (h[i] == n[0] && memcmp(h + i, n, needle_len) == 0) {
			return (void *)(h + i);
		}
	}
	return NULL;
}
#define memmem test_memmem
#endif /* !defined(_GNU_SOURCE) */

struct header_cb_ctx {
	struct http_conn *p;
	bool reject;
};

static bool write_all(const int fd, const void *buf, size_t len)
{
	const unsigned char *p = buf;
	while (len > 0) {
		const ssize_t n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return false;
		}
		if (n == 0) {
			return false;
		}
		p += (size_t)n;
		len -= (size_t)n;
	}
	return true;
}

static ssize_t recv_nowait(const int fd, void *buf, const size_t len)
{
	for (;;) {
		const ssize_t n = recv(fd, buf, len, MSG_DONTWAIT);
		if (n < 0 && errno == EINTR) {
			continue;
		}
		return n;
	}
}

/*
 * Cygwin/MSYS socketpairs deliver one write as several delayed fragments, so a
 * single http_conn_recv() may report "need more" (1) before the whole message
 * has arrived. These helpers poll the connection fd so the tests never depend
 * on a write being delivered atomically; they also evaluate http_conn_recv()
 * exactly once, since it has side effects.
 */
#define TEST_RECV_BUDGET_MS 4000
#define TEST_RECV_QUIET_MS 200

/* Receive until the parser reaches a terminal state (0 = done, -1 = error).
 * Use when the complete message or EOF has been written and must arrive. */
static int http_recv_until_done(struct http_conn *restrict p)
{
	for (int waited = 0; waited < TEST_RECV_BUDGET_MS;) {
		const int ret = http_conn_recv(p);
		if (ret <= 0) {
			return ret;
		}
		struct pollfd pfd = {
			.fd = p->fd,
			.events = POLLIN,
		};
		if (poll(&pfd, 1, TEST_RECV_QUIET_MS) <= 0) {
			waited += TEST_RECV_QUIET_MS;
		}
	}
	return 1;
}

/* Receive every fragment currently available, then return the parser result
 * once the connection goes quiet. Use when only a partial message has been
 * written and the parser is expected to still need more input. */
static int http_recv_drain(struct http_conn *restrict p)
{
	for (;;) {
		const int ret = http_conn_recv(p);
		if (ret <= 0) {
			return ret;
		}
		struct pollfd pfd = {
			.fd = p->fd,
			.events = POLLIN,
		};
		if (poll(&pfd, 1, TEST_RECV_QUIET_MS) <= 0) {
			return ret;
		}
	}
}

/*
 * socketpair() can fail transiently with EMFILE/ENFILE/ENOBUFS under the
 * resource pressure of a parallel `ctest -j` run on socket emulations such as
 * Cygwin/MSYS. Retry briefly so a test does not abort on a momentary shortage;
 * a persistent failure still aborts after the budget is exhausted.
 */
static void make_socketpair(int sv[2])
{
	bool ok = false;
	for (int attempt = 0; attempt < 100; attempt++) {
		ok = (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
		if (ok) {
			return;
		}
		const int err = errno;
		if (err != EMFILE && err != ENFILE && err != ENOBUFS &&
		    err != EINTR) {
			break;
		}
		(void)poll(NULL, 0, 10);
	}
	T_CHECK(ok);
}

static bool fd_set_nonblock(const int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		return false;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
		return false;
	}
	return true;
}

static bool parse_header_cb(void *ctx, const char *key, char *value)
{
	struct header_cb_ctx *const c = ctx;
	if (c->reject) {
		return false;
	}

	if (strcasecmp(key, "TE") == 0) {
		return parsehdr_accept_te(c->p, value);
	}
	if (strcasecmp(key, "Transfer-Encoding") == 0) {
		return parsehdr_transfer_encoding(c->p, value);
	}
	if (strcasecmp(key, "Accept-Encoding") == 0) {
		return parsehdr_accept_encoding(c->p, value);
	}
	if (strcasecmp(key, "Content-Length") == 0) {
		return parsehdr_content_length(c->p, value);
	}
	if (strcasecmp(key, "Content-Encoding") == 0) {
		return parsehdr_content_encoding(c->p, value);
	}
	if (strcasecmp(key, "Expect") == 0) {
		return parsehdr_expect(c->p, value);
	}
	return true;
}

static void conn_init_for_test(
	struct http_conn *restrict p, const int fd,
	const enum http_conn_state mode, struct header_cb_ctx *restrict cb)
{
	*cb = (struct header_cb_ctx){
		.p = p,
		.reject = false,
	};
	const struct http_parsehdr_cb on_header = {
		.func = parse_header_cb,
		.ctx = cb,
	};
	http_conn_init(p, fd, mode, on_header, NULL, NULL);
}

static bool stream_read_exact(
	struct stream *restrict r, unsigned char *restrict buf,
	const size_t want)
{
	size_t got = 0;
	while (got < want) {
		size_t n = want - got;
		if (stream_read(r, buf + got, &n) != 0) {
			return false;
		}
		if (n == 0) {
			break;
		}
		got += n;
	}
	return got == want;
}

static bool stream_write_all(
	struct stream *restrict w, const void *restrict data, const size_t len)
{
	size_t n = len;
	if (stream_write(w, data, &n) != 0) {
		return false;
	}
	return n == len;
}

/* -------------------------------------------------------------------------
 * fuzz - randomized HTTP inputs are exercised by main_test; none here.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - message framing, header parsing and codec selection cases.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(http_conn_init_request)
{
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };

	conn_init_for_test(&p, 7, STATE_PARSE_REQUEST, &cb);
	T_EXPECT_EQ(p.state, STATE_PARSE_REQUEST);
	T_EXPECT_EQ(p.fd, 7);
	T_EXPECT_EQ(p.http_status, HTTP_BAD_REQUEST);
	T_EXPECT(p.next == NULL);
	T_EXPECT(p.cbuf == NULL);
}

T_DECLARE_CASE(http_conn_init_response)
{
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };

	conn_init_for_test(&p, 8, STATE_PARSE_RESPONSE, &cb);
	T_EXPECT_EQ(p.state, STATE_PARSE_RESPONSE);
	T_EXPECT_EQ(p.fd, 8);
}

T_DECLARE_CASE(parsehdr_accept_te_cases)
{
	struct http_conn p = { 0 };

	{
		char value[] = "   ";
		T_EXPECT(parsehdr_accept_te(&p, value));
		T_EXPECT_EQ(p.hdr.transfer.accept, TENCODING_NONE);
	}
	{
		char value[] = " chunked ";
		T_EXPECT(parsehdr_accept_te(&p, value));
		T_EXPECT_EQ(p.hdr.transfer.accept, TENCODING_CHUNKED);
	}
	{
		char value[] = "gzip";
		T_EXPECT(!parsehdr_accept_te(&p, value));
	}
}

T_DECLARE_CASE(parsehdr_transfer_encoding_cases)
{
	struct http_conn p = { 0 };

	{
		char value[] = "";
		T_EXPECT(parsehdr_transfer_encoding(&p, value));
		T_EXPECT_EQ(p.hdr.transfer.encoding, TENCODING_NONE);
	}
	{
		char value[] = "chunked";
		T_EXPECT(parsehdr_transfer_encoding(&p, value));
		T_EXPECT_EQ(p.hdr.transfer.encoding, TENCODING_CHUNKED);
	}
	{
		char value[] = "deflate";
		T_EXPECT(!parsehdr_transfer_encoding(&p, value));
	}
}

T_DECLARE_CASE(parsehdr_transfer_encoding_rejects_content_length_conflict)
{
	struct http_conn p = { 0 };
	p.hdr.content.has_length = true;

	/* RFC 9112 §6.3: Transfer-Encoding: chunked must be rejected once
	 * Content-Length has already been seen (the reverse header order
	 * from parsehdr_content_length_rejects_te_chunked_conflict). */
	char value[] = "chunked";
	T_EXPECT(!parsehdr_transfer_encoding(&p, value));
	T_EXPECT_EQ(p.hdr.transfer.encoding, TENCODING_NONE);
}

T_DECLARE_CASE(parsehdr_accept_encoding_cases)
{
	struct http_conn p = { 0 };

	{
		char value[] = "*";
		T_EXPECT(parsehdr_accept_encoding(&p, value));
		T_EXPECT_EQ(p.hdr.accept_encoding, CENCODING_DEFLATE);
	}
	{
		char value[] = "gzip;q=0.5, DEFLATE;q=0.8";
		T_EXPECT(parsehdr_accept_encoding(&p, value));
		T_EXPECT_EQ(p.hdr.accept_encoding, CENCODING_DEFLATE);
	}
	{
		struct http_conn q = { 0 };
		char value[] = "gzip,br";
		T_EXPECT(parsehdr_accept_encoding(&q, value));
		T_EXPECT_EQ(q.hdr.accept_encoding, CENCODING_NONE);
	}
}

T_DECLARE_CASE(parsehdr_content_length_cases)
{
	/* each scenario uses its own conn: parsehdr_content_length now
	 * tracks has_length across calls, so reusing one would make later
	 * scenarios spuriously hit the duplicate-rejection path below. */
	{
		struct http_conn p = { 0 };
		p.msg.req.method = "GET";
		T_EXPECT(parsehdr_content_length(&p, "0"));
		T_EXPECT(p.hdr.content.has_length);
		T_EXPECT_EQ(p.hdr.content.length, 0);
	}
	{
		struct http_conn p = { 0 };
		p.msg.req.method = "GET";
		T_EXPECT(parsehdr_content_length(&p, "17"));
		T_EXPECT_EQ(p.hdr.content.length, 17);
	}
	{
		struct http_conn p = { 0 };
		p.msg.req.method = "GET";
		T_EXPECT(!parsehdr_content_length(&p, "12x"));
	}
	{
		struct http_conn p = { 0 };
		p.msg.req.method = "CONNECT";
		T_EXPECT(!parsehdr_content_length(&p, "1"));
	}
	/* RFC 9110 §8.6: Content-Length = 1*DIGIT, no sign of either kind
	 * and at least one digit required. */
	{
		struct http_conn p = { 0 };
		p.msg.req.method = "GET";
		T_EXPECT(!parsehdr_content_length(&p, "-1"));
	}
	{
		struct http_conn p = { 0 };
		p.msg.req.method = "GET";
		T_EXPECT(!parsehdr_content_length(&p, "+1"));
	}
	{
		struct http_conn p = { 0 };
		p.msg.req.method = "GET";
		T_EXPECT(!parsehdr_content_length(&p, ""));
	}
}

T_DECLARE_CASE(parsehdr_content_length_rejects_duplicate)
{
	struct http_conn p = { 0 };
	p.msg.req.method = "GET";

	/* RFC 9112 §6.3: a second Content-Length must be rejected, even
	 * when its value matches the first. */
	T_EXPECT(parsehdr_content_length(&p, "5"));
	T_EXPECT(!parsehdr_content_length(&p, "5"));
	T_EXPECT_EQ(p.hdr.content.length, 5);
}

T_DECLARE_CASE(parsehdr_content_length_rejects_te_chunked_conflict)
{
	struct http_conn p = { 0 };
	p.msg.req.method = "GET";
	p.hdr.transfer.encoding = TENCODING_CHUNKED;

	/* RFC 9112 §6.3: Content-Length must be rejected once
	 * Transfer-Encoding: chunked has already been seen. */
	T_EXPECT(!parsehdr_content_length(&p, "5"));
	T_EXPECT(!p.hdr.content.has_length);
}

T_DECLARE_CASE(parsehdr_content_encoding_cases)
{
	struct http_conn p = { 0 };

	T_EXPECT(parsehdr_content_encoding(&p, "deflate"));
	T_EXPECT_EQ(p.hdr.content.encoding, CENCODING_DEFLATE);

	T_EXPECT(parsehdr_content_encoding(&p, "GZIP"));
	T_EXPECT_EQ(p.hdr.content.encoding, CENCODING_GZIP);

	T_EXPECT(!parsehdr_content_encoding(&p, "br"));
	T_EXPECT_EQ(p.http_status, HTTP_UNSUPPORTED_MEDIA_TYPE);
}

T_DECLARE_CASE(parsehdr_expect_cases)
{
	struct http_conn p = { 0 };

	{
		char value[] = " 100-Continue ";
		T_EXPECT(parsehdr_expect(&p, value));
		T_EXPECT(p.expect_continue);
	}
	{
		char value[] = "100-digest";
		p.expect_continue = false;
		T_EXPECT(!parsehdr_expect(&p, value));
		T_EXPECT(!p.expect_continue);
		T_EXPECT_EQ(p.http_status, HTTP_EXPECTATION_FAILED);
	}
}

T_DECLARE_CASE(content_reader_none)
{
	static const unsigned char input[] = "hello";
	unsigned char output[sizeof(input)] = { 0 };
	struct stream *r = content_reader(input, sizeof(input), CENCODING_NONE);

	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, output, sizeof(output)));
	T_EXPECT_MEMEQ(output, input, sizeof(input));
	T_EXPECT_EQ(stream_close(r), 0);
}

T_DECLARE_CASE(content_reader_gzip)
{
	static const unsigned char gzip_data[] = {
		0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x86,
		0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00,
	};
	static const unsigned char expected[] = { 'h', 'e', 'l', 'l', 'o' };
	unsigned char output[sizeof(expected)] = { 0 };
	struct stream *r =
		content_reader(gzip_data, sizeof(gzip_data), CENCODING_GZIP);
	bool ok = false;
	int rc = -1;

	T_CHECK(r != NULL);
	ok = stream_read_exact(r, output, sizeof(output));
	rc = stream_close(r);
	T_EXPECT(ok);
	T_EXPECT_MEMEQ(output, expected, sizeof(expected));
	T_EXPECT_EQ(rc, 0);
}

T_DECLARE_CASE(content_writer_roundtrip_none)
{
	struct vbuffer *vbuf = NULL;
	static const unsigned char input[] = "roundtrip-none";
	unsigned char output[sizeof(input)] = { 0 };

	struct stream *w = content_writer(&vbuf, 64, CENCODING_NONE);
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, input, sizeof(input)));
	T_EXPECT_EQ(stream_close(w), 0);
	T_CHECK(vbuf != NULL);
	T_EXPECT(VBUF_LEN(vbuf) >= sizeof(input));

	struct stream *r =
		content_reader(VBUF_DATA(vbuf), VBUF_LEN(vbuf), CENCODING_NONE);
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, output, sizeof(output)));
	T_EXPECT_MEMEQ(output, input, sizeof(input));
	T_EXPECT_EQ(stream_close(r), 0);

	VBUF_FREE(vbuf);
}

T_DECLARE_CASE(content_writer_roundtrip_deflate)
{
	struct vbuffer *vbuf = NULL;
	static const unsigned char input[] = "roundtrip-deflate";
	unsigned char output[sizeof(input)] = { 0 };

	struct stream *w = content_writer(&vbuf, 64, CENCODING_DEFLATE);
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, input, sizeof(input)));
	T_EXPECT_EQ(stream_close(w), 0);
	T_CHECK(vbuf != NULL);

	struct stream *r = content_reader(
		VBUF_DATA(vbuf), VBUF_LEN(vbuf), CENCODING_DEFLATE);
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, output, sizeof(output)));
	T_EXPECT_MEMEQ(output, input, sizeof(input));
	T_EXPECT_EQ(stream_close(r), 0);

	VBUF_FREE(vbuf);
}

/* Regression: content_writer must support gzip symmetrically with
 * content_reader, not abort (FAILMSGF) on CENCODING_GZIP. */
T_DECLARE_CASE(content_writer_roundtrip_gzip)
{
	struct vbuffer *vbuf = NULL;
	static const unsigned char input[] = "roundtrip-gzip";
	unsigned char output[sizeof(input)] = { 0 };

	struct stream *w = content_writer(&vbuf, 64, CENCODING_GZIP);
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, input, sizeof(input)));
	T_EXPECT_EQ(stream_close(w), 0);
	T_CHECK(vbuf != NULL);

	struct stream *r =
		content_reader(VBUF_DATA(vbuf), VBUF_LEN(vbuf), CENCODING_GZIP);
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, output, sizeof(output)));
	T_EXPECT_MEMEQ(output, input, sizeof(input));
	T_EXPECT_EQ(stream_close(r), 0);

	VBUF_FREE(vbuf);
}

T_DECLARE_CASE(http_resp_errpage_normal_and_fallback)
{
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };

	conn_init_for_test(&p, -1, STATE_PARSE_REQUEST, &cb);
	p.cbuf = VBUF_NEW(16);
	T_CHECK(p.cbuf != NULL);
	VBUF_APPENDSTR(p.cbuf, "dummy");

	http_resp_errpage(&p, HTTP_BAD_REQUEST);
	T_EXPECT(p.cbuf == NULL);
	T_EXPECT(p.wbuf.len > 0);
	T_EXPECT(memmem(p.wbuf.data, p.wbuf.len, "HTTP/1.1 400", 12) != NULL);

	/* A too-small write buffer truncates the page but must never let
	 * wbuf.len exceed wbuf.cap (regression: the length was added
	 * unclamped, so wbuf.len could run past what was actually written). */
	p.wbuf.len = 0;
	p.wbuf.cap = 32;
	http_resp_errpage(&p, HTTP_BAD_REQUEST);
	T_EXPECT(p.wbuf.len > 0);
	T_EXPECT(p.wbuf.len <= p.wbuf.cap);

	/* An unknown status code makes http_error() return 0, exercising the
	 * code-only fallback that still emits Connection: close. */
	p.wbuf.len = 0;
	p.wbuf.cap = sizeof(p.wbuf.data);
	http_resp_errpage(&p, 599);
	T_EXPECT(
		memmem(p.wbuf.data, p.wbuf.len, "Connection: close", 17) !=
		NULL);
}

T_DECLARE_CASE(http_conn_recv_request_ok)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char req[] = "GET /hello HTTP/1.1\r\n"
				  "Host: test\r\n"
				  "\r\n";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req, sizeof(req) - 1));
	const int ret = http_recv_until_done(&p);
	T_EXPECT_EQ(ret, 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);
	T_EXPECT_STREQ(p.msg.req.method, "GET");
	T_EXPECT_STREQ(p.msg.req.url, "/hello");

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_conn_recv_response_ok)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char rsp[] = "HTTP/1.1 204 No Content\r\n"
				  "Date: Wed, 01 Jan 2025 00:00:00 GMT\r\n"
				  "\r\n";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_RESPONSE, &cb);

	T_CHECK(write_all(sv[1], rsp, sizeof(rsp) - 1));
	const int ret = http_recv_until_done(&p);
	T_EXPECT_EQ(ret, 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);
	T_EXPECT_STREQ(p.msg.rsp.version, "HTTP/1.1");
	T_EXPECT_STREQ(p.msg.rsp.code, "204");
	T_EXPECT_STREQ(p.msg.rsp.status, "No Content");

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

/* Response mode reports a hard -1 (immediate teardown) rather than the
 * request mode's graceful STATE_PARSE_ERROR: unsupported response version. */
T_DECLARE_CASE(http_conn_recv_response_unsupported_version)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char rsp[] = "HTTP/2 200 OK\r\n\r\n";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_RESPONSE, &cb);

	T_CHECK(write_all(sv[1], rsp, sizeof(rsp) - 1));
	T_EXPECT_EQ(http_recv_until_done(&p), -1);

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

/* Response mode: a malformed header line also returns a hard -1. */
T_DECLARE_CASE(http_conn_recv_response_malformed_header)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char rsp[] = "HTTP/1.1 200 OK\r\n"
				  "no-colon-here\r\n"
				  "\r\n";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_RESPONSE, &cb);

	T_CHECK(write_all(sv[1], rsp, sizeof(rsp) - 1));
	T_EXPECT_EQ(http_recv_until_done(&p), -1);

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

/* A Content-Length beyond HTTP_MAX_CONTENT must be rejected with
 * ENTITY_TOO_LARGE (bounds the VBUF_NEW allocation). */
T_DECLARE_CASE(http_conn_recv_content_length_too_large)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };
	/* HTTP_MAX_CONTENT is 4194304 */
	static const char req[] = "POST / HTTP/1.1\r\n"
				  "Content-Length: 4194305\r\n"
				  "\r\n";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req, sizeof(req) - 1));
	T_EXPECT_EQ(http_recv_until_done(&p), 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_ERROR);
	T_EXPECT_EQ(p.http_status, HTTP_ENTITY_TOO_LARGE);

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_conn_recv_bad_version)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char req[] = "GET / HTTP/2.0\r\n\r\n";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req, sizeof(req) - 1));
	/* request-mode: bad version → STATE_PARSE_ERROR + 0 (not -1) */
	const int ret = http_recv_until_done(&p);
	T_EXPECT_EQ(ret, 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_ERROR);

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

/*
 * Regression: a header value that never contains \r\n must fail cleanly
 * (413), matching parse_message()'s existing guard for an unterminated
 * request line. Pre-fix, parse_header() had no such guard: rbuf fills
 * up, the next recv_request() computes a zero-length read, and that gets
 * misread as early EOF -- tearing down the connection with no response.
 */
T_DECLARE_CASE(http_conn_recv_header_line_too_long)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char reqline[] = "GET / HTTP/1.1\r\nX-Long: ";
	unsigned char filler[HTTP_MAX_ENTITY];
	memset(filler, 'a', sizeof(filler));

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], reqline, sizeof(reqline) - 1));
	T_CHECK(write_all(sv[1], filler, sizeof(filler)));

	const int ret = http_recv_until_done(&p);
	T_EXPECT_EQ(ret, 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_ERROR);
	T_EXPECT_EQ(p.http_status, HTTP_ENTITY_TOO_LARGE);

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_conn_recv_incremental)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char req1[] = "GET / HTTP/1.1\r\n"
				   "Host: a\r\n";
	static const char req2[] = "\r\n";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req1, sizeof(req1) - 1));
	const int ret1 = http_recv_drain(&p);
	T_EXPECT_EQ(ret1, 1);
	T_CHECK(write_all(sv[1], req2, sizeof(req2) - 1));
	const int ret2 = http_recv_until_done(&p);
	T_EXPECT_EQ(ret2, 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_conn_recv_content_incomplete_then_complete)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char req1[] = "POST /x HTTP/1.1\r\n"
				   "Content-Length: 5\r\n"
				   "\r\n"
				   "he";
	static const char req2[] = "llo";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req1, sizeof(req1) - 1));
	const int ret1 = http_recv_drain(&p);
	T_EXPECT_EQ(ret1, 1);
	T_CHECK(p.cbuf != NULL);
	T_EXPECT_EQ(VBUF_LEN(p.cbuf), 2);

	T_CHECK(write_all(sv[1], req2, sizeof(req2) - 1));
	const int ret2 = http_recv_until_done(&p);
	T_EXPECT_EQ(ret2, 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);
	T_EXPECT_EQ(VBUF_LEN(p.cbuf), 5);
	T_EXPECT_MEMEQ(VBUF_DATA(p.cbuf), "hello", 5);

	VBUF_FREE(p.cbuf);
	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_conn_recv_content_clamped_to_content_length)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };
	/* Content-Length: 5 declared, but 8 body bytes arrive in the same
	 * write as the headers; the extra 3 bytes must not be copied into
	 * the content buffer (they belong to a later message, if anything). */
	static const char req[] = "POST /x HTTP/1.1\r\n"
				  "Content-Length: 5\r\n"
				  "\r\n"
				  "hello!!!";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req, sizeof(req) - 1));
	const int ret = http_recv_until_done(&p);
	T_EXPECT_EQ(ret, 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);
	T_CHECK(p.cbuf != NULL);
	T_EXPECT_EQ(VBUF_LEN(p.cbuf), 5);
	T_EXPECT_MEMEQ(VBUF_DATA(p.cbuf), "hello", 5);

	VBUF_FREE(p.cbuf);
	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_conn_recv_expect_continue)
{
	int sv[2] = { -1, -1 };
	unsigned char rsp[128] = { 0 };
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char req1[] = "POST /x HTTP/1.1\r\n"
				   "Expect: 100-continue\r\n"
				   "Content-Length: 5\r\n"
				   "\r\n";
	static const char req2[] = "hello";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req1, sizeof(req1) - 1));
	const int ret1 = http_recv_drain(&p);
	T_EXPECT_EQ(ret1, 1);
	T_EXPECT(p.expect_continue);

	/* read the 100-continue reply, tolerating fragmented delivery */
	size_t rsplen = 0;
	for (int waited = 0; waited < TEST_RECV_BUDGET_MS &&
			     memmem(rsp, rsplen, "100 Continue", 12) == NULL;) {
		struct pollfd pfd = {
			.fd = sv[1],
			.events = POLLIN,
		};
		if (poll(&pfd, 1, TEST_RECV_QUIET_MS) <= 0) {
			waited += TEST_RECV_QUIET_MS;
			continue;
		}
		const ssize_t n =
			recv_nowait(sv[1], rsp + rsplen, sizeof(rsp) - rsplen);
		if (n > 0) {
			rsplen += (size_t)n;
		}
	}
	T_EXPECT(memmem(rsp, rsplen, "100 Continue", 12) != NULL);

	T_CHECK(write_all(sv[1], req2, sizeof(req2) - 1));
	const int ret2 = http_recv_until_done(&p);
	T_EXPECT_EQ(ret2, 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);

	VBUF_FREE(p.cbuf);
	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_conn_recv_content_early_eof)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char req[] = "POST /x HTTP/1.1\r\n"
				  "Content-Length: 5\r\n"
				  "\r\n"
				  "he";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req, sizeof(req) - 1));
	T_EXPECT_EQ(http_conn_recv(&p), 1);
	T_CHECK(shutdown(sv[1], SHUT_WR) == 0);
	T_EXPECT_EQ(http_conn_recv(&p), -1);

	VBUF_FREE(p.cbuf);
	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_conn_recv_header_callback_reject)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct header_cb_ctx cb = { 0 };
	static const char req[] = "GET /x HTTP/1.1\r\n"
				  "Host: reject\r\n"
				  "\r\n";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);
	cb.reject = true;

	T_CHECK(write_all(sv[1], req, sizeof(req) - 1));
	T_EXPECT_EQ(http_conn_recv(&p), 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_ERROR);

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

/* ------------------------------------------------------------------ */
/* http_body_* tests                                                   */
/* ------------------------------------------------------------------ */

struct body_sink {
	unsigned char buf[1024];
	size_t len;
	bool reject;
};

static bool body_sink_cb(void *ctx, const unsigned char *data, const size_t len)
{
	struct body_sink *s = ctx;
	if (s->reject) {
		return false;
	}
	if (s->len + len > sizeof(s->buf)) {
		return false;
	}
	memcpy(s->buf + s->len, data, len);
	s->len += len;
	return true;
}

T_DECLARE_CASE(http_body_none)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_NONE, 0);
	T_EXPECT(d.done);
	T_EXPECT(http_body_finish(&d));

	/* any consume on HTTP_BODY_NONE returns false */
	static const unsigned char data[] = "x";
	size_t n = 1;
	T_EXPECT(!http_body_consume(&d, data, &n, cb));

	/* zero-length consume is always accepted */
	n = 0;
	T_EXPECT(http_body_consume(&d, data, &n, cb));
}

T_DECLARE_CASE(http_body_content_length)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};
	static const unsigned char data[] = "hello";

	http_body_init(&d, HTTP_BODY_CONTENT_LENGTH, 5);
	T_EXPECT(!d.done);
	T_EXPECT(!http_body_finish(&d));

	size_t n = 5;
	T_EXPECT(http_body_consume(&d, data, &n, cb));
	T_EXPECT_EQ(n, (size_t)5);
	T_EXPECT(d.done);
	T_EXPECT(http_body_finish(&d));
	T_EXPECT_EQ(sink.len, (size_t)5);
	T_EXPECT_MEMEQ(sink.buf, data, 5);

	/* extra data after completion */
	n = 1;
	T_EXPECT(!http_body_consume(&d, data, &n, cb));

	/* zero content-length body is immediately done */
	http_body_init(&d, HTTP_BODY_CONTENT_LENGTH, 0);
	T_EXPECT(d.done);
}

T_DECLARE_CASE(http_body_content_length_overflow)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};
	static const unsigned char data[] = "hello world";

	http_body_init(&d, HTTP_BODY_CONTENT_LENGTH, 5);
	/* providing more bytes than content_length must fail */
	size_t n = sizeof(data) - 1;
	T_EXPECT(!http_body_consume(&d, data, &n, cb));
}

T_DECLARE_CASE(http_body_content_length_cb_reject)
{
	struct http_body d;
	struct body_sink sink = { .reject = true };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};
	static const unsigned char data[] = "hello";

	http_body_init(&d, HTTP_BODY_CONTENT_LENGTH, 5);
	size_t n = 5;
	T_EXPECT(!http_body_consume(&d, data, &n, cb));
}

T_DECLARE_CASE(http_body_eof)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};
	static const unsigned char data[] = "stream";

	http_body_init(&d, HTTP_BODY_EOF, 0);
	T_EXPECT(!d.done);

	size_t n = sizeof(data) - 1;
	T_EXPECT(http_body_consume(&d, data, &n, cb));
	T_EXPECT_EQ(n, sizeof(data) - 1);
	T_EXPECT(!d.done); /* not done until http_body_finish */
	T_EXPECT_EQ(sink.len, sizeof(data) - 1);

	T_EXPECT(http_body_finish(&d));
	T_EXPECT(d.done);
}

T_DECLARE_CASE(http_body_eof_cb_reject)
{
	struct http_body d;
	struct body_sink sink = { .reject = true };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};
	static const unsigned char data[] = "stream";

	http_body_init(&d, HTTP_BODY_EOF, 0);
	size_t n = sizeof(data) - 1;
	T_EXPECT(!http_body_consume(&d, data, &n, cb));
}

T_DECLARE_CASE(http_body_chunked_simple)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_CHUNKED, 0);
	T_EXPECT(!d.done);

	/* "5\r\nhello\r\n0\r\n\r\n" */
	static const unsigned char chunk[] = "5\r\nhello\r\n0\r\n\r\n";
	size_t n = sizeof(chunk) - 1;
	T_EXPECT(http_body_consume(&d, chunk, &n, cb));
	T_EXPECT_EQ(n, sizeof(chunk) - 1);
	T_EXPECT(d.done);
	T_EXPECT(http_body_finish(&d));
	T_EXPECT_EQ(sink.len, (size_t)5);
	T_EXPECT_MEMEQ(sink.buf, "hello", 5);
}

T_DECLARE_CASE(http_body_chunked_split_input)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_CHUNKED, 0);

	/* Feed one byte at a time to exercise state machine transitions. */
	static const unsigned char chunk[] = "3\r\nabc\r\n0\r\n\r\n";
	for (size_t i = 0; i < sizeof(chunk) - 1; i++) {
		size_t n = 1;
		T_EXPECT(http_body_consume(&d, chunk + i, &n, cb));
	}
	T_EXPECT(d.done);
	T_EXPECT_EQ(sink.len, (size_t)3);
	T_EXPECT_MEMEQ(sink.buf, "abc", 3);
}

T_DECLARE_CASE(http_body_chunked_uppercase_hex)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_CHUNKED, 0);

	/* Uppercase hex size: "A" = 10 bytes */
	static const unsigned char chunk[] = "A\r\n0123456789\r\n0\r\n\r\n";
	size_t n = sizeof(chunk) - 1;
	T_EXPECT(http_body_consume(&d, chunk, &n, cb));
	T_EXPECT(d.done);
	T_EXPECT_EQ(sink.len, (size_t)10);
}

T_DECLARE_CASE(http_body_chunked_with_extension)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_CHUNKED, 0);

	/* Chunk size line with extension: "5;ext=val\r\nhello\r\n0\r\n\r\n" */
	static const unsigned char chunk[] = "5;ext=val\r\nhello\r\n0\r\n\r\n";
	size_t n = sizeof(chunk) - 1;
	T_EXPECT(http_body_consume(&d, chunk, &n, cb));
	T_EXPECT(d.done);
	T_EXPECT_EQ(sink.len, (size_t)5);
}

T_DECLARE_CASE(http_body_chunked_trailer)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_CHUNKED, 0);

	/* Last chunk with trailer header: "0\r\nTrailer: val\r\n\r\n" */
	static const unsigned char chunk[] = "0\r\nTrailer: val\r\n\r\n";
	size_t n = sizeof(chunk) - 1;
	T_EXPECT(http_body_consume(&d, chunk, &n, cb));
	T_EXPECT(d.done);
	T_EXPECT_EQ(sink.len, (size_t)0);
}

T_DECLARE_CASE(http_body_chunked_no_hex_digit_fails)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_CHUNKED, 0);

	/* Leading \r\n with no hex digit must fail */
	static const unsigned char bad[] = "\r\nhello";
	size_t n = sizeof(bad) - 1;
	T_EXPECT(!http_body_consume(&d, bad, &n, cb));
}

T_DECLARE_CASE(http_body_chunked_size_line_too_long)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_CHUNKED, 0);

	/* Fill the 128-byte line buffer to trigger the overflow check. */
	unsigned char long_line[130];
	memset(long_line, 'a', 128);
	long_line[128] = '\n';
	long_line[129] = '\0';
	size_t n = 129;
	T_EXPECT(!http_body_consume(&d, long_line, &n, cb));
}

T_DECLARE_CASE(http_body_chunked_missing_cr_after_data)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_CHUNKED, 0);

	/* After chunk data the CRLF separator is mandatory;
	 * a bare LF in place of CR must be rejected. */
	static const unsigned char bad[] = "3\r\nabc\nmore";
	size_t n = sizeof(bad) - 1;
	T_EXPECT(!http_body_consume(&d, bad, &n, cb));
}

T_DECLARE_CASE(http_body_chunked_extra_data_after_done)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_CHUNKED, 0);
	static const unsigned char chunk[] = "0\r\n\r\n";
	size_t n = sizeof(chunk) - 1;
	T_EXPECT(http_body_consume(&d, chunk, &n, cb));
	T_EXPECT_EQ(n, sizeof(chunk) - 1);
	T_EXPECT(d.done);

	/* any data after the terminal chunk, in a separate call, must be
	 * rejected -- unlike trailing bytes within the same call, which
	 * http_body_chunked_trailing_data_after_terminator covers below */
	static const unsigned char extra[] = "x";
	n = 1;
	T_EXPECT(!http_body_consume(&d, extra, &n, cb));
}

/*
 * Regression: trailing bytes past the chunked terminator in the SAME
 * call (e.g. the start of a pipelined next request read in one recv())
 * must be reported via *len, not treated as a parse failure.
 */
T_DECLARE_CASE(http_body_chunked_trailing_data_after_terminator)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_CHUNKED, 0);
	static const unsigned char chunk[] = "3\r\nabc\r\n0\r\n\r\nGET / HTTP";
	static const size_t terminator_len =
		sizeof("3\r\nabc\r\n0\r\n\r\n") - 1;
	size_t n = sizeof(chunk) - 1;
	T_EXPECT(http_body_consume(&d, chunk, &n, cb));
	T_EXPECT(d.done);
	T_EXPECT_EQ(sink.len, (size_t)3);
	T_EXPECT_MEMEQ(sink.buf, "abc", 3);
	/* only the terminator itself was consumed; the pipelined bytes
	 * that followed in the same buffer are left for the caller */
	T_EXPECT_EQ(n, terminator_len);
}

T_DECLARE_CASE(http_body_chunked_data_cb_reject)
{
	struct http_body d;
	struct body_sink sink = { .reject = true };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_CHUNKED, 0);
	static const unsigned char chunk[] = "3\r\nabc\r\n0\r\n\r\n";
	size_t n = sizeof(chunk) - 1;
	T_EXPECT(!http_body_consume(&d, chunk, &n, cb));
}
T_DECLARE_CASE(http_body_chunked_lowercase_hex)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_CHUNKED, 0);

	/* Lowercase hex size: "a" = 10 bytes */
	static const unsigned char chunk[] = "a\r\n0123456789\r\n0\r\n\r\n";
	size_t n = sizeof(chunk) - 1;
	T_EXPECT(http_body_consume(&d, chunk, &n, cb));
	T_EXPECT(d.done);
	T_EXPECT_EQ(sink.len, (size_t)10);
}

T_DECLARE_CASE(http_body_chunked_size_value_overflow)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_CHUNKED, 0);

	/* A 17-digit hex chunk size overflows size_t and must be rejected. */
	static const unsigned char bad[] = "fffffffffffffffff\r\n";
	size_t n = sizeof(bad) - 1;
	T_EXPECT(!http_body_consume(&d, bad, &n, cb));
}

T_DECLARE_CASE(http_body_chunked_size_trailing_ws)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_CHUNKED, 0);

	/* Trailing spaces/tabs after the size are tolerated. */
	static const unsigned char chunk[] = "5 \t\r\nhello\r\n0\r\n\r\n";
	size_t n = sizeof(chunk) - 1;
	T_EXPECT(http_body_consume(&d, chunk, &n, cb));
	T_EXPECT(d.done);
	T_EXPECT_EQ(sink.len, (size_t)5);
	T_EXPECT_MEMEQ(sink.buf, "hello", 5);
}

T_DECLARE_CASE(http_body_chunked_size_trailing_junk)
{
	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};

	http_body_init(&d, HTTP_BODY_CHUNKED, 0);

	/* Non-hex, non-extension junk after the size must be rejected. */
	static const unsigned char bad[] = "5x\r\nhello\r\n";
	size_t n = sizeof(bad) - 1;
	T_EXPECT(!http_body_consume(&d, bad, &n, cb));
}

T_DECLARE_CASE(http_chunk_header_format)
{
	char buf[HTTP_CHUNK_HEADER_MAX];
	T_EXPECT_EQ(http_chunk_header(buf, 1), (size_t)3);
	T_EXPECT_MEMEQ(buf, "1\r\n", 3);
	T_EXPECT_EQ(http_chunk_header(buf, 16), (size_t)4);
	T_EXPECT_MEMEQ(buf, "10\r\n", 4);
	T_EXPECT_EQ(http_chunk_header(buf, 255), (size_t)4);
	T_EXPECT_MEMEQ(buf, "ff\r\n", 4);
	T_EXPECT_EQ(http_chunk_header(buf, 4096), (size_t)6);
	T_EXPECT_MEMEQ(buf, "1000\r\n", 6);
}

/* A stream re-chunked with http_chunk_header round-trips through the http_body
 * chunked dechunker back to the original bytes. */
T_DECLARE_CASE(http_chunk_header_roundtrip)
{
	static const char *const parts[2] = { "Hello, ", "chunked world!" };
	static const char expect[] = "Hello, chunked world!";
	unsigned char stream[256];
	size_t slen = 0;
	for (int i = 0; i < 2; i++) {
		const size_t dl = strlen(parts[i]);
		char hdr[HTTP_CHUNK_HEADER_MAX];
		const size_t hn = http_chunk_header(hdr, dl);
		memcpy(stream + slen, hdr, hn);
		slen += hn;
		memcpy(stream + slen, parts[i], dl);
		slen += dl;
		stream[slen++] = '\r';
		stream[slen++] = '\n';
	}
	memcpy(stream + slen, HTTP_CHUNK_TERMINATOR,
	       sizeof(HTTP_CHUNK_TERMINATOR) - 1);
	slen += sizeof(HTTP_CHUNK_TERMINATOR) - 1;

	struct http_body d;
	struct body_sink sink = { 0 };
	const struct http_body_data_cb cb = {
		.func = body_sink_cb,
		.ctx = &sink,
	};
	http_body_init(&d, HTTP_BODY_CHUNKED, 0);
	size_t n = slen;
	T_EXPECT(http_body_consume(&d, stream, &n, cb));
	T_EXPECT_EQ(n, slen);
	T_EXPECT(http_body_finish(&d));
	T_EXPECT_EQ(sink.len, sizeof(expect) - 1);
	T_EXPECT_MEMEQ(sink.buf, expect, sizeof(expect) - 1);
}

/* -------------------------------------------------------------------------
 * bench - end-to-end recv + parse of a representative keep-alive request.
 * Runs only when a name filter selects it (e.g. --run bench); a plain ctest
 * run skips it.
 * ---------------------------------------------------------------------- */

static const char BENCH_REQUEST[] = "GET /path/to/resource?query=1 HTTP/1.1\r\n"
				    "Host: example.com\r\n"
				    "User-Agent: neosocksd-bench/1.0\r\n"
				    "Accept: */*\r\n"
				    "Accept-Encoding: gzip, deflate\r\n"
				    "Connection: keep-alive\r\n"
				    "Content-Length: 0\r\n"
				    "\r\n";

T_DECLARE_BENCH(bench_parse_request)
{
	int sv[2];
	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));

	for (uint_fast64_t iter = 0; iter < _b_->N; ++iter) {
		const char *p = BENCH_REQUEST;
		size_t left = sizeof(BENCH_REQUEST) - 1;
		while (left > 0) {
			const ssize_t n = write(sv[1], p, left);
			T_CHECK(n > 0);
			p += n;
			left -= (size_t)n;
		}

		struct http_conn conn = { 0 };
		struct header_cb_ctx cb = { 0 };
		conn_init_for_test(&conn, sv[0], STATE_PARSE_REQUEST, &cb);
		for (int k = 0; k < 16 && http_conn_recv(&conn) == 1; ++k) {
		}
		VBUF_FREE(conn.cbuf);
	}

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(http_conn_init_request),
	T_CASE(http_conn_init_response),
	T_CASE(parsehdr_accept_te_cases),
	T_CASE(parsehdr_transfer_encoding_cases),
	T_CASE(parsehdr_transfer_encoding_rejects_content_length_conflict),
	T_CASE(parsehdr_accept_encoding_cases),
	T_CASE(parsehdr_content_length_cases),
	T_CASE(parsehdr_content_length_rejects_duplicate),
	T_CASE(parsehdr_content_length_rejects_te_chunked_conflict),
	T_CASE(parsehdr_content_encoding_cases),
	T_CASE(parsehdr_expect_cases),
	T_CASE(content_reader_none),
	T_CASE(content_reader_gzip),
	T_CASE(content_writer_roundtrip_none),
	T_CASE(content_writer_roundtrip_deflate),
	T_CASE(content_writer_roundtrip_gzip),
	T_CASE(http_resp_errpage_normal_and_fallback),
	T_CASE(http_conn_recv_request_ok),
	T_CASE(http_conn_recv_response_ok),
	T_CASE(http_conn_recv_response_unsupported_version),
	T_CASE(http_conn_recv_response_malformed_header),
	T_CASE(http_conn_recv_content_length_too_large),
	T_CASE(http_conn_recv_bad_version),
	T_CASE(http_conn_recv_header_line_too_long),
	T_CASE(http_conn_recv_incremental),
	T_CASE(http_conn_recv_content_incomplete_then_complete),
	T_CASE(http_conn_recv_content_clamped_to_content_length),
	T_CASE(http_conn_recv_expect_continue),
	T_CASE(http_conn_recv_content_early_eof),
	T_CASE(http_conn_recv_header_callback_reject),
	T_CASE(http_body_none),
	T_CASE(http_body_content_length),
	T_CASE(http_body_content_length_overflow),
	T_CASE(http_body_content_length_cb_reject),
	T_CASE(http_body_eof),
	T_CASE(http_body_eof_cb_reject),
	T_CASE(http_body_chunked_simple),
	T_CASE(http_body_chunked_split_input),
	T_CASE(http_body_chunked_uppercase_hex),
	T_CASE(http_body_chunked_with_extension),
	T_CASE(http_body_chunked_trailer),
	T_CASE(http_body_chunked_no_hex_digit_fails),
	T_CASE(http_body_chunked_size_line_too_long),
	T_CASE(http_body_chunked_missing_cr_after_data),
	T_CASE(http_body_chunked_extra_data_after_done),
	T_CASE(http_body_chunked_trailing_data_after_terminator),
	T_CASE(http_body_chunked_data_cb_reject),
	T_CASE(http_body_chunked_lowercase_hex),
	T_CASE(http_body_chunked_size_value_overflow),
	T_CASE(http_body_chunked_size_trailing_ws),
	T_CASE(http_body_chunked_size_trailing_junk),
	T_CASE(http_chunk_header_format),
	T_CASE(http_chunk_header_roundtrip),
	T_BENCH(bench_parse_request),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
