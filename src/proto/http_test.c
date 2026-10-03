/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * http_test - white-box unit tests for proto/http.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   proto/http.c     module under test, compiled with http_date redirected
 *                    to test_http_date so a case can fail the clock
 *   proto/codec.c    leaf (transfer codecs)
 * Leaf libraries: csnippets (io/stream).
 * http.c has no stateful collaborator module to mock; the mock section holds
 * that clock seam and a portability shim. Randomized HTTP parsing is fuzzed by
 * main_test (fuzz_http_req, fuzz_http_resp, fuzz_parsehdr).
 */

#include "http.h"

#include "io/stream.h"
#include "meta/arraysize.h"
#include "net/http.h"
#include "os/clock.h"
#include "utils/buffer.h"
#include "utils/testing.h"

#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - the http_date() clock seam and a portability shim.
 * ---------------------------------------------------------------------- */

size_t test_http_date(char *restrict buf, size_t buf_size);

/* when set, the clock has no IMF-fixdate rendering */
static bool g_http_date_fail;

size_t test_http_date(char *restrict buf, const size_t buf_size)
{
	if (g_http_date_fail) {
		return 0;
	}
	return http_date(buf, buf_size);
}

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

/* Per-connection test fixture: the header callback's context plus the byte
 * counters http_conn_init() maintains, so a case can assert on them and the
 * recv helpers can decide completion from the bytes actually delivered. */
struct conn_test_ctx {
	struct http_conn *p;
	bool reject;
	uint_least64_t byt_recv, byt_sent;
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
 * has arrived. These helpers wait on the connection fd so the tests never
 * depend on a write being delivered atomically; they also evaluate
 * http_conn_recv() exactly once, since it has side effects.
 *
 * What ends a wait is always the message itself -- the parser reaching a
 * terminal state, or every byte the peer wrote having been taken in -- never a
 * quiet period. The budget below is a watchdog: reaching it means the expected
 * bytes never arrived, and the helper then returns a value no case accepts.
 */
#define TEST_RECV_BUDGET_NS INT64_C(4000000000)
#define TEST_RECV_TIMEDOUT (-2)

/* Wait for `fd` to become readable, bounded by the watchdog `deadline`
 * (monotonic ns). Returns false once the deadline has passed, or when the
 * monotonic clock is unavailable and the wait cannot be bounded. */
static bool wait_readable(const int fd, const int_fast64_t deadline)
{
	for (;;) {
		const int_fast64_t now = clock_monotonic_ns();
		if (now < 0 || now >= deadline) {
			return false;
		}
		struct pollfd pfd = {
			.fd = fd,
			.events = POLLIN,
		};
		const int ret =
			poll(&pfd, 1, (int)((deadline - now) / 1000000) + 1);
		if (ret > 0) {
			return true;
		}
		if (ret < 0 && errno != EINTR) {
			return false;
		}
	}
}

/* Receive until the parser reaches a terminal state (0 = done, -1 = error).
 * Use when the complete message or EOF has been written and must arrive. */
static int http_recv_until_done(struct http_conn *restrict p)
{
	const int_fast64_t deadline =
		clock_monotonic_ns() + TEST_RECV_BUDGET_NS;
	for (;;) {
		const int ret = http_conn_recv(p);
		if (ret <= 0) {
			return ret;
		}
		if (!wait_readable(p->fd, deadline)) {
			return TEST_RECV_TIMEDOUT;
		}
	}
}

/* Receive until `want` bytes -- exactly what the peer has written so far --
 * have been taken in, then return the parser's last result. Use when only a
 * fragment of a message has been written and the parser is expected to still
 * need more input. Requires a connection set up by conn_init_for_test(), whose
 * byt_recv counter measures the arrival. */
static int http_recv_nbytes(struct http_conn *restrict p, const size_t want)
{
	const int_fast64_t deadline =
		clock_monotonic_ns() + TEST_RECV_BUDGET_NS;
	for (;;) {
		const int ret = http_conn_recv(p);
		if (ret <= 0 || *p->byt_recv >= (uint_least64_t)want) {
			return ret;
		}
		if (!wait_readable(p->fd, deadline)) {
			return TEST_RECV_TIMEDOUT;
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
	struct conn_test_ctx *const c = ctx;
	if (c->reject) {
		return false;
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
	const enum http_conn_state mode, struct conn_test_ctx *restrict cb)
{
	*cb = (struct conn_test_ctx){
		.p = p,
		.reject = false,
	};
	const struct http_parsehdr_cb on_header = {
		.func = parse_header_cb,
		.ctx = cb,
	};
	http_conn_init(p, fd, mode, on_header, &cb->byt_recv, &cb->byt_sent);
}

static bool stream_read_exact(
	struct io_stream *restrict r, unsigned char *restrict buf,
	const size_t want)
{
	size_t got = 0;
	while (got < want) {
		size_t n = want - got;
		if (io_stream_read(r, buf + got, &n) != 0) {
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
	struct io_stream *restrict w, const void *restrict data,
	const size_t len)
{
	size_t n = len;
	if (io_stream_write(w, data, &n) != 0) {
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
	struct conn_test_ctx cb = { 0 };

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
	struct conn_test_ctx cb = { 0 };

	conn_init_for_test(&p, 8, STATE_PARSE_RESPONSE, &cb);
	T_EXPECT_EQ(p.state, STATE_PARSE_RESPONSE);
	T_EXPECT_EQ(p.fd, 8);
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
		/* RFC 9112 §7: transfer-coding names are case-insensitive */
		p.hdr.transfer.encoding = TENCODING_NONE;
		char value[] = "Chunked";
		T_EXPECT(parsehdr_transfer_encoding(&p, value));
		T_EXPECT_EQ(p.hdr.transfer.encoding, TENCODING_CHUNKED);
	}
	{
		char value[] = "deflate";
		T_EXPECT(!parsehdr_transfer_encoding(&p, value));
	}
	{
		/* An empty second Transfer-Encoding line must NOT downgrade an
		 * already-recorded `chunked` framing to NONE: doing so would
		 * leave the chunked body bytes unframed and attributed to
		 * whatever follows (request smuggling). The empty-value branch
		 * is a no-op that leaves the recorded coding intact. */
		p.hdr.transfer.encoding = TENCODING_CHUNKED;
		char value[] = "";
		T_EXPECT(parsehdr_transfer_encoding(&p, value));
		T_EXPECT_EQ(p.hdr.transfer.encoding, TENCODING_CHUNKED);
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
	{
		/* RFC 9110 §12.5.3: q=0 means "not acceptable" -- a client that
		 * explicitly refuses deflate must not be sent it */
		struct http_conn q = { 0 };
		char value[] = "deflate;q=0";
		T_EXPECT(parsehdr_accept_encoding(&q, value));
		T_EXPECT_EQ(q.hdr.accept_encoding, CENCODING_NONE);
	}
	{
		/* the same for the wildcard */
		struct http_conn q = { 0 };
		char value[] = "*;q=0";
		T_EXPECT(parsehdr_accept_encoding(&q, value));
		T_EXPECT_EQ(q.hdr.accept_encoding, CENCODING_NONE);
	}
	{
		/* "0.000" is also zero */
		struct http_conn q = { 0 };
		char value[] = "deflate;q=0.000";
		T_EXPECT(parsehdr_accept_encoding(&q, value));
		T_EXPECT_EQ(q.hdr.accept_encoding, CENCODING_NONE);
	}
	{
		/* a nonzero weight (even tiny) keeps the coding acceptable */
		struct http_conn q = { 0 };
		char value[] = "deflate;q=0.001";
		T_EXPECT(parsehdr_accept_encoding(&q, value));
		T_EXPECT_EQ(q.hdr.accept_encoding, CENCODING_DEFLATE);
	}
	{
		/* a q=0 wildcard still lets a later explicit coding match */
		struct http_conn q = { 0 };
		char value[] = "*;q=0, deflate";
		T_EXPECT(parsehdr_accept_encoding(&q, value));
		T_EXPECT_EQ(q.hdr.accept_encoding, CENCODING_DEFLATE);
	}
	{
		/* RFC 9110 §12.5.3: `*` matches only codings "not explicitly
		 * listed", so an explicit deflate;q=0 must not be re-enabled by
		 * a `*` -- regardless of token order */
		struct http_conn q = { 0 };
		char value[] = "deflate;q=0, *";
		T_EXPECT(parsehdr_accept_encoding(&q, value));
		T_EXPECT_EQ(q.hdr.accept_encoding, CENCODING_NONE);
	}
	{
		/* the symmetric order is wrong the same way: the `*` comes first
		 * but the explicit refusal still wins */
		struct http_conn q = { 0 };
		char value[] = "*, deflate;q=0";
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
	/* one supported coding per message; each scenario uses its own conn now
	 * that a second coding line is rejected as an unsupported stack */
	{
		struct http_conn p = { 0 };
		T_EXPECT(parsehdr_content_encoding(&p, "deflate"));
		T_EXPECT_EQ(p.hdr.content.encoding, CENCODING_DEFLATE);
	}
	{
		/* RFC 9112 §7: coding names are case-insensitive */
		struct http_conn p = { 0 };
		T_EXPECT(parsehdr_content_encoding(&p, "GZIP"));
		T_EXPECT_EQ(p.hdr.content.encoding, CENCODING_GZIP);
	}
	{
		struct http_conn p = { 0 };
		T_EXPECT(!parsehdr_content_encoding(&p, "br"));
		T_EXPECT_EQ(p.http_status, HTTP_UNSUPPORTED_MEDIA_TYPE);
	}
}

/* Regression: RFC 9110 §5.3 combines repeated Content-Encoding lines into one
 * ordered coding list. Only a single supported coding can be decoded, so a
 * second coding line is a stack this decoder cannot apply -- it must be
 * rejected (like the comma-joined multi-coding), not silently overwrite the
 * first coding and leave the outer layer un-decoded. */
T_DECLARE_CASE(parsehdr_content_encoding_rejects_stacked)
{
	struct http_conn p = { 0 };

	T_EXPECT(parsehdr_content_encoding(&p, "gzip"));
	T_EXPECT_EQ(p.hdr.content.encoding, CENCODING_GZIP);

	T_EXPECT(!parsehdr_content_encoding(&p, "deflate"));
	T_EXPECT_EQ(p.http_status, HTTP_UNSUPPORTED_MEDIA_TYPE);
	/* the first coding is left intact, not overwritten by the rejected one */
	T_EXPECT_EQ(p.hdr.content.encoding, CENCODING_GZIP);
}

/* Parse one Transfer-Encoding value on a fresh request-mode connection and
 * check both the verdict and the status left for the error page. */
T_DECLARE_SUBCASE(
	expect_transfer_encoding, const char *restrict value, const bool ok,
	const int status)
{
	struct http_conn p = { 0 };
	p.http_status = HTTP_BAD_REQUEST;
	char buf[64];
	const size_t len = strlen(value);
	T_CHECK(len < sizeof(buf));
	(void)memcpy(buf, value, len + 1);

	T_EXPECT_EQ(parsehdr_transfer_encoding(&p, buf), ok);
	T_EXPECT_EQ(p.http_status, status);
	if (!ok) {
		/* a rejected value records no framing */
		T_EXPECT_EQ(p.hdr.transfer.encoding, TENCODING_NONE);
	}
}

/*
 * Regression: RFC 9112 §6.1 -- a well-framed request (chunked is the final
 * coding) naming a transfer-coding the server does not implement is answered
 * 501, not the parser's default 400. A list whose final coding is not chunked
 * cannot be framed at all (RFC 9112 §6.3) and stays 400, as does chunked
 * applied twice.
 */
T_DECLARE_CASE(parsehdr_transfer_encoding_unimplemented_coding)
{
	T_CALL_SUBCASE(
		expect_transfer_encoding, "gzip, chunked", false,
		HTTP_NOT_IMPLEMENTED);
	T_CALL_SUBCASE(
		expect_transfer_encoding, "x-custom ,Chunked", false,
		HTTP_NOT_IMPLEMENTED);
	T_CALL_SUBCASE(
		expect_transfer_encoding, "gzip", false, HTTP_BAD_REQUEST);
	T_CALL_SUBCASE(
		expect_transfer_encoding, "chunked, gzip", false,
		HTTP_BAD_REQUEST);
	T_CALL_SUBCASE(
		expect_transfer_encoding, "chunked, chunked", false,
		HTTP_BAD_REQUEST);
	T_CALL_SUBCASE(
		expect_transfer_encoding, "gzip, chunked, chunked", false,
		HTTP_BAD_REQUEST);
	/* RFC 9110 §5.6.1: empty list elements are ignored */
	{
		struct http_conn p = { 0 };
		char value[] = " , chunked ,";
		T_EXPECT(parsehdr_transfer_encoding(&p, value));
		T_EXPECT_EQ(p.hdr.transfer.encoding, TENCODING_CHUNKED);
	}
	{
		struct http_conn p = { 0 };
		char value[] = " , ";
		T_EXPECT(parsehdr_transfer_encoding(&p, value));
		T_EXPECT_EQ(p.hdr.transfer.encoding, TENCODING_NONE);
	}

	{
		/* an ambiguous Content-Length framing is a 400 before the
		 * coding is judged */
		struct http_conn p = { 0 };
		p.http_status = HTTP_BAD_REQUEST;
		p.hdr.content.has_length = true;
		char value[] = "gzip, chunked";
		T_EXPECT(!parsehdr_transfer_encoding(&p, value));
		T_EXPECT_EQ(p.http_status, HTTP_BAD_REQUEST);
	}
}

/* Regression: RFC 9112 §6.1 forbids applying chunked more than once, so a
 * repeated Transfer-Encoding: chunked line -- the split-line form of the
 * already-rejected "chunked, chunked" -- must be rejected on the request side
 * too, matching the response parser. */
T_DECLARE_CASE(parsehdr_transfer_encoding_rejects_double_chunked)
{
	struct http_conn p = { 0 };

	char first[] = "chunked";
	T_EXPECT(parsehdr_transfer_encoding(&p, first));
	T_EXPECT_EQ(p.hdr.transfer.encoding, TENCODING_CHUNKED);

	char second[] = "chunked";
	T_EXPECT(!parsehdr_transfer_encoding(&p, second));
}

/* Regression: RFC 9110 §5.3 combines repeated Accept-Encoding lines, so a
 * `deflate;q=0` on any line refuses deflate for the whole request even if a
 * later line's `*` would otherwise select it -- the refusal is sticky across
 * lines, independent of order. */
T_DECLARE_CASE(parsehdr_accept_encoding_refusal_sticks_across_lines)
{
	{
		/* refusal first, then a selecting wildcard on a later line */
		struct http_conn p = { 0 };
		char l1[] = "deflate;q=0";
		char l2[] = "*";
		T_EXPECT(parsehdr_accept_encoding(&p, l1));
		T_EXPECT(parsehdr_accept_encoding(&p, l2));
		T_EXPECT_EQ(p.hdr.accept_encoding, CENCODING_NONE);
	}
	{
		/* the symmetric order: the wildcard selects first, a later refusal
		 * still wins */
		struct http_conn p = { 0 };
		char l1[] = "*";
		char l2[] = "deflate;q=0";
		T_EXPECT(parsehdr_accept_encoding(&p, l1));
		T_EXPECT_EQ(p.hdr.accept_encoding, CENCODING_DEFLATE);
		T_EXPECT(parsehdr_accept_encoding(&p, l2));
		T_EXPECT_EQ(p.hdr.accept_encoding, CENCODING_NONE);
	}
}

/* Regression: RFC 9110 §5.3 combines repeated Connection lines into one ordered
 * token list. A single line is referenced in place; further lines join a
 * combine buffer so an earlier line's tokens (e.g. `close`) stay visible to
 * every consumer instead of being overwritten by a later line. */
T_DECLARE_CASE(parsehdr_connection_combines_repeated_lines)
{
	struct http_conn p = { 0 };

	char l1[] = "close";
	T_EXPECT(parsehdr_connection(&p, l1));
	/* the common single-line case is referenced in place, not copied */
	T_EXPECT(p.hdr.connection == l1);

	char l2[] = "upgrade";
	T_EXPECT(parsehdr_connection(&p, l2));
	/* both tokens are visible in the combined list */
	T_EXPECT(http_connection_lists(p.hdr.connection, "close"));
	T_EXPECT(http_connection_lists(p.hdr.connection, "upgrade"));
}

/* The combined Connection value is bounded: an overflowing run of repeated
 * lines is rejected rather than silently truncated, which would drop
 * hop-by-hop tokens a proxy relies on. */
T_DECLARE_CASE(parsehdr_connection_rejects_overflow)
{
	struct http_conn p = { 0 };

	char tok[] = "keep-alive";
	/* the first line is referenced in place and always succeeds */
	T_EXPECT(parsehdr_connection(&p, tok));

	/* each further line appends "keep-alive" plus a separator, so the store
	 * (HTTP_MAX_CONNECTION bytes) overflows well within this many lines */
	bool overflowed = false;
	for (size_t i = 0; i < HTTP_MAX_CONNECTION; i++) {
		if (!parsehdr_connection(&p, tok)) {
			overflowed = true;
			break;
		}
	}
	T_EXPECT(overflowed);
}

T_DECLARE_CASE(parsehdr_expect_cases)
{
	struct http_conn p = { 0 };
	p.msg.req.version = "HTTP/1.1";

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
	{
		/* RFC 9110 §10.1.1: an HTTP/1.0 request's 100-continue is
		 * accepted but ignored, so no interim response is armed */
		char value[] = "100-continue";
		p.msg.req.version = "HTTP/1.0";
		p.expect_continue = false;
		T_EXPECT(parsehdr_expect(&p, value));
		T_EXPECT(!p.expect_continue);
	}
}

T_DECLARE_CASE(content_reader_none)
{
	static const unsigned char input[] = "hello";
	unsigned char output[sizeof(input)] = { 0 };
	struct io_stream *r =
		content_reader(input, sizeof(input), CENCODING_NONE);

	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, output, sizeof(output)));
	T_EXPECT_MEMEQ(output, input, sizeof(input));
	T_EXPECT_EQ(io_stream_close(r), 0);
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
	struct io_stream *r =
		content_reader(gzip_data, sizeof(gzip_data), CENCODING_GZIP);
	bool ok = false;
	int rc = -1;

	T_CHECK(r != NULL);
	ok = stream_read_exact(r, output, sizeof(output));
	rc = io_stream_close(r);
	T_EXPECT(ok);
	T_EXPECT_MEMEQ(output, expected, sizeof(expected));
	T_EXPECT_EQ(rc, 0);
}

/*
 * Every stream content_reader() can hand back must implement direct_read: the
 * ruleset Lua loader pulls the body through io_stream_direct_read(), which
 * fails outright on a stream without the slot. Pins the invariant the reader
 * asserts, for each encoding it constructs.
 */
T_DECLARE_CASE(content_reader_supports_direct_read)
{
	static const enum content_encodings encodings[] = {
		CENCODING_NONE,
		CENCODING_DEFLATE,
		CENCODING_GZIP,
	};
	static const unsigned char input[] = "hello";
	for (size_t i = 0; i < ARRAY_SIZE(encodings); i++) {
		struct io_stream *r =
			content_reader(input, sizeof(input), encodings[i]);
		T_CHECK(r != NULL);
		T_EXPECT(r->vftable->direct_read != NULL);
		(void)io_stream_close(r);
	}
}

T_DECLARE_CASE(content_reader_vbuf_cases)
{
	/* NULL cbuf is the documented empty-body case (Content-Length: 0 leaves
	 * the content vbuffer unallocated): it must read as "" rather than fault
	 * on the NULL that io_memreader() would otherwise reject. */
	{
		struct io_stream *r = content_reader_vbuf(NULL, CENCODING_NONE);
		T_CHECK(r != NULL);
		unsigned char buf[8];
		size_t n = sizeof(buf);
		T_EXPECT_EQ(io_stream_read(r, buf, &n), 0);
		T_EXPECT_EQ(n, 0); /* immediate EOF: the stream is empty */
		T_EXPECT_EQ(io_stream_close(r), 0);
	}
	/* a populated cbuf reads back its bytes */
	{
		struct vbuffer *cbuf = VBUF_NEW(16);
		T_CHECK(cbuf != NULL);
		VBUF_APPENDSTR(cbuf, "hello");
		struct io_stream *r = content_reader_vbuf(cbuf, CENCODING_NONE);
		T_CHECK(r != NULL);
		unsigned char out[5] = { 0 };
		T_EXPECT(stream_read_exact(r, out, sizeof(out)));
		T_EXPECT_MEMEQ(out, "hello", sizeof(out));
		T_EXPECT_EQ(io_stream_close(r), 0);
		VBUF_FREE(cbuf);
	}
}

T_DECLARE_CASE(content_writer_roundtrip_none)
{
	struct vbuffer *vbuf = NULL;
	static const unsigned char input[] = "roundtrip-none";
	unsigned char output[sizeof(input)] = { 0 };

	struct io_stream *w = content_writer(&vbuf, 64, CENCODING_NONE);
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, input, sizeof(input)));
	T_EXPECT_EQ(io_stream_close(w), 0);
	T_CHECK(vbuf != NULL);
	T_EXPECT(VBUF_LEN(vbuf) >= sizeof(input));

	struct io_stream *r =
		content_reader(VBUF_DATA(vbuf), VBUF_LEN(vbuf), CENCODING_NONE);
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, output, sizeof(output)));
	T_EXPECT_MEMEQ(output, input, sizeof(input));
	T_EXPECT_EQ(io_stream_close(r), 0);

	VBUF_FREE(vbuf);
}

T_DECLARE_CASE(content_writer_roundtrip_deflate)
{
	struct vbuffer *vbuf = NULL;
	static const unsigned char input[] = "roundtrip-deflate";
	unsigned char output[sizeof(input)] = { 0 };

	struct io_stream *w = content_writer(&vbuf, 64, CENCODING_DEFLATE);
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, input, sizeof(input)));
	T_EXPECT_EQ(io_stream_close(w), 0);
	T_CHECK(vbuf != NULL);

	struct io_stream *r = content_reader(
		VBUF_DATA(vbuf), VBUF_LEN(vbuf), CENCODING_DEFLATE);
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, output, sizeof(output)));
	T_EXPECT_MEMEQ(output, input, sizeof(input));
	T_EXPECT_EQ(io_stream_close(r), 0);

	VBUF_FREE(vbuf);
}

/* Regression: content_writer must support gzip symmetrically with
 * content_reader, not abort (FAILMSGF) on CENCODING_GZIP. */
T_DECLARE_CASE(content_writer_roundtrip_gzip)
{
	struct vbuffer *vbuf = NULL;
	static const unsigned char input[] = "roundtrip-gzip";
	unsigned char output[sizeof(input)] = { 0 };

	struct io_stream *w = content_writer(&vbuf, 64, CENCODING_GZIP);
	T_CHECK(w != NULL);
	T_EXPECT(stream_write_all(w, input, sizeof(input)));
	T_EXPECT_EQ(io_stream_close(w), 0);
	T_CHECK(vbuf != NULL);

	struct io_stream *r =
		content_reader(VBUF_DATA(vbuf), VBUF_LEN(vbuf), CENCODING_GZIP);
	T_CHECK(r != NULL);
	T_EXPECT(stream_read_exact(r, output, sizeof(output)));
	T_EXPECT_MEMEQ(output, input, sizeof(input));
	T_EXPECT_EQ(io_stream_close(r), 0);

	VBUF_FREE(vbuf);
}

T_DECLARE_CASE(http_resp_errpage_normal_and_fallback)
{
	struct http_conn p = { 0 };
	struct conn_test_ctx cb = { 0 };

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

T_DECLARE_CASE(http_resp_errpage_fallback_omits_date_without_clock)
{
	struct http_conn p = { 0 };
	struct conn_test_ctx cb = { 0 };

	conn_init_for_test(&p, -1, STATE_PARSE_REQUEST, &cb);

	/* an unknown status code takes the RESPHDR_BEGIN fallback, which
	 * carries a Date line while the clock renders */
	http_resp_errpage(&p, 599);
	T_EXPECT(memmem(p.wbuf.data, p.wbuf.len, "\r\nDate: ", 8) != NULL);
	T_EXPECT(memmem(p.wbuf.data, p.wbuf.len, "Date: \r\n", 8) == NULL);

	/* RFC 9110 §6.6.1: with no usable clock the Date field is omitted
	 * whole, never sent with an empty value */
	g_http_date_fail = true;
	http_resp_errpage(&p, 599);
	g_http_date_fail = false;
	T_EXPECT(memmem(p.wbuf.data, p.wbuf.len, "Date:", 5) == NULL);
	static const char want[] = "HTTP/1.1 599 \r\n"
				   "Connection: close\r\n"
				   "\r\n";
	T_EXPECT_EQ(p.wbuf.len, sizeof(want) - 1);
	T_EXPECT_MEMEQ(p.wbuf.data, want, sizeof(want) - 1);
}

T_DECLARE_CASE(http_conn_host_syntax)
{
	static const struct {
		const char *host;
		bool valid;
	} cases[] = {
		{ "", true },
		{ "example.com", true },
		{ "127.0.0.1:8080", true },
		{ "example.com:", true },
		{ "example.com:999999999999", true },
		{ "ex%61mple.com", true },
		{ "-._~!$&'()*+,;=", true },
		{ "[::1]", true },
		{ "[::ffff:192.0.2.1]:80", true },
		{ "[v1.a:b]:", true },
		{ "[VF.a-._~!$&'()*+,;=]", true },
		{ "user@example.com", false },
		{ "example.com/path", false },
		{ "example.com?query", false },
		{ "example.com#fragment", false },
		{ "bad host", false },
		{ "bad\thost", false },
		{ "bad\x80host", false },
		{ "%", false },
		{ "%1", false },
		{ "%gg", false },
		{ "host:-1", false },
		{ "host:1x", false },
		{ "::1", false },
		{ "[::1", false },
		{ "[]", false },
		{ "[broken]", false },
		{ "[1:2:3:4:5:6:7:8:9:0:1:2:3:4:5:6:7:8:9:0:1:2]", false },
		{ "[::1]suffix", false },
		{ "[v.a]", false },
		{ "[v1]", false },
		{ "[v1.]", false },
		{ "[v1.a%20]", false },
	};
	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		struct http_conn p = { 0 };
		struct conn_test_ctx cb = { 0 };
		conn_init_for_test(&p, -1, STATE_PARSE_REQUEST, &cb);
		BUF_APPENDF(
			p.rbuf, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n",
			cases[i].host);
		T_EXPECT_EQ(http_conn_parse(&p), 0);
		T_EXPECT_EQ(
			p.state,
			cases[i].valid ? STATE_PARSE_OK : STATE_PARSE_ERROR);
		T_EXPECT_EQ(p.http_status, HTTP_BAD_REQUEST);
	}
}

T_DECLARE_CASE(http_conn_recv_request_ok)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct conn_test_ctx cb = { 0 };
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

/*
 * Characterizes the http_conn_recv() body-framing contract: a chunked message
 * parses OK but is NOT framed -- cbuf stays NULL and the body is left unframed
 * in rbuf. A caller that reads cbuf must reject chunked itself or it silently
 * sees an empty body; api_server answers 501 Not Implemented for a chunked
 * request (it reserves 411 Length Required for a body endpoint that omits
 * Content-Length). Pinned here so the invariant the other callers depend on is
 * visible rather than incidental.
 */
T_DECLARE_CASE(http_conn_recv_chunked_body_is_not_framed)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct conn_test_ctx cb = { 0 };
	static const char req[] = "POST /hello HTTP/1.1\r\n"
				  "Host: test\r\n"
				  "Transfer-Encoding: chunked\r\n"
				  "\r\n"
				  "5\r\nhello\r\n0\r\n\r\n";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req, sizeof(req) - 1));
	const int ret = http_recv_until_done(&p);
	T_EXPECT_EQ(ret, 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);
	T_EXPECT_EQ(p.hdr.transfer.encoding, TENCODING_CHUNKED);
	/* the headers parsed, but the body was not framed */
	T_EXPECT(p.cbuf == NULL);
	T_EXPECT(!p.hdr.content.has_length);

	VBUF_FREE(p.cbuf);
	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

/* A second, empty Transfer-Encoding line must not downgrade the chunked framing
 * recorded by the first line -- driven through the real recv path (the parser
 * http_proxy uses per request). Without the fix the empty value resets the
 * coding to NONE and the chunked body desyncs into the next message. */
T_DECLARE_CASE(http_conn_recv_empty_te_does_not_downgrade_chunked)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct conn_test_ctx cb = { 0 };
	static const char req[] = "POST /hello HTTP/1.1\r\n"
				  "Host: test\r\n"
				  "Transfer-Encoding: chunked\r\n"
				  "Transfer-Encoding:\r\n"
				  "\r\n"
				  "5\r\nhello\r\n0\r\n\r\n";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req, sizeof(req) - 1));
	const int ret = http_recv_until_done(&p);
	T_EXPECT_EQ(ret, 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);
	/* the chunked coding survives the empty second line */
	T_EXPECT_EQ(p.hdr.transfer.encoding, TENCODING_CHUNKED);
	T_EXPECT(p.cbuf == NULL);
	T_EXPECT(!p.hdr.content.has_length);

	VBUF_FREE(p.cbuf);
	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_conn_recv_response_ok)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct conn_test_ctx cb = { 0 };
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
	struct conn_test_ctx cb = { 0 };
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
	struct conn_test_ctx cb = { 0 };
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
	struct conn_test_ctx cb = { 0 };
	/* HTTP_MAX_CONTENT is 4194304 */
	static const char req[] = "POST / HTTP/1.1\r\nHost: test\r\n"
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

/* Feed `msg` to a fresh connection in `mode` and check its HTTP-version is
 * rejected: a request fails with STATE_PARSE_ERROR (400 page, return 0), a
 * response with -1. */
T_DECLARE_SUBCASE(
	expect_bad_version, const enum http_conn_state mode,
	const char *restrict msg)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct conn_test_ctx cb = { 0 };

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], mode, &cb);

	T_CHECK(write_all(sv[1], msg, strlen(msg)));
	const int ret = http_recv_until_done(&p);
	if (mode == STATE_PARSE_REQUEST) {
		T_EXPECT_EQ(ret, 0);
		T_EXPECT_EQ(p.state, STATE_PARSE_ERROR);
		T_EXPECT_EQ(p.http_status, HTTP_BAD_REQUEST);
	} else {
		T_EXPECT_EQ(ret, -1);
	}

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

/*
 * RFC 9112 §2.3: HTTP-version = HTTP-name "/" DIGIT "." DIGIT, exactly. A
 * version merely starting with "HTTP/1." -- no minor digit, trailing bytes, or
 * a third field swallowing the rest of the request-line -- is not HTTP/1.x.
 */
T_DECLARE_CASE(http_conn_recv_bad_version)
{
	static const char *const bad_req[] = {
		"GET / HTTP/2.0\r\n\r\n",
		"CONNECT example.com:443 HTTP/1.\r\n\r\n",
		"CONNECT example.com:443 HTTP/1.1x\r\n\r\n",
		"CONNECT example.com:443 HTTP/1.10\r\n\r\n",
		"CONNECT example.com:443 HTTP/1.1 trailing junk\r\n\r\n",
		"GET / HTTP/1.a\r\n\r\n",
		"GET / http/1.1\r\n\r\n",
		"GET / \r\n\r\n",
	};
	for (size_t i = 0; i < ARRAY_SIZE(bad_req); i++) {
		T_CALL_SUBCASE(
			expect_bad_version, STATE_PARSE_REQUEST, bad_req[i]);
	}
	static const char *const bad_rsp[] = {
		"HTTP/1. 200 OK\r\n\r\n",
		"HTTP/1.1x 200 OK\r\n\r\n",
	};
	for (size_t i = 0; i < ARRAY_SIZE(bad_rsp); i++) {
		T_CALL_SUBCASE(
			expect_bad_version, STATE_PARSE_RESPONSE, bad_rsp[i]);
	}
}

/* An over-long request-line is an over-long request-target: RFC 9112 §3
 * requires 414, not the 413 reserved for request content. */
T_DECLARE_CASE(http_conn_recv_request_line_too_long)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct conn_test_ctx cb = { 0 };
	static const char reqline[] = "GET /";
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
	T_EXPECT_EQ(p.http_status, HTTP_URI_TOO_LONG);

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

/*
 * Regression: a header value that never contains \r\n must fail cleanly
 * with 431 Request Header Fields Too Large (RFC 6585 §5), matching
 * parse_message()'s existing guard for an unterminated request line. Pre-fix, parse_header() had no such guard: rbuf fills
 * up, the next recv_request() computes a zero-length read, and that gets
 * misread as early EOF -- tearing down the connection with no response.
 */
T_DECLARE_CASE(http_conn_recv_header_line_too_long)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct conn_test_ctx cb = { 0 };
	static const char reqline[] =
		"GET / HTTP/1.1\r\nHost: test\r\nX-Long: ";
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
	T_EXPECT_EQ(p.http_status, HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_conn_recv_incremental)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct conn_test_ctx cb = { 0 };
	static const char req1[] = "GET / HTTP/1.1\r\n"
				   "Host: a\r\n";
	static const char req2[] = "\r\n";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req1, sizeof(req1) - 1));
	const int ret1 = http_recv_nbytes(&p, sizeof(req1) - 1);
	T_EXPECT_EQ(ret1, 1);
	T_EXPECT_EQ(p.state, STATE_PARSE_HEADER);
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
	struct conn_test_ctx cb = { 0 };
	static const char req1[] = "POST /x HTTP/1.1\r\nHost: test\r\n"
				   "Content-Length: 5\r\n"
				   "\r\n"
				   "he";
	static const char req2[] = "llo";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req1, sizeof(req1) - 1));
	const int ret1 = http_recv_nbytes(&p, sizeof(req1) - 1);
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

T_DECLARE_CASE(http_conn_recv_content_later_read_keeps_nul_terminator)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct conn_test_ctx cb = { 0 };
	static const char req1[] = "POST /x HTTP/1.1\r\nHost: test\r\n"
				   "Content-Length: 5\r\n"
				   "\r\n"
				   "he";
	static const char req2[] = "llo";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req1, sizeof(req1) - 1));
	T_EXPECT_EQ(http_recv_nbytes(&p, sizeof(req1) - 1), 1);
	T_CHECK(p.cbuf != NULL);
	T_CHECK(VBUF_LEN(p.cbuf) == 2);
	/* poison the spare room, so a terminator can only come from the
	 * bytes read directly into it */
	memset(p.cbuf->data + p.cbuf->len, 'X', p.cbuf->cap + 1 - p.cbuf->len);

	T_CHECK(write_all(sv[1], req2, sizeof(req2) - 1));
	T_EXPECT_EQ(http_recv_until_done(&p), 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);
	T_EXPECT_EQ(VBUF_LEN(p.cbuf), 5);
	T_EXPECT_EQ(p.cbuf->data[p.cbuf->len], '\0');
	T_EXPECT_STREQ((const char *)VBUF_DATA(p.cbuf), "hello");

	VBUF_FREE(p.cbuf);
	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_conn_recv_content_clamped_to_content_length)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct conn_test_ctx cb = { 0 };
	/* Content-Length: 5 declared, but 8 body bytes arrive in the same
	 * write as the headers; the extra 3 bytes must not be copied into
	 * the content buffer (they belong to a later message, if anything). */
	static const char req[] = "POST /x HTTP/1.1\r\nHost: test\r\n"
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
	struct conn_test_ctx cb = { 0 };
	static const char req1[] = "POST /x HTTP/1.1\r\nHost: test\r\n"
				   "Expect: 100-continue\r\n"
				   "Content-Length: 5\r\n"
				   "\r\n";
	static const char req2[] = "hello";
	/* the interim response reply_short() writes straight to the socket */
	static const char rsp_expect[] = "HTTP/1.1 100 Continue\r\n\r\n";
	const size_t rsp_want = sizeof(rsp_expect) - 1;

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req1, sizeof(req1) - 1));
	const int ret1 = http_recv_nbytes(&p, sizeof(req1) - 1);
	T_EXPECT_EQ(ret1, 1);
	T_EXPECT(p.expect_continue);

	/* read the interim response, tolerating fragmented delivery */
	size_t rsplen = 0;
	const int_fast64_t deadline =
		clock_monotonic_ns() + TEST_RECV_BUDGET_NS;
	while (rsplen < rsp_want && wait_readable(sv[1], deadline)) {
		const ssize_t n =
			recv_nowait(sv[1], rsp + rsplen, sizeof(rsp) - rsplen);
		if (n < 0) {
			const int err = errno;
			T_CHECK(err == EAGAIN || err == EWOULDBLOCK);
			continue;
		}
		if (n == 0) {
			break;
		}
		rsplen += (size_t)n;
	}
	T_EXPECT_EQ(rsplen, rsp_want);
	T_EXPECT_MEMEQ(rsp, rsp_expect, rsp_want);
	/* the interim response is accounted like every other write */
	T_EXPECT_EQ((uintmax_t)cb.byt_sent, (uintmax_t)rsp_want);

	T_CHECK(write_all(sv[1], req2, sizeof(req2) - 1));
	const int ret2 = http_recv_until_done(&p);
	T_EXPECT_EQ(ret2, 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);
	T_EXPECT_EQ(
		(uintmax_t)cb.byt_recv,
		(uintmax_t)((sizeof(req1) - 1) + (sizeof(req2) - 1)));

	VBUF_FREE(p.cbuf);
	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

/* Regression: RFC 9110 §10.1.1 and §15.2 -- an HTTP/1.0 request's
 * 100-continue is ignored, so no interim response reaches the peer. */
T_DECLARE_CASE(http_conn_recv_expect_continue_http10)
{
	int sv[2] = { -1, -1 };
	unsigned char rsp[128];
	struct http_conn p = { 0 };
	struct conn_test_ctx cb = { 0 };
	static const char req1[] = "POST /x HTTP/1.0\r\n"
				   "Expect: 100-continue\r\n"
				   "Content-Length: 5\r\n"
				   "\r\n";
	static const char req2[] = "hello";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req1, sizeof(req1) - 1));
	const int ret1 = http_recv_nbytes(&p, sizeof(req1) - 1);
	T_EXPECT_EQ(ret1, 1);
	T_EXPECT_EQ(p.state, STATE_PARSE_CONTENT);
	T_EXPECT(!p.expect_continue);
	/* the interim reply is written synchronously when the body starts, so
	 * nothing pending now means nothing was sent */
	T_EXPECT_EQ((uintmax_t)cb.byt_sent, 0);
	const ssize_t n = recv_nowait(sv[1], rsp, sizeof(rsp));
	const int err = errno;
	T_EXPECT_EQ(n, -1);
	T_EXPECT(err == EAGAIN || err == EWOULDBLOCK);

	T_CHECK(write_all(sv[1], req2, sizeof(req2) - 1));
	const int ret2 = http_recv_until_done(&p);
	T_EXPECT_EQ(ret2, 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_OK);
	T_CHECK(p.cbuf != NULL);
	T_EXPECT_MEMEQ(VBUF_DATA(p.cbuf), "hello", 5);

	VBUF_FREE(p.cbuf);
	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_conn_recv_content_early_eof)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct conn_test_ctx cb = { 0 };
	static const char req[] = "POST /x HTTP/1.1\r\nHost: test\r\n"
				  "Content-Length: 5\r\n"
				  "\r\n"
				  "he";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);

	T_CHECK(write_all(sv[1], req, sizeof(req) - 1));
	/* take in the partial body (parser still needs more) in a
	 * fragmentation-safe way, then signal EOF and recv to the terminal
	 * error -- a single recv per phase can race delayed fragments */
	T_EXPECT_EQ(http_recv_nbytes(&p, sizeof(req) - 1), 1);
	T_CHECK(shutdown(sv[1], SHUT_WR) == 0);
	T_EXPECT_EQ(http_recv_until_done(&p), -1);

	VBUF_FREE(p.cbuf);
	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_conn_recv_header_callback_reject)
{
	int sv[2] = { -1, -1 };
	struct http_conn p = { 0 };
	struct conn_test_ctx cb = { 0 };
	static const char req[] = "GET /x HTTP/1.1\r\n"
				  "Host: reject\r\n"
				  "\r\n";

	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));
	conn_init_for_test(&p, sv[0], STATE_PARSE_REQUEST, &cb);
	cb.reject = true;

	T_CHECK(write_all(sv[1], req, sizeof(req) - 1));
	/* recv to the terminal result: a single recv can see only the request
	 * line before the header callback that rejects has run */
	T_EXPECT_EQ(http_recv_until_done(&p), 0);
	T_EXPECT_EQ(p.state, STATE_PARSE_ERROR);

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

T_DECLARE_CASE(http_connection_lists_cases)
{
	/* NULL value lists nothing */
	T_EXPECT(!http_connection_lists(NULL, "close"));
	/* single token, case-insensitive */
	T_EXPECT(http_connection_lists("close", "close"));
	T_EXPECT(http_connection_lists("Close", "close"));
	/* token in a comma+OWS separated list */
	T_EXPECT(http_connection_lists("keep-alive, Upgrade", "upgrade"));
	T_EXPECT(http_connection_lists("TE, Trailers", "te"));
	/* absent token */
	T_EXPECT(!http_connection_lists("keep-alive", "close"));
	/* a prefix must not match a longer token */
	T_EXPECT(!http_connection_lists("keep-alive", "keep"));
	T_EXPECT(!http_connection_lists("close", "clos"));
}

static void restore_c_ctype(void *data)
{
	(void)data;
	(void)setlocale(LC_CTYPE, "C");
}

/* Selects a Turkish LC_CTYPE when one is installed: its tolower() maps 'I'
 * to a dotless i, so a locale-aware case fold stops pairing 'I' with 'i'.
 * Without one, the environment's LC_CTYPE is used, as init() would. */
static void use_turkish_ctype(struct testing_ctx *_t_)
{
	static const char *const names[] = {
		"tr_TR.ISO-8859-9", "tr_TR.UTF-8", "tr_TR.utf8", "tr_TR", "",
	};
	T_CLEANUP(restore_c_ctype, NULL);
	for (size_t i = 0; i < ARRAY_SIZE(names); i++) {
		const char *const loc = setlocale(LC_CTYPE, names[i]);
		if (loc != NULL) {
			T_LOGF("LC_CTYPE=%s", loc);
			return;
		}
	}
}

T_DECLARE_CASE(http_tokens_match_case_insensitively_under_any_locale)
{
	use_turkish_ctype(_t_);

	/* a field name spelled with an upper-case I still dispatches */
	{
		struct http_conn p = { 0 };
		char value[] = "chunked";
		T_EXPECT_EQ(
			parsehdr_representation(&p, "TRANSFER-ENCODING", value),
			PARSEHDR_OK);
		T_EXPECT_EQ(p.hdr.transfer.encoding, TENCODING_CHUNKED);
	}
	{
		struct http_conn p = { 0 };
		char value[] = "GZIP";
		T_EXPECT_EQ(
			parsehdr_representation(&p, "CONTENT-ENCODING", value),
			PARSEHDR_OK);
		T_EXPECT_EQ(p.hdr.content.encoding, CENCODING_GZIP);
	}
	{
		struct http_conn p = { 0 };
		p.msg.req.version = "HTTP/1.1";
		char value[] = "100-CONTINUE";
		T_EXPECT(parsehdr_expect(&p, value));
		T_EXPECT(p.expect_continue);
	}
	T_EXPECT(http_connection_lists("close, KEEP-ALIVE", "keep-alive"));
	T_EXPECT(http_connection_lists("Keep-Alive", "KEEP-ALIVE"));
}

T_DECLARE_CASE(http_token_equal_folds_ascii_only)
{
	use_turkish_ctype(_t_);

	T_EXPECT(
		http_token_equal("Proxy-Authorization", "PROXY-AUTHORIZATION"));
	T_EXPECT(http_token_equal("BASIC", "Basic"));
	T_EXPECT(http_token_equal("", ""));
	T_EXPECT(!http_token_equal("Basic", "Basi"));
	T_EXPECT(!http_token_equal("Basi", "Basic"));
	T_EXPECT(!http_token_equal("TE", "TF"));
	/* bytes outside ASCII fold to nothing, whatever the locale pairs */
	T_EXPECT(!http_token_equal("\xc9", "\xe9"));
	T_EXPECT(!http_token_equal("\xfd", "I"));
	T_EXPECT(!http_token_equal("\xdd", "i"));
	T_EXPECT(http_token_equal("\xc9", "\xc9"));
}

T_DECLARE_CASE(http_parse_content_length_accepts)
{
	size_t out = 12345;
	/* a bare decimal length is accepted */
	T_EXPECT(http_parse_content_length("0", &out));
	T_EXPECT_EQ(out, (size_t)0);
	T_EXPECT(http_parse_content_length("42", &out));
	T_EXPECT_EQ(out, (size_t)42);
	/* SIZE_MAX itself fits exactly (boundary is inclusive) */
	char max[32];
	(void)snprintf(max, sizeof(max), "%zu", (size_t)SIZE_MAX);
	T_EXPECT(http_parse_content_length(max, &out));
	T_EXPECT_EQ(out, (size_t)SIZE_MAX);
}

T_DECLARE_CASE(http_parse_content_length_rejects)
{
	size_t out = 777;
	/* empty, signed, or garbage-suffixed values are rejected; the helper does
	 * not strip OWS (its callers rely on http_parsehdr having done so) */
	T_EXPECT(!http_parse_content_length("", &out));
	T_EXPECT(!http_parse_content_length("-1", &out));
	T_EXPECT(!http_parse_content_length("+1", &out));
	T_EXPECT(!http_parse_content_length("12x", &out));
	T_EXPECT(!http_parse_content_length("12 ", &out));
	/* a value overflowing uintmax_t is rejected (ERANGE), not clamped to
	 * SIZE_MAX: on an LP64 target 2^64 would otherwise wrap past the
	 * `> SIZE_MAX` guard and be silently accepted */
	T_EXPECT(!http_parse_content_length("18446744073709551616", &out));
	T_EXPECT(!http_parse_content_length(
		"999999999999999999999999999999", &out));
	/* on a rejected value *out is left untouched */
	T_EXPECT_EQ(out, (size_t)777);
}

#if WITH_RULESET
/*
 * check_rpcall_mime() is the content-type admission gate for POST
 * /ruleset/rpcall (api_server) and for the rpcall response (api_client): the
 * media type must be the RPC type and carry the supported version parameter.
 * It parses in place, so every input here is a writable array.
 */
T_DECLARE_CASE(check_rpcall_mime_cases)
{
	/* what the client actually sends */
	{
		char s[] = MIME_RPCALL;
		T_EXPECT(check_rpcall_mime(s));
	}
	/* RFC 9110 §8.3.1: type and subtype are case-insensitive, and §5.6.6:
	 * so are parameter names */
	{
		char s[] = "Application/X-NeoSocksd-RPC; Version=1";
		T_EXPECT(check_rpcall_mime(s));
	}
	/* RFC 9110 §5.6.6: a token value may equally be sent quoted */
	{
		char s[] = "application/x-neosocksd-rpc; version=\"1\"";
		T_EXPECT(check_rpcall_mime(s));
	}
	/* an unrelated parameter on either side does not hide the version */
	{
		char s[] = "application/x-neosocksd-rpc; charset=utf-8;"
			   " version=1";
		T_EXPECT(check_rpcall_mime(s));
	}
	{
		char s[] = "application/x-neosocksd-rpc; version=1;"
			   " charset=utf-8";
		T_EXPECT(check_rpcall_mime(s));
	}
	/* RFC 9110 §5.6.6: the parameter list may end on a bare ';' */
	{
		char s[] = "application/x-neosocksd-rpc; version=1;";
		T_EXPECT(check_rpcall_mime(s));
	}
	/* a request without Content-Type reaches the gate as NULL */
	T_EXPECT(!check_rpcall_mime(NULL));
	/* type mismatch */
	{
		char s[] = "text/plain";
		T_EXPECT(!check_rpcall_mime(s));
	}
	/* subtype mismatch under the right type */
	{
		char s[] = "application/json";
		T_EXPECT(!check_rpcall_mime(s));
	}
	/* not a media type at all */
	{
		char s[] = "application";
		T_EXPECT(!check_rpcall_mime(s));
	}
	/* the version parameter is mandatory... */
	{
		char s[] = MIME_RPCALL_TYPE "/" MIME_RPCALL_SUBTYPE;
		T_EXPECT(!check_rpcall_mime(s));
	}
	/* ...and only the supported version is accepted */
	{
		char s[] = "application/x-neosocksd-rpc; version=2";
		T_EXPECT(!check_rpcall_mime(s));
	}
	{
		char s[] = "application/x-neosocksd-rpc; version=";
		T_EXPECT(!check_rpcall_mime(s));
	}
	/* a malformed parameter list is rejected, not scanned past */
	{
		char s[] = "application/x-neosocksd-rpc; version";
		T_EXPECT(!check_rpcall_mime(s));
	}
	{
		char s[] = "application/x-neosocksd-rpc; =1";
		T_EXPECT(!check_rpcall_mime(s));
	}
	/* RFC 2231 parameter continuations are not supported */
	{
		char s[] = "application/x-neosocksd-rpc; version*=utf-8''1";
		T_EXPECT(!check_rpcall_mime(s));
	}
}
#endif /* WITH_RULESET */

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
		struct conn_test_ctx cb = { 0 };
		conn_init_for_test(&conn, sv[0], STATE_PARSE_REQUEST, &cb);
		T_CHECK(http_recv_until_done(&conn) == 0);
		T_CHECK(conn.state == STATE_PARSE_OK);
		VBUF_FREE(conn.cbuf);
	}

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

/*
 * Drive the shipped representation-header dispatcher directly (api_server.c /
 * api_client.c use it), rather than a hand-reimplemented copy of the same key
 * dispatch: a drift/typo in a literal header name or a wrong PARSEHDR_* mapping
 * must be caught here.
 */
T_DECLARE_CASE(parsehdr_representation_dispatches_by_key)
{
	/* Content-Type: recorded verbatim -> OK */
	{
		struct http_conn p = { 0 };
		char value[] = "text/plain";
		T_EXPECT_EQ(
			parsehdr_representation(&p, "Content-Type", value),
			PARSEHDR_OK);
		T_EXPECT(p.hdr.content.type == value);
	}
	/* the key match is case-insensitive */
	{
		struct http_conn p = { 0 };
		char value[] = "text/html";
		T_EXPECT_EQ(
			parsehdr_representation(&p, "content-TYPE", value),
			PARSEHDR_OK);
		T_EXPECT(p.hdr.content.type == value);
	}
	/* Content-Length: valid -> OK; invalid -> handled but ERROR.
	 * Response mode skips the request-only CONNECT check that would read the
	 * (unset) request method. */
	{
		struct http_conn p = { 0 };
		p.mode = STATE_PARSE_RESPONSE;
		char value[] = "42";
		T_EXPECT_EQ(
			parsehdr_representation(&p, "Content-Length", value),
			PARSEHDR_OK);
	}
	{
		struct http_conn p = { 0 };
		p.mode = STATE_PARSE_RESPONSE;
		char value[] = "not-a-number";
		T_EXPECT_EQ(
			parsehdr_representation(&p, "Content-Length", value),
			PARSEHDR_ERROR);
	}
	/* Transfer-Encoding: chunked -> OK */
	{
		struct http_conn p = { 0 };
		char value[] = "chunked";
		T_EXPECT_EQ(
			parsehdr_representation(&p, "Transfer-Encoding", value),
			PARSEHDR_OK);
	}
	/* Content-Encoding: a known coding -> OK */
	{
		struct http_conn p = { 0 };
		char value[] = "gzip";
		T_EXPECT_EQ(
			parsehdr_representation(&p, "Content-Encoding", value),
			PARSEHDR_OK);
	}
	/* an unhandled key -> UNHANDLED (the caller then tries its own headers) */
	{
		struct http_conn p = { 0 };
		char value[] = "keep-alive";
		T_EXPECT_EQ(
			parsehdr_representation(&p, "Connection", value),
			PARSEHDR_UNHANDLED);
	}
}

/*
 * http_conn_send() (used by api_server.c, http_proxy.c, http_client.c) drains
 * wbuf then cbuf to the socket, returns 1 on backpressure/partial send, 0 on
 * completion, advances wpos/cpos, accumulates *byt_sent, and frees cbuf when
 * done. Stage a body larger than the socket send buffer to force a real
 * partial send, then drain and re-send to completion.
 */
T_DECLARE_CASE(http_conn_send_drains_wbuf_then_cbuf_with_backpressure)
{
	int sv[2] = { -1, -1 };
	make_socketpair(sv);
	T_CHECK(fd_set_nonblock(sv[0]));

	struct http_conn p = { 0 };
	uint_least64_t byt_sent = 0;
	const struct http_parsehdr_cb no_hdr = { 0 };
	http_conn_init(
		&p, sv[0], STATE_PARSE_RESPONSE, no_hdr, NULL, &byt_sent);

	static const char header[] = "HTTP/1.1 200 OK\r\n\r\n";
	BUF_APPEND(p.wbuf, header, sizeof(header) - 1);

	/* larger than any socket send buffer, so the first send is partial */
	const size_t body_len = (size_t)2 * 1024 * 1024;
	static unsigned char wire[sizeof(header) - 1 + (size_t)2 * 1024 * 1024];
	memcpy(wire, header, sizeof(header) - 1);
	unsigned char *const body = wire + sizeof(header) - 1;
	for (size_t i = 0; i < body_len; i++) {
		body[i] = (unsigned char)(i ^ (i >> 8) ^ (i >> 16));
	}
	p.cbuf = VBUF_NEW(body_len);
	T_CHECK(p.cbuf != NULL);
	VBUF_APPEND(p.cbuf, body, body_len);

	/* first send: wbuf drains fully, cbuf partially, then backpressure (1) */
	int err = -1;
	T_EXPECT_EQ(http_conn_send(&p, sv[0], &err), 1);
	T_EXPECT_EQ(err, 0);
	T_EXPECT_EQ(p.wpos, sizeof(header) - 1);
	T_CHECK(p.cpos > 0 && p.cpos < body_len);
	T_EXPECT_EQ((uintmax_t)byt_sent, (uintmax_t)(p.wpos + p.cpos));

	/* drain the receiver and re-send until the whole body is out. Each
	 * drained round frees at least the socket buffer (>= 1 KiB on any real
	 * system) of room, so the round count is bounded by the body size. */
	static unsigned char drain[64 * 1024];
	size_t total_recv = 0;
	const int max_rounds = (int)(body_len / 1024) + 16;
	int rounds = 0;
	int r = 1;
	while (r != 0) {
		T_CHECK(rounds++ < max_rounds);
		for (;;) {
			const ssize_t n =
				recv(sv[1], drain, sizeof(drain), MSG_DONTWAIT);
			if (n <= 0) {
				break;
			}
			T_CHECK((size_t)n <= sizeof(wire) - total_recv);
			T_EXPECT_MEMEQ(drain, wire + total_recv, (size_t)n);
			total_recv += (size_t)n;
		}
		r = http_conn_send(&p, sv[0], &err);
		T_EXPECT_EQ(err, 0);
	}
	/* drain what the final send left in the socket */
	for (;;) {
		const ssize_t n =
			recv(sv[1], drain, sizeof(drain), MSG_DONTWAIT);
		if (n <= 0) {
			break;
		}
		T_CHECK((size_t)n <= sizeof(wire) - total_recv);
		T_EXPECT_MEMEQ(drain, wire + total_recv, (size_t)n);
		total_recv += (size_t)n;
	}

	T_EXPECT_EQ(p.wpos, sizeof(header) - 1);
	T_EXPECT_EQ((uintmax_t)p.cpos, (uintmax_t)body_len);
	T_EXPECT(p.cbuf == NULL); /* cbuf freed on completion */
	T_EXPECT_EQ(
		(uintmax_t)byt_sent,
		(uintmax_t)((sizeof(header) - 1) + body_len));
	T_EXPECT_EQ((uintmax_t)total_recv, (uintmax_t)byt_sent);

	T_CHECK(close(sv[0]) == 0);
	T_CHECK(close(sv[1]) == 0);
}

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(http_conn_init_request),
	T_CASE(http_conn_init_response),
	T_CASE(parsehdr_transfer_encoding_cases),
	T_CASE(parsehdr_transfer_encoding_rejects_content_length_conflict),
	T_CASE(parsehdr_transfer_encoding_rejects_double_chunked),
	T_CASE(parsehdr_transfer_encoding_unimplemented_coding),
	T_CASE(parsehdr_accept_encoding_cases),
	T_CASE(parsehdr_accept_encoding_refusal_sticks_across_lines),
	T_CASE(parsehdr_content_length_cases),
	T_CASE(parsehdr_representation_dispatches_by_key),
	T_CASE(http_conn_send_drains_wbuf_then_cbuf_with_backpressure),
	T_CASE(parsehdr_content_length_rejects_duplicate),
	T_CASE(parsehdr_content_length_rejects_te_chunked_conflict),
	T_CASE(parsehdr_content_encoding_cases),
	T_CASE(parsehdr_content_encoding_rejects_stacked),
	T_CASE(parsehdr_connection_combines_repeated_lines),
	T_CASE(parsehdr_connection_rejects_overflow),
	T_CASE(parsehdr_expect_cases),
	T_CASE(content_reader_none),
	T_CASE(content_reader_gzip),
	T_CASE(content_reader_supports_direct_read),
	T_CASE(content_reader_vbuf_cases),
	T_CASE(content_writer_roundtrip_none),
	T_CASE(content_writer_roundtrip_deflate),
	T_CASE(content_writer_roundtrip_gzip),
	T_CASE(http_resp_errpage_normal_and_fallback),
	T_CASE(http_resp_errpage_fallback_omits_date_without_clock),
	T_CASE(http_conn_host_syntax),
	T_CASE(http_conn_recv_request_ok),
	T_CASE(http_conn_recv_chunked_body_is_not_framed),
	T_CASE(http_conn_recv_empty_te_does_not_downgrade_chunked),
	T_CASE(http_conn_recv_response_ok),
	T_CASE(http_conn_recv_response_unsupported_version),
	T_CASE(http_conn_recv_response_malformed_header),
	T_CASE(http_conn_recv_content_length_too_large),
	T_CASE(http_conn_recv_bad_version),
	T_CASE(http_conn_recv_request_line_too_long),
	T_CASE(http_conn_recv_header_line_too_long),
	T_CASE(http_conn_recv_incremental),
	T_CASE(http_conn_recv_content_incomplete_then_complete),
	T_CASE(http_conn_recv_content_later_read_keeps_nul_terminator),
	T_CASE(http_conn_recv_content_clamped_to_content_length),
	T_CASE(http_conn_recv_expect_continue),
	T_CASE(http_conn_recv_expect_continue_http10),
	T_CASE(http_conn_recv_content_early_eof),
	T_CASE(http_conn_recv_header_callback_reject),
	T_CASE(http_connection_lists_cases),
	T_CASE(http_tokens_match_case_insensitively_under_any_locale),
	T_CASE(http_token_equal_folds_ascii_only),
	T_CASE(http_parse_content_length_accepts),
	T_CASE(http_parse_content_length_rejects),
#if WITH_RULESET
	T_CASE(check_rpcall_mime_cases),
#endif
	T_BENCH(bench_parse_request),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
