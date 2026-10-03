/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for api_client.c; mocked: dialer. */

#include "api_client.h"

#include "conf.h"
#include "dialer.h"
#include "proto/http.h"
#include "server.h"

#include "io/stream.h"
#include "utils/buffer.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>
#include <malloc.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#if WITH_RULESET

/* -------------------------------------------------------------------------
 * mock - dialer (network boundary) stub and shared fixtures.
 * ---------------------------------------------------------------------- */

/* conf.timeout ceiling; tests that exercise the timeout (e.g. rpcall_timeout)
 * set a small value; generous default covers MSYS2/Cygwin emulation delays. */
static struct config test_conf = {
	.timeout = 1.0,
};

/* the collaborators most cases run against: no resolver, no stats */
static const struct api_client_opts test_opts = {
	.conf = &test_conf,
};

static const ev_tstamp TEST_WAIT_SHORT_SEC = 0.064;
static const ev_tstamp TEST_WAIT_RESPONSE_SEC = 1.0;
static const ev_tstamp TEST_WAIT_LONG_SEC = 2.0;
/* Short tick so ev_run() wakes promptly when mock servers write in fragments
 * (needed for MSYS2/Cygwin socket emulation). */
static const ev_tstamp TEST_TICK_SEC = 0.002;

struct cb_result {
	bool called;
	char errmsg[256];
	size_t errlen;
	bool has_stream;
	unsigned char stream_buf[512];
	size_t stream_len;
};

struct stub_state {
	bool dialer_defer;
	int dialer_result_fd;
	enum dialer_error dialer_err;
	int dialer_syserr;
	int_least32_t dialer_do_calls;
	int_least32_t dialer_cancel_calls;
	int_least32_t dialreq_free_calls;
	struct ev_loop *pending_loop;
	struct dialer *pending_dialer;
	/* the counters dialer_init was handed, so a test can pin which
	 * server_stats field each one is */
	uint_least64_t *dialer_byt_sent;
	uint_least64_t *dialer_byt_recv;
};

static struct stub_state S = {
	.dialer_defer = false,
	.dialer_result_fd = -1,
	.dialer_err = DIALER_ERR_CONNECT,
	.dialer_syserr = ECONNREFUSED,
	.dialer_do_calls = 0,
	.dialer_cancel_calls = 0,
	.dialreq_free_calls = 0,
	.pending_loop = NULL,
	.pending_dialer = NULL,
	.dialer_byt_sent = NULL,
	.dialer_byt_recv = NULL,
};

static void reset_stub_state(void)
{
	S.dialer_defer = false;
	S.dialer_result_fd = -1;
	S.dialer_err = DIALER_ERR_CONNECT;
	S.dialer_syserr = ECONNREFUSED;
	S.dialer_do_calls = 0;
	S.dialer_cancel_calls = 0;
	S.dialreq_free_calls = 0;
	S.pending_loop = NULL;
	S.pending_dialer = NULL;
	S.dialer_byt_sent = NULL;
	S.dialer_byt_recv = NULL;
	test_conf.timeout = 1.0;
}

static bool fd_set_nonblock(const int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		return false;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

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

static void
read_stream_content(struct io_stream *stream, unsigned char *buf, size_t *len)
{
	size_t total = 0;
	while (total < *len) {
		size_t n = *len - total;
		if (io_stream_read(stream, buf + total, &n) != 0) {
			break;
		}
		if (n == 0) {
			break;
		}
		total += n;
	}
	*len = total;
}

static void capture_cb(
	struct api_client_ctx *ctx, struct ev_loop *loop, void *data,
	const char *errmsg, size_t errlen, struct io_stream *stream)
{
	struct cb_result *const out = data;
	(void)ctx;
	(void)loop;
	out->called = true;
	out->errlen = errlen;
	if (errmsg != NULL) {
		const size_t copy_len = errlen < sizeof(out->errmsg) - 1 ?
						errlen :
						sizeof(out->errmsg) - 1;
		(void)memcpy(out->errmsg, errmsg, copy_len);
		out->errmsg[copy_len] = '\0';
	} else {
		out->errmsg[0] = '\0';
	}
	if (stream != NULL) {
		size_t n = sizeof(out->stream_buf);
		read_stream_content(stream, out->stream_buf, &n);
		out->has_stream = true;
		out->stream_len = n;
	} else {
		out->has_stream = false;
		out->stream_len = 0;
	}
}

struct test_watchdog {
	bool fired;
};

static void
test_watchdog_cb(struct ev_loop *loop, struct ev_timer *w, const int revents)
{
	struct test_watchdog *const watchdog = w->data;
	(void)revents;
	watchdog->fired = true;
	ev_break(loop, EVBREAK_ONE);
}

static void
test_tick_cb(struct ev_loop *loop, struct ev_timer *w, const int revents)
{
	/* No-op: this timer exists only to bound ev_run(EVRUN_ONCE) sleeps. */
	(void)loop;
	(void)w;
	(void)revents;
}

static bool test_wait_until(
	struct ev_loop *loop, bool (*predicate)(void *), void *data,
	const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout, w_tick;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	/* The predicate may poll a socket that is not registered with the loop
	 * (e.g. fd_closed_predicate); bound ev_run() so it is re-checked
	 * promptly instead of sleeping until the watchdog. */
	ev_timer_init(&w_tick, test_tick_cb, TEST_TICK_SEC, TEST_TICK_SEC);
	ev_timer_start(loop, &w_tick);
	while (!watchdog.fired && !predicate(data)) {
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_tick);
	ev_timer_stop(loop, &w_timeout);
	return predicate(data);
}

static bool cb_called_predicate(void *data)
{
	const struct cb_result *const r = data;
	return r->called;
}

struct fd_closed_ctx {
	int fd;
};

/* Drains whatever the client sent, so a single call sees the close as soon as
 * it happens instead of one byte per loop iteration. */
static bool fd_closed_predicate(void *data)
{
	struct fd_closed_ctx *const ctx = data;
	unsigned char buf[256];

	for (;;) {
		const ssize_t n = recv_nowait(ctx->fd, buf, sizeof(buf));
		if (n == 0) {
			return true;
		}
		if (n < 0) {
			return false;
		}
	}
}

static bool read_request_headers_with_size(
	struct ev_loop *loop, const int fd, char *buf, const size_t cap,
	const ev_tstamp timeout_sec, size_t *received)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout, w_tick;
	size_t off = 0;

	if (cap == 0) {
		return false;
	}
	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	/* fd is not registered with the loop; bound ev_run() so we keep
	 * re-polling and pick up the request even when the peer's write lands
	 * a little later (as it does under the MSYS2/Cygwin socket emulation). */
	ev_timer_init(&w_tick, test_tick_cb, TEST_TICK_SEC, TEST_TICK_SEC);
	ev_timer_start(loop, &w_tick);
	while (!watchdog.fired && off + 1 < cap) {
		const ssize_t n = recv_nowait(fd, buf + off, cap - off - 1);
		if (n > 0) {
			off += (size_t)n;
			buf[off] = '\0';
			if (strstr(buf, "\r\n\r\n") != NULL) {
				break;
			}
			continue;
		}
		if (n == 0) {
			break; /* EOF */
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ev_run(loop, EVRUN_ONCE);
			continue;
		}
		break; /* hard error */
	}
	ev_timer_stop(loop, &w_tick);
	ev_timer_stop(loop, &w_timeout);
	buf[off] = '\0';
	*received = off;
	return strstr(buf, "\r\n\r\n") != NULL;
}

static bool read_request_headers(
	struct ev_loop *loop, const int fd, char *buf, const size_t cap,
	const ev_tstamp timeout_sec)
{
	size_t received = 0;
	return read_request_headers_with_size(
		loop, fd, buf, cap, timeout_sec, &received);
}

struct request_body_capture {
	int fd;
	char *buf;
	size_t received, total;
};

static bool request_body_complete(void *data)
{
	struct request_body_capture *const capture = data;
	if (capture->received < capture->total) {
		const ssize_t n = recv_nowait(
			capture->fd, capture->buf + capture->received,
			capture->total - capture->received);
		if (n > 0) {
			capture->received += (size_t)n;
		}
	}
	return capture->received == capture->total;
}

static bool send_response(
	const int fd, const char *status_line, const char *content_type,
	const char *connection, const void *body, const size_t body_len)
{
	char hdr[1024];
	int n = snprintf(hdr, sizeof(hdr), "HTTP/1.1 %s\r\n", status_line);
	if (n <= 0 || (size_t)n >= sizeof(hdr)) {
		return false;
	}
	size_t off = (size_t)n;
	if (content_type != NULL) {
		n = snprintf(
			hdr + off, sizeof(hdr) - off, "Content-Type: %s\r\n",
			content_type);
		if (n <= 0 || (size_t)n >= sizeof(hdr) - off) {
			return false;
		}
		off += (size_t)n;
	}
	if (connection != NULL) {
		n = snprintf(
			hdr + off, sizeof(hdr) - off, "Connection: %s\r\n",
			connection);
		if (n <= 0 || (size_t)n >= sizeof(hdr) - off) {
			return false;
		}
		off += (size_t)n;
	}
	n = snprintf(
		hdr + off, sizeof(hdr) - off, "Content-Length: %zu\r\n\r\n",
		body_len);
	if (n <= 0 || (size_t)n >= sizeof(hdr) - off) {
		return false;
	}
	off += (size_t)n;
	if (!write_all(fd, hdr, off)) {
		return false;
	}
	if (body_len > 0) {
		return write_all(fd, body, body_len);
	}
	return true;
}

/* Like send_response but adds a Content-Encoding header; the body is written
 * verbatim (already encoded by the caller). */
static bool send_encoded_response(
	const int fd, const char *status_line, const char *content_type,
	const char *encoding, const void *body, const size_t body_len)
{
	char hdr[256];
	const int n = snprintf(
		hdr, sizeof(hdr),
		"HTTP/1.1 %s\r\n"
		"Content-Type: %s\r\n"
		"Content-Encoding: %s\r\n"
		"Connection: close\r\n"
		"Content-Length: %zu\r\n\r\n",
		status_line, content_type, encoding, body_len);
	if (n <= 0 || (size_t)n >= sizeof(hdr)) {
		return false;
	}
	if (!write_all(fd, hdr, (size_t)n)) {
		return false;
	}
	return body_len == 0 || write_all(fd, body, body_len);
}

static struct dialreq *new_test_dialreq(void)
{
	return calloc(1, sizeof(struct dialreq));
}

int dialaddr_format(
	char *restrict s, const size_t maxlen,
	const struct dialaddr *restrict addr)
{
	char host[INET6_ADDRSTRLEN];
	const char *name = NULL;

	switch (addr->type) {
	case ATYP_INET:
		name = inet_ntop(AF_INET, &addr->in, host, sizeof(host));
		if (name == NULL) {
			return -1;
		}
		return snprintf(s, maxlen, "%s:%u", name, (unsigned)addr->port);
	case ATYP_INET6:
		name = inet_ntop(AF_INET6, &addr->in6, host, sizeof(host));
		if (name == NULL) {
			return -1;
		}
		return snprintf(
			s, maxlen, "[%s]:%u", name, (unsigned)addr->port);
	case ATYP_DOMAIN:
		return snprintf(
			s, maxlen, "%.*s:%u", (int)addr->domain.len,
			addr->domain.name, (unsigned)addr->port);
	default:
		return -1;
	}
}

const char *dialer_strerror(const enum dialer_error err)
{
	(void)err;
	return "stub dialer error";
}

void dialer_init(
	struct dialer *restrict d, const struct dialer_cb *callback,
	uint_least64_t *byt_sent, uint_least64_t *byt_recv)
{
	S.dialer_byt_sent = byt_sent;
	S.dialer_byt_recv = byt_recv;
	d->finish_cb = *callback;
}

void dialer_do(
	struct dialer *d, struct ev_loop *loop, const struct dialreq *req,
	const struct config *conf, struct resolver *resolver,
	struct server *server)
{
	(void)req;
	(void)conf;
	(void)resolver;
	(void)server;
	S.dialer_do_calls++;
	d->err = S.dialer_err;
	d->syserr = S.dialer_syserr;
	if (S.dialer_defer) {
		S.pending_loop = loop;
		S.pending_dialer = d;
		return;
	}
	d->finish_cb.func(loop, d->finish_cb.data, S.dialer_result_fd);
}

void dialer_cancel(struct dialer *restrict d, struct ev_loop *restrict loop)
{
	(void)d;
	(void)loop;
	S.dialer_cancel_calls++;
}

void dialreq_free(struct dialreq *req)
{
	S.dialreq_free_calls++;
	free(req);
}

/* check_rpcall_mime is the real proto/http.c implementation (linked in). */

/* ---- log capture ----
 * A fire-and-forget invoke reports its failure only in the log, so a writer
 * sink collects the formatted lines for the case to search. */
static struct {
	char buf[4096];
	size_t len;
} g_logcap;

static void logcap_write(void *ud, const unsigned char *buf, size_t len)
{
	(void)ud;
	const size_t space = sizeof(g_logcap.buf) - 1 - g_logcap.len;
	if (len > space) {
		len = space;
	}
	memcpy(g_logcap.buf + g_logcap.len, buf, len);
	g_logcap.len += len;
	g_logcap.buf[g_logcap.len] = '\0';
}

static void logcap_start(const int level)
{
	g_logcap.len = 0;
	g_logcap.buf[0] = '\0';
	slog_setoutput(SLOG_OUTPUT_WRITER, logcap_write, NULL);
	slog_setlevel(level);
}

/* Restore the default silence, so a case that longjmps out of an assertion
 * cannot leave the writer sink installed for the next one. */
static void logcap_stop(void)
{
	slog_setlevel(LOG_LEVEL_SILENCE);
	slog_setoutput(SLOG_OUTPUT_DISCARD);
}

/* ---- realloc fault injection ----
 * api_client's error paths build their message through vbuffer, which calls
 * libc realloc() directly, so interposing realloc() here drives their
 * out-of-memory branches. Arming is deliberately coarse ("fail everything from
 * now on"): the branch under test is whichever vbuffer allocation comes first,
 * and the asserted invariant holds for all of them -- the callback must report
 * an error rather than deliver (NULL errmsg, NULL stream), which
 * api_client_finish() also asserts. libev is taken out of the blast radius by
 * ev_isolated_alloc below, since it aborts the process on a failed allocation.
 * The passthrough is reimplemented over malloc()/free() so it needs no
 * libc-internal symbol. */
static bool g_realloc_fail;
static size_t g_realloc_allocations;

/* realloc() semantics over malloc()/free(), with an optional armed failure. */
static void *realloc_impl(void *ptr, const size_t size, const bool may_fail)
{
	/* realloc(ptr, 0) must free ptr even while a failure is armed, so the
	 * free path precedes the fault-injection check */
	if (size == 0) {
		free(ptr);
		return NULL;
	}
	if (may_fail && g_realloc_fail) {
		return NULL;
	}
	void *const np = malloc(size);
	if (np == NULL) {
		return NULL;
	}
	if (may_fail) {
		g_realloc_allocations++;
	}
	if (ptr != NULL) {
		const size_t oldsize = malloc_usable_size(ptr);
		memcpy(np, ptr, oldsize < size ? oldsize : size);
		free(ptr);
	}
	return np;
}

void *realloc(void *ptr, size_t size)
{
	return realloc_impl(ptr, size, true);
}

/* libev's allocator, which bypasses the injection: libev aborts the whole
 * process on an allocation failure, so an armed realloc() would kill the test
 * run rather than exercise api_client. Interchangeable with the interposer
 * above, as both are malloc()/free() underneath. */
static void *ev_isolated_alloc(void *ptr, long size)
{
	return realloc_impl(ptr, (size_t)size, false);
}

struct response_phase {
	const struct server_stats *stats;
	const struct cb_result *result;
	size_t received, allocations;
};

static bool response_phase_consumed(void *data)
{
	const struct response_phase *const phase = data;
	return phase->result->called ||
	       (phase->stats->api_client_byt_recv == phase->received &&
		g_realloc_allocations > phase->allocations);
}

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - RPC call/invoke lifecycle, errors and connection reuse.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(rpcall_success_returns_stream)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";
	static const char rsp_body[] = "ok";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(ctx != NULL);
	T_CHECK(read_request_headers(
		loop, sv[1], reqbuf, sizeof(reqbuf), TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(strstr(reqbuf, "POST /ruleset/rpcall HTTP/1.1") != NULL);
	T_CHECK(send_response(
		sv[1], "200 OK", MIME_RPCALL, "keep-alive", rsp_body,
		sizeof(rsp_body) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(out.called);
	T_EXPECT_EQ(out.errlen, 0);
	T_EXPECT(out.errmsg[0] == '\0');
	T_EXPECT(out.has_stream);
	T_EXPECT_EQ(out.stream_len, sizeof(rsp_body) - 1);
	T_EXPECT_MEMEQ(out.stream_buf, rsp_body, sizeof(rsp_body) - 1);
	/* no stats means no counters at all */
	T_EXPECT(S.dialer_byt_sent == NULL);
	T_EXPECT(S.dialer_byt_recv == NULL);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

/* Each of the four byte counters must reach the server_stats field it names.
 * A transposed pair compiles clean and only shows up as wrong numbers in
 * /stats, so pin the wiring: the dialer's two by the identity of the pointers
 * it was handed, the connection's two by orientation -- the response here is
 * far larger than the request, so a swapped recv/sent pair cannot pass. */
T_DECLARE_CASE(rpcall_threads_stats_counters)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	struct server_stats stats = { 0 };
	int sv[2] = { -1, -1 };
	char reqbuf[512] = { 0 };
	char rsp_body[1024];
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};
	const struct api_client_opts opts = {
		.conf = &test_conf,
		.stats = &stats,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	(void)memset(rsp_body, 'x', sizeof(rsp_body));
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb, &opts));
	T_CHECK(ctx != NULL);
	T_EXPECT(S.dialer_byt_sent == &stats.byt_dial_send);
	T_EXPECT(S.dialer_byt_recv == &stats.byt_dial_recv);
	T_CHECK(read_request_headers(
		loop, sv[1], reqbuf, sizeof(reqbuf), TEST_WAIT_RESPONSE_SEC));
	T_CHECK(send_response(
		sv[1], "200 OK", MIME_RPCALL, "keep-alive", rsp_body,
		sizeof(rsp_body)));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(out.called);
	T_EXPECT_EQ(out.errlen, 0);
	T_EXPECT_EQ(stats.num_api_client_request, 1);
	T_EXPECT(stats.api_client_byt_recv > sizeof(rsp_body));
	T_EXPECT(stats.api_client_byt_send > 0);
	T_EXPECT(stats.api_client_byt_send < sizeof(rsp_body));

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(rpcall_chunked_response_reports_error)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";
	/* A chunked 200 rpcall response: http_conn parses it to completion with
	 * cbuf == NULL and the body left in rbuf, so on_http_client_done would
	 * otherwise deliver an empty body. It must instead report an error rather
	 * than silently lose the response. */
	static const char resp[] = "HTTP/1.1 200 OK\r\n"
				   "Content-Type: " MIME_RPCALL "\r\n"
				   "Transfer-Encoding: chunked\r\n"
				   "Connection: close\r\n\r\n"
				   "2\r\nok\r\n0\r\n\r\n";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(ctx != NULL);
	T_CHECK(read_request_headers(
		loop, sv[1], reqbuf, sizeof(reqbuf), TEST_WAIT_RESPONSE_SEC));
	T_CHECK(write_all(sv[1], resp, sizeof(resp) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(out.called);
	/* an error, not a silent empty-body success */
	T_EXPECT(out.errlen > 0);
	T_EXPECT(!out.has_stream);
	T_EXPECT(strstr(out.errmsg, "chunked") != NULL);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

/* Run one rpcall against a peer that answers with the raw bytes of `resp`
 * and then closes, and capture what the callback reports. */
T_DECLARE_SUBCASE(
	rpcall_raw_response, const char *restrict resp, const size_t resplen,
	struct cb_result *restrict out)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(read_request_headers(
		loop, sv[1], reqbuf, sizeof(reqbuf), TEST_WAIT_RESPONSE_SEC));
	T_CHECK(write_all(sv[1], resp, resplen));
	T_CHECK(close(sv[1]) == 0);
	T_EXPECT(test_wait_until(
		loop, cb_called_predicate, out, TEST_WAIT_RESPONSE_SEC));

	ev_loop_destroy(loop);
}

T_DECLARE_CASE(rpcall_interim_responses_deliver_final_result)
{
	struct cb_result out = { 0 };
	static const char response[] =
		"HTTP/1.1 103 Early Hints\r\n"
		"Content-Type: text/plain\r\nContent-Encoding: gzip\r\n"
		"Transfer-Encoding: chunked\r\n\r\n"
		"HTTP/1.1 199 Informational\r\n\r\n"
		"HTTP/1.1 200 OK\r\nContent-Type: " MIME_RPCALL "\r\n"
		"Content-Length: 2\r\n\r\nok";
	T_CALL_SUBCASE(
		rpcall_raw_response, response, sizeof(response) - 1, &out);
	T_EXPECT(out.called);
	T_EXPECT_EQ(out.errlen, 0);
	T_EXPECT(out.has_stream);
	T_EXPECT_EQ(out.stream_len, 2);
	T_EXPECT_MEMEQ(out.stream_buf, "ok", 2);
}

T_DECLARE_CASE(rpcall_interim_response_requires_valid_final_response)
{
	static const char *const responses[] = {
		"HTTP/1.1 103 Early Hints\r\n\r\n",
		"HTTP/1.1 103 Early Hints\r\n\r\nSPDY/3 200 OK\r\n\r\n",
	};
	for (size_t i = 0; i < sizeof(responses) / sizeof(responses[0]); i++) {
		struct cb_result out = { 0 };
		T_CALL_SUBCASE(
			rpcall_raw_response, responses[i], strlen(responses[i]),
			&out);
		T_EXPECT(out.called);
		T_EXPECT(!out.has_stream);
		T_EXPECT_STREQ(out.errmsg, "error receiving response");
	}
}

/* A 2xx rpcall response with neither Content-Length nor chunked is delimited
 * by the connection close; its body is not read, so it must be reported as an
 * error rather than delivered as a successful empty result. */
T_DECLARE_CASE(rpcall_close_delimited_response_reports_error)
{
	struct cb_result out = { 0 };
	static const char resp[] = "HTTP/1.1 200 OK\r\n"
				   "Content-Type: " MIME_RPCALL "\r\n"
				   "Connection: close\r\n\r\n"
				   "ok";

	T_CALL_SUBCASE(rpcall_raw_response, resp, sizeof(resp) - 1, &out);
	T_EXPECT(out.called);
	T_EXPECT(out.errlen > 0);
	T_EXPECT(!out.has_stream);
	T_EXPECT(strstr(out.errmsg, "close-delimited") != NULL);
}

/* A 204 has no body whatever its header fields say (RFC 9112 6.3), so a
 * missing Content-Length there hides nothing: it stays an empty result. */
T_DECLARE_CASE(rpcall_no_content_without_length_is_empty)
{
	struct cb_result out = { 0 };
	static const char resp[] = "HTTP/1.1 204 No Content\r\n"
				   "Content-Type: " MIME_RPCALL "\r\n"
				   "Connection: close\r\n\r\n";

	T_CALL_SUBCASE(rpcall_raw_response, resp, sizeof(resp) - 1, &out);
	T_EXPECT(out.called);
	T_EXPECT_EQ(out.errlen, 0);
	T_EXPECT(out.has_stream);
	T_EXPECT_EQ(out.stream_len, 0);
}

T_DECLARE_CASE(rpcall_success_empty_body_ok)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(ctx != NULL);
	T_CHECK(read_request_headers(
		loop, sv[1], reqbuf, sizeof(reqbuf), TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(strstr(reqbuf, "POST /ruleset/rpcall HTTP/1.1") != NULL);
	/* Regression: a 2xx rpcall response with Content-Length: 0 leaves the
	 * content vbuffer unallocated (NULL); this must not crash the caller. */
	T_CHECK(send_response(
		sv[1], "200 OK", MIME_RPCALL, "keep-alive", NULL, 0));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(out.called);
	T_EXPECT_EQ(out.errlen, 0);
	T_EXPECT(out.errmsg[0] == '\0');
	T_EXPECT(out.has_stream);
	T_EXPECT_EQ(out.stream_len, 0);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(invoke_uses_invoke_path)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct dialreq *req = NULL;
	struct fd_closed_ctx closed_ctx = { 0 };
	int sv[2] = { -1, -1 };
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	api_client_invoke(loop, req, payload, sizeof(payload) - 1, &test_opts);
	T_CHECK(read_request_headers(
		loop, sv[1], reqbuf, sizeof(reqbuf), TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(strstr(reqbuf, "POST /ruleset/invoke HTTP/1.1") != NULL);
	T_CHECK(send_response(sv[1], "204 No Content", NULL, "close", NULL, 0));
	closed_ctx.fd = sv[1];
	T_CHECK(test_wait_until(
		loop, fd_closed_predicate, &closed_ctx,
		TEST_WAIT_RESPONSE_SEC));

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

static bool logcap_has_invoke_error(void *data)
{
	(void)data;
	return strstr(g_logcap.buf, "api invoke: ") != NULL;
}

/*
 * An invoke carries no callback, so a failed request is reported only in the
 * log -- the one branch of process_cb() nothing else observes. Drive it and
 * read the line back; the teardown behind it must still free everything.
 */
T_DECLARE_CASE(invoke_failure_is_logged)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct dialreq *req = NULL;
	struct server_stats stats = { 0 };
	static const char payload[] = "{}";
	const struct api_client_opts opts = {
		.conf = &test_conf,
		.stats = &stats,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	S.dialer_result_fd = -1;
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	logcap_start(LOG_LEVEL_WARNING);
	api_client_invoke(loop, req, payload, sizeof(payload) - 1, &opts);
	const bool logged = test_wait_until(
		loop, logcap_has_invoke_error, NULL, TEST_WAIT_SHORT_SEC);
	logcap_stop();

	T_CHECK(logged);
	T_EXPECT(strstr(g_logcap.buf, "api invoke: connection failed") != NULL);
	T_EXPECT_EQ(S.dialer_do_calls, 1);
	T_EXPECT_EQ(stats.num_api_client_request, 1);

	ev_loop_destroy(loop);
}

/*
 * A request whose body cannot be built is never issued: api_client_do() must
 * report the failure, free the dialreq itself (nothing downstream consumes it),
 * leave *pctx alone, and leave the request counter where it was -- it counts
 * requests that went out, not requests that were attempted.
 */
T_DECLARE_CASE(rpcall_request_build_failure_issues_nothing)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	struct server_stats stats = { 0 };
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};
	const struct api_client_opts opts = {
		.conf = &test_conf,
		.stats = &stats,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	/* fail every allocation, so content_writer() cannot reserve the request
	 * body buffer and make_request() gives up before anything is sent */
	g_realloc_fail = true;
	const bool ok = api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb, &opts);
	g_realloc_fail = false;

	T_EXPECT(!ok);
	T_EXPECT(ctx == NULL);
	T_EXPECT_EQ(S.dialreq_free_calls, 1);
	T_EXPECT_EQ(S.dialer_do_calls, 0);
	T_EXPECT_EQ(stats.num_api_client_request, 0);
	T_EXPECT(!out.called);

	ev_loop_destroy(loop);
}

T_DECLARE_CASE(rpcall_unsupported_content_type)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	static const char payload[] = "{}";
	static const char rsp_body[] = "x";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(send_response(
		sv[1], "200 OK", "text/plain", "keep-alive", rsp_body,
		sizeof(rsp_body) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(out.called);
	T_EXPECT_STREQ(out.errmsg, "unsupported content-type");
	T_EXPECT(!out.has_stream);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(rpcall_dialer_failure)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	S.dialer_result_fd = -1;
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_SHORT_SEC));
	T_EXPECT(out.called);
	T_EXPECT_STREQ(out.errmsg, "connection failed");
	T_EXPECT_EQ(S.dialer_do_calls, 1);

	ev_loop_destroy(loop);
}

T_DECLARE_CASE(rpcall_timeout)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	/* A zero timeout arms the request deadline to fire on the next event-loop
	 * iteration, so the "timeout" result is reached deterministically without
	 * waiting out a real wall-clock deadline. */
	test_conf.timeout = 0;
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_LONG_SEC));
	T_EXPECT(out.called);
	T_EXPECT_STREQ(out.errmsg, "timeout");

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(rpcall_http_error_status_line)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(send_response(sv[1], "404 Not Found", NULL, "close", NULL, 0));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(out.called);
	T_EXPECT(strstr(out.errmsg, "404") != NULL);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

/*
 * Regression: an allocation failure while building a non-2xx error message must
 * still report an error. These branches used to finish with both a NULL errmsg
 * and a NULL stream, which a caller reads as success: ruleset/await.c's
 * await_invoke_k then hands the NULL stream to aux_load() and crashes. The
 * contract asserted here -- errmsg is non-NULL, so the caller reports the error
 * -- is the one api_client_finish() also asserts.
 */
T_DECLARE_CASE(rpcall_oom_building_error_still_reports_error)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(send_response(sv[1], "404 Not Found", NULL, "close", NULL, 0));

	/* fail every allocation from here on, so building the error message
	 * for the 404 cannot succeed */
	g_realloc_fail = true;
	const bool waited = test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC);
	g_realloc_fail = false;

	T_CHECK(waited);
	T_EXPECT(out.called);
	/* the error must be reported, never delivered as a NULL/NULL success */
	T_EXPECT(out.errlen > 0);
	T_EXPECT(!out.has_stream);
	/* and it must be the OOM-specific message, not the ordinary 404 error
	 * page: this is what proves the OOM branch was exercised rather than the
	 * case passing vacuously if the realloc injection ever stops firing */
	T_EXPECT(strstr(out.errmsg, "out of memory") != NULL);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(rpcall_structured_error_body)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	static const char payload[] = "{}";
	static const char rsp_body[] = "backend failed";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(send_response(
		sv[1], "500 Internal Server Error", MIME_RPCALL, "close",
		rsp_body, sizeof(rsp_body) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(out.called);
	T_EXPECT_EQ(out.errlen, sizeof(rsp_body) - 1);
	T_EXPECT_STREQ(out.errmsg, rsp_body);
	T_EXPECT(!out.has_stream);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

/* A structured (rpcall-MIME) error body carrying Content-Encoding: deflate must
 * be decoded before reaching the caller, mirroring the success path; otherwise
 * the raw compressed bytes were delivered as the error message. */
T_DECLARE_CASE(rpcall_structured_error_body_deflate_is_decoded)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	static const char payload[] = "{}";
	static const char plain[] = "backend failed: structured error detail";
	struct vbuffer *cbuf = NULL;
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();

	/* deflate-compress the known error text to use as the response body */
	struct io_stream *w =
		content_writer(&cbuf, sizeof(plain) - 1, CENCODING_DEFLATE);
	T_CHECK(w != NULL);
	size_t wn = sizeof(plain) - 1;
	T_CHECK(io_stream_write(w, plain, &wn) == 0);
	T_CHECK(wn == sizeof(plain) - 1);
	T_CHECK(io_stream_close(w) == 0);
	T_CHECK(cbuf != NULL);
	T_CHECK(VBUF_LEN(cbuf) > 0);

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(send_encoded_response(
		sv[1], "500 Internal Server Error", MIME_RPCALL, "deflate",
		VBUF_DATA(cbuf), VBUF_LEN(cbuf)));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(out.called);
	/* the decoded plain text, not the raw deflate bytes */
	T_EXPECT_EQ(out.errlen, sizeof(plain) - 1);
	T_EXPECT_STREQ(out.errmsg, plain);
	T_EXPECT(!out.has_stream);

	VBUF_FREE(cbuf);
	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

/* Regression: decoding a Content-Encoding'd structured error must report an
 * error, not crash, when content_decode_vbuf's decode buffer (VBUF_NEW) fails
 * to allocate. Arms the realloc injector so that allocation returns NULL. */
T_DECLARE_CASE(rpcall_structured_error_decode_oom_reports_error)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	static const char payload[] = "{}";
	static const char plain[] = "backend failed: structured error detail";
	struct vbuffer *cbuf = NULL;
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};
	struct server_stats stats = { 0 };
	const struct api_client_opts opts = {
		.conf = &test_conf,
		.stats = &stats,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();

	struct io_stream *w =
		content_writer(&cbuf, sizeof(plain) - 1, CENCODING_DEFLATE);
	T_CHECK(w != NULL);
	size_t wn = sizeof(plain) - 1;
	T_CHECK(io_stream_write(w, plain, &wn) == 0);
	T_CHECK(wn == sizeof(plain) - 1);
	T_CHECK(io_stream_close(w) == 0);
	T_CHECK(cbuf != NULL);
	T_CHECK(VBUF_LEN(cbuf) > 0);

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb, &opts));
	char reqbuf[512];
	T_CHECK(read_request_headers(
		loop, sv[1], reqbuf, sizeof(reqbuf), TEST_WAIT_RESPONSE_SEC));

	/* Build the full response so it can be delivered in two phases. The
	 * client allocates its content buffer (VBUF_NEW) on the first body byte;
	 * the inflate reader used later allocates via malloc, which the injector
	 * does not fail, so the decode buffer's VBUF_NEW is the one realloc that
	 * must fail to reach the bug. */
	unsigned char resp[512];
	const int hn = snprintf(
		(char *)resp, sizeof(resp),
		"HTTP/1.1 500 Internal Server Error\r\n"
		"Content-Type: %s\r\n"
		"Content-Encoding: deflate\r\n"
		"Connection: close\r\n"
		"Content-Length: %zu\r\n\r\n",
		MIME_RPCALL, VBUF_LEN(cbuf));
	T_CHECK(hn > 0);
	const size_t total = (size_t)hn + VBUF_LEN(cbuf);
	T_CHECK(total <= sizeof(resp) && VBUF_LEN(cbuf) >= 1);
	memcpy(resp + hn, VBUF_DATA(cbuf), VBUF_LEN(cbuf));

	/* Phase 1: deliver everything but the last body byte and let the client
	 * parse the headers and allocate its content buffer while allocations
	 * still succeed. The response stays incomplete, so the callback does not
	 * fire. */
	const struct response_phase phase = {
		.stats = &stats,
		.result = &out,
		.received = total - 1,
		.allocations = g_realloc_allocations,
	};
	T_CHECK(write_all(sv[1], resp, total - 1));
	T_CHECK(test_wait_until(
		loop, response_phase_consumed, (void *)&phase,
		TEST_WAIT_RESPONSE_SEC));
	T_CHECK(!out.called);
	T_EXPECT_EQ(stats.api_client_byt_recv, total - 1);
	T_EXPECT(g_realloc_allocations > phase.allocations);

	/* Phase 2: fail allocations, then deliver the last byte so the response
	 * completes and content_decode_vbuf's VBUF_NEW returns NULL. */
	g_realloc_fail = true;
	T_CHECK(write_all(sv[1], resp + total - 1, 1));
	const bool waited = test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC);
	g_realloc_fail = false;

	T_CHECK(waited);
	T_EXPECT(out.called);
	/* an error is reported (never a NULL/NULL success) and nothing crashed */
	T_EXPECT(out.errlen > 0);
	T_EXPECT(!out.has_stream);
	T_EXPECT(strstr(out.errmsg, "cannot decode error content") != NULL);

	VBUF_FREE(cbuf);
	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(cancel_during_connect_calls_dialer_cancel)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	S.dialer_defer = true;
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(ctx != NULL);
	api_client_cancel(loop, ctx);
	T_EXPECT_EQ(S.dialer_cancel_calls, 1);
	T_EXPECT(!out.called);

	ev_loop_destroy(loop);
}

/* Complete an rpcall with `resp`, then cancel it after the exchange finished
 * but before the deferred callback ran -- the window in which a ruleset
 * coroutine closed early cancels a finished request. The callback must never
 * fire, and the recorded result must be released (the sanitizer builds catch
 * a leak or a dispatch onto the freed request). */
T_DECLARE_SUBCASE(cancel_after_response, const char *restrict resp)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	struct fd_closed_ctx closed_ctx = { 0 };
	int sv[2] = { -1, -1 };
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(ctx != NULL);
	T_CHECK(read_request_headers(
		loop, sv[1], reqbuf, sizeof(reqbuf), TEST_WAIT_RESPONSE_SEC));
	T_CHECK(write_all(sv[1], resp, strlen(resp)));
	/* the client closes its socket in the same callback that records the
	 * result and defers the user callback, which the loop dispatches no
	 * earlier than its next iteration */
	closed_ctx.fd = sv[1];
	T_CHECK(test_wait_until(
		loop, fd_closed_predicate, &closed_ctx,
		TEST_WAIT_RESPONSE_SEC));
	T_CHECK(!out.called);

	api_client_cancel(loop, ctx);
	T_EXPECT(!test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_SHORT_SEC));
	T_EXPECT(!out.called);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(cancel_after_success_drops_stream)
{
	T_CALL_SUBCASE(
		cancel_after_response, "HTTP/1.1 200 OK\r\n"
				       "Content-Type: " MIME_RPCALL "\r\n"
				       "Content-Length: 2\r\n\r\n"
				       "ok");
}

T_DECLARE_CASE(cancel_after_error_drops_message)
{
	T_CALL_SUBCASE(
		cancel_after_response, "HTTP/1.1 500 Internal Server Error\r\n"
				       "Content-Type: " MIME_RPCALL "\r\n"
				       "Content-Length: 4\r\n\r\n"
				       "boom");
}

/* An HTTP/1.1 request must carry a Host field naming the server it is sent
 * to, or a conforming server or reverse proxy in front of the API answers 400
 * (RFC 9112 3.2). */
T_DECLARE_CASE(request_carries_host_header)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";
	static const char host[] = "api.example";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);
	req->addr.type = ATYP_DOMAIN;
	req->addr.port = 9080;
	req->addr.domain.len = (uint_least8_t)(sizeof(host) - 1);
	(void)memcpy(req->addr.domain.name, host, sizeof(host) - 1);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(read_request_headers(
		loop, sv[1], reqbuf, sizeof(reqbuf), TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(strstr(reqbuf, "\r\nHost: api.example:9080\r\n") != NULL);

	T_CHECK(send_response(
		sv[1], "204 No Content", MIME_RPCALL, "close", NULL, 0));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(out.called);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

/* The client never pools connections, so every request advertises
 * Connection: close and the exchange completes regardless of what the peer
 * offers in its own Connection header. */
T_DECLARE_CASE(request_advertises_connection_close)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";
	static const char rsp_body[] = "ok";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(read_request_headers(
		loop, sv[1], reqbuf, sizeof(reqbuf), TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(strstr(reqbuf, "Connection: close") != NULL);
	T_EXPECT(strstr(reqbuf, "keep-alive") == NULL);

	/* peer offers keep-alive; the client must still finish normally */
	T_CHECK(send_response(
		sv[1], "200 OK", MIME_RPCALL, "keep-alive", rsp_body,
		sizeof(rsp_body) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(out.called);
	T_EXPECT_EQ(out.errlen, 0);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

/*
 * Regression: send_cb's generic write-error path builds the error message in a
 * stack buffer and finishes synchronously, but api_client defers the callback
 * to an ev_idle, so the message must be copied into ctx-owned storage before
 * that stack frame unwinds. Dial to a socket whose peer is already closed, so
 * the first write fails with EPIPE and takes that path.
 * A dangling read in process_cb would be caught here under the sanitizers.
 */
T_DECLARE_CASE(rpcall_write_error_reports_message)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(close(sv[1]) == 0);
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(out.called);
	T_EXPECT(out.errlen > 0);
	T_EXPECT(out.errmsg[0] != '\0');
	T_EXPECT_EQ(S.dialer_do_calls, 1);

	ev_loop_destroy(loop);
}

/* A payload >= RPCALL_COMPRESS_THRESHOLD must be deflate-compressed on the
 * wire (make_request's content_writer path) and advertised via
 * Content-Encoding. Every other case sends "{}" (below the threshold), so
 * this compression path was unexercised. */
T_DECLARE_CASE(rpcall_large_payload_is_deflate_compressed)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	char reqbuf[1024] = { 0 };
	char payload[RPCALL_COMPRESS_THRESHOLD + 64];
	static const char rsp_body[] = "ok";
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};
	struct server_stats stats = { 0 };
	const struct api_client_opts opts = {
		.conf = &test_conf,
		.stats = &stats,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	/* highly compressible payload above the threshold */
	memset(payload, 'a', sizeof(payload));
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload), &cb, &opts));
	size_t received = 0;
	T_CHECK(read_request_headers_with_size(
		loop, sv[1], reqbuf, sizeof(reqbuf), TEST_WAIT_RESPONSE_SEC,
		&received));
	T_EXPECT(strstr(reqbuf, "POST /ruleset/rpcall HTTP/1.1") != NULL);
	T_EXPECT(strstr(reqbuf, "Content-Encoding: deflate") != NULL);
	char *const length_header = strstr(reqbuf, "\r\nContent-Length: ");
	T_CHECK(length_header != NULL);
	char *const length_value =
		length_header + strlen("\r\nContent-Length: ");
	char *const length_end = strstr(length_value, "\r\n");
	T_CHECK(length_end != NULL);
	*length_end = '\0';
	size_t body_len = 0;
	T_CHECK(http_parse_content_length(length_value, &body_len));
	*length_end = '\r';
	char *const body = strstr(reqbuf, "\r\n\r\n") + 4;
	const size_t header_len = (size_t)(body - reqbuf);
	T_CHECK(body_len > 0 && body_len <= sizeof(reqbuf) - header_len);
	struct request_body_capture capture = {
		.fd = sv[1],
		.buf = reqbuf,
		.received = received,
		.total = header_len + body_len,
	};
	T_CHECK(test_wait_until(
		loop, request_body_complete, &capture, TEST_WAIT_RESPONSE_SEC));
	/* The sender's counter also catches bytes transmitted beyond the
	 * declared body, even when they arrive after the captured prefix. */
	T_EXPECT_EQ(stats.api_client_byt_send, capture.total);
	struct io_stream *const reader =
		content_reader(body, body_len, CENCODING_DEFLATE);
	T_CHECK(reader != NULL);
	unsigned char decoded[sizeof(payload) + 1];
	size_t decoded_len = sizeof(decoded);
	T_CHECK(io_stream_read(reader, decoded, &decoded_len) == 0);
	T_EXPECT_EQ(decoded_len, sizeof(payload));
	T_EXPECT_MEMEQ(decoded, payload, sizeof(payload));
	size_t extra = 1;
	T_CHECK(io_stream_read(reader, decoded, &extra) == 0);
	T_EXPECT_EQ(extra, 0);
	T_EXPECT_EQ(io_stream_close(reader), 0);

	/* respond so the exchange completes cleanly */
	T_CHECK(send_response(
		sv[1], "200 OK", MIME_RPCALL, "close", rsp_body,
		sizeof(rsp_body) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(out.called);
	T_EXPECT_EQ(out.errlen, 0);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

/* A Content-Encoding: deflate response body must be decoded before reaching
 * the caller (on_http_client_done's content_reader path). Every other case
 * returns identity-encoded bodies, so this decode path was unexercised. */
T_DECLARE_CASE(rpcall_deflate_response_is_decoded)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct cb_result out = { 0 };
	struct api_client_ctx *ctx = NULL;
	struct dialreq *req = NULL;
	int sv[2] = { -1, -1 };
	static const char payload[] = "{}";
	static const char plain[] = "decoded rpcall response body";
	struct vbuffer *cbuf = NULL;
	const struct api_client_cb cb = {
		.func = capture_cb,
		.data = &out,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();

	/* deflate-compress the known plaintext to use as the response body */
	struct io_stream *w =
		content_writer(&cbuf, sizeof(plain) - 1, CENCODING_DEFLATE);
	T_CHECK(w != NULL);
	size_t wn = sizeof(plain) - 1;
	T_CHECK(io_stream_write(w, plain, &wn) == 0);
	T_CHECK(wn == sizeof(plain) - 1);
	T_CHECK(io_stream_close(w) == 0);
	T_CHECK(cbuf != NULL);
	T_CHECK(VBUF_LEN(cbuf) > 0);

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(fd_set_nonblock(sv[0]));
	T_CHECK(fd_set_nonblock(sv[1]));
	S.dialer_result_fd = sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(send_encoded_response(
		sv[1], "200 OK", MIME_RPCALL, "deflate", VBUF_DATA(cbuf),
		VBUF_LEN(cbuf)));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(out.called);
	T_EXPECT_EQ(out.errlen, 0);
	T_EXPECT(out.has_stream);
	T_EXPECT_EQ(out.stream_len, sizeof(plain) - 1);
	T_EXPECT_MEMEQ(out.stream_buf, plain, sizeof(plain) - 1);

	VBUF_FREE(cbuf);
	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner (a trivial runner is used when ruleset is disabled).
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(rpcall_success_returns_stream),
	T_CASE(rpcall_threads_stats_counters),
	T_CASE(rpcall_chunked_response_reports_error),
	T_CASE(rpcall_close_delimited_response_reports_error),
	T_CASE(rpcall_no_content_without_length_is_empty),
	T_CASE(rpcall_success_empty_body_ok),
	T_CASE(invoke_uses_invoke_path),
	T_CASE(invoke_failure_is_logged),
	T_CASE(rpcall_request_build_failure_issues_nothing),
	T_CASE(rpcall_unsupported_content_type),
	T_CASE(rpcall_dialer_failure),
	T_CASE(rpcall_timeout),
	T_CASE(rpcall_http_error_status_line),
	T_CASE(rpcall_oom_building_error_still_reports_error),
	T_CASE(rpcall_structured_error_body),
	T_CASE(rpcall_structured_error_body_deflate_is_decoded),
	T_CASE(rpcall_structured_error_decode_oom_reports_error),
	T_CASE(cancel_during_connect_calls_dialer_cancel),
	T_CASE(cancel_after_success_drops_stream),
	T_CASE(cancel_after_error_drops_message),
	T_CASE(request_carries_host_header),
	T_CASE(request_advertises_connection_close),
	T_CASE(rpcall_write_error_reports_message),
	T_CASE(rpcall_large_payload_is_deflate_compressed),
	T_CASE(rpcall_interim_responses_deliver_final_result),
	T_CASE(rpcall_interim_response_requires_valid_final_response),
	T_CASE(rpcall_deflate_response_is_decoded),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	/* Ignore SIGPIPE: write to closed peer returns EPIPE instead of killing
	 * the process; MSYS2/Cygwin emulation raises it on close/write races. */
	const struct sigaction ignore = { .sa_handler = SIG_IGN };
	(void)sigaction(SIGPIPE, &ignore, NULL);

	/* keep libev clear of the realloc fault injection (see above) */
	ev_set_allocator(ev_isolated_alloc);

	return testing_main(argc, argv, suite);
}

#else /* WITH_RULESET */

int main(void)
{
	return 0;
}

#endif /* WITH_RULESET */
