/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for api_client.c; mocked: dialer. */

#include "api_client.h"

#include "conf.h"
#include "dialer.h"
#include "proto/http.h"
#include "server.h"

#include "io/stream.h"
#include "meta/arraysize.h"
#include "utils/buffer.h"
#include "utils/gc.h"
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

static bool context_alloc_fail;

void *test_context_malloc(const size_t size)
{
	if (context_alloc_fail) {
		context_alloc_fail = false;
		return NULL;
	}
	return malloc(size);
}

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
	size_t errlen, errsum;
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
	out->errsum = 0;
	if (errmsg != NULL) {
		for (size_t i = 0; i < errlen; i++) {
			out->errsum += (unsigned char)errmsg[i];
		}
	}
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

/* A polling wakeup must not suppress default-priority idle completion. */
static void test_tick_start(struct ev_loop *loop, ev_timer *w)
{
	ev_timer_init(w, test_tick_cb, TEST_TICK_SEC, TEST_TICK_SEC);
	ev_set_priority(w, EV_MINPRI);
	ev_timer_start(loop, w);
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
	test_tick_start(loop, &w_tick);
	while (!watchdog.fired && !predicate(data)) {
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_tick);
	ev_timer_stop(loop, &w_timeout);
	return predicate(data);
}

struct idle_progress {
	ev_timer tick;
	bool called;
};

static void
idle_progress_prepare(struct ev_loop *loop, ev_prepare *w, const int revents)
{
	(void)revents;
	struct idle_progress *const progress = w->data;
	/* Keep the polling tick overdue on every iteration, without waiting. */
	ev_timer_stop(loop, &progress->tick);
	ev_timer_set(&progress->tick, -1.0, TEST_TICK_SEC);
	ev_timer_start(loop, &progress->tick);
}

static void
idle_progress_cb(struct ev_loop *loop, ev_idle *w, const int revents)
{
	(void)revents;
	struct idle_progress *const progress = w->data;
	progress->called = true;
	ev_idle_stop(loop, w);
}

static bool idle_progress_done(void *data)
{
	const struct idle_progress *const progress = data;
	return progress->called;
}

T_DECLARE_CASE(wait_tick_allows_idle_progress)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct idle_progress progress = { 0 };
	ev_prepare prepare;
	ev_idle idle;
	T_CHECK(loop != NULL);
	ev_prepare_init(&prepare, idle_progress_prepare);
	prepare.data = &progress;
	ev_idle_init(&idle, idle_progress_cb);
	idle.data = &progress;
	test_tick_start(loop, &progress.tick);
	ev_prepare_start(loop, &prepare);
	ev_idle_start(loop, &idle);
	const bool observed =
		test_wait_until(loop, idle_progress_done, &progress, 1.0);
	ev_idle_stop(loop, &idle);
	ev_prepare_stop(loop, &prepare);
	ev_timer_stop(loop, &progress.tick);
	ev_loop_destroy(loop);
	T_EXPECT(observed);
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
	test_tick_start(loop, &w_tick);
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

/* Fail the native allocations in response reader constructors after the
 * content buffer has been received. libev and the vbuffer interposer bypass
 * this hook so only the stream chain is counted. */
void *__real_malloc(size_t size);
void __real_free(void *ptr);

static size_t native_fail_at, native_calls, native_live;
static void *native_allocations[8];

void *__wrap_malloc(size_t size)
{
	if (native_fail_at != 0 && ++native_calls == native_fail_at) {
		return NULL;
	}
	void *const ptr = __real_malloc(size);
	if (native_fail_at != 0 && ptr != NULL) {
		for (size_t i = 0; i < ARRAY_SIZE(native_allocations); i++) {
			if (native_allocations[i] == NULL) {
				native_allocations[i] = ptr;
				native_live++;
				break;
			}
		}
	}
	return ptr;
}

void __wrap_free(void *ptr)
{
	if (ptr != NULL) {
		for (size_t i = 0; i < ARRAY_SIZE(native_allocations); i++) {
			if (native_allocations[i] == ptr) {
				native_allocations[i] = NULL;
				native_live--;
				break;
			}
		}
	}
	__real_free(ptr);
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
static size_t g_realloc_allocations, g_realloc_fail_at;

/* realloc() semantics over malloc()/free(), with an optional armed failure. */
static void *realloc_impl(void *ptr, const size_t size, const bool may_fail)
{
	/* realloc(ptr, 0) must free ptr even while a failure is armed, so the
	 * free path precedes the fault-injection check */
	if (size == 0) {
		free(ptr);
		return NULL;
	}
	if (may_fail && (g_realloc_fail ||
			 g_realloc_allocations + 1 == g_realloc_fail_at)) {
		return NULL;
	}
	void *const np = __real_malloc(size);
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

struct client_fixture {
	struct ev_loop *loop;
	struct api_client_ctx *ctx;
	struct cb_result out;
	struct server_stats stats;
	int sv[2];
	bool invoke;
	struct vbuffer *cbuf;
	struct io_stream *stream;
	char reqbuf[1024];
};

static unsigned fixture_cleanup_count;

static int fixture_close_peer(struct client_fixture *f)
{
	if (f->sv[1] == -1) {
		return 0;
	}
	const int result = close(f->sv[1]);
	f->sv[1] = -1;
	return result;
}

static int fixture_close_stream(struct client_fixture *f)
{
	struct io_stream *stream = f->stream;
	f->stream = NULL;
	return io_stream_close(stream);
}

static void fixture_finish(struct client_fixture *f)
{
	context_alloc_fail = false;
	native_fail_at = 0;
	g_realloc_fail_at = 0;
	g_realloc_fail = false;
	if (f->ctx != NULL) {
		api_client_cancel(f->loop, f->ctx);
		f->ctx = NULL;
	}
	/* Invokes expose no cancellation handle. This binary owns only its
	 * current request, so finalize it while its loop and counters survive. */
	if (f->invoke) {
		(void)gc_finalizeall();
		f->invoke = false;
	}
	if (f->stream != NULL) {
		T_CHECK(fixture_close_stream(f) == 0);
	}
	VBUF_FREE(f->cbuf);
	T_CHECK(fixture_close_peer(f) == 0);
	if (f->loop != NULL) {
		ev_loop_destroy(f->loop);
		f->loop = NULL;
	}
	logcap_stop();
}

static void fixture_cleanup(void *data)
{
	struct client_fixture *f = data;
	fixture_finish(f);
	reset_stub_state();
	free(f);
	fixture_cleanup_count++;
}

static struct client_fixture *fixture_new(struct testing_ctx *_t_)
{
	struct client_fixture *f = calloc(1, sizeof(*f));
	T_CHECK(f != NULL);
	f->sv[0] = f->sv[1] = -1;
	T_CLEANUP(fixture_cleanup, f);
	f->loop = ev_loop_new(0);
	T_CHECK(f->loop != NULL);
	return f;
}

static void fixture_capture_cb(
	struct api_client_ctx *ctx, struct ev_loop *loop, void *data,
	const char *errmsg, size_t errlen, struct io_stream *stream)
{
	struct client_fixture *f = data;
	f->ctx = NULL;
	capture_cb(ctx, loop, &f->out, errmsg, errlen, stream);
}

T_DECLARE_CASE(rpcall_success_returns_stream)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";
	static const char rsp_body[] = "ok";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(f->ctx != NULL);
	T_CHECK(read_request_headers(
		loop, f->sv[1], reqbuf, sizeof(reqbuf),
		TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(strstr(reqbuf, "POST /ruleset/rpcall HTTP/1.1") != NULL);
	T_CHECK(send_response(
		f->sv[1], "200 OK", MIME_RPCALL, "keep-alive", rsp_body,
		sizeof(rsp_body) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(f->out.called);
	T_EXPECT_EQ(f->out.errlen, 0);
	T_EXPECT(f->out.errmsg[0] == '\0');
	T_EXPECT(f->out.has_stream);
	T_EXPECT_EQ(f->out.stream_len, sizeof(rsp_body) - 1);
	T_EXPECT_MEMEQ(f->out.stream_buf, rsp_body, sizeof(rsp_body) - 1);
	/* no stats means no counters at all */
	T_EXPECT(S.dialer_byt_sent == NULL);
	T_EXPECT(S.dialer_byt_recv == NULL);

	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
}

/* Each of the four byte counters must reach the server_stats field it names.
 * A transposed pair compiles clean and only shows up as wrong numbers in
 * /stats, so pin the wiring: the dialer's two by the identity of the pointers
 * it was handed, the connection's two by orientation -- the response here is
 * far larger than the request, so a swapped recv/sent pair cannot pass. */
T_DECLARE_CASE(rpcall_threads_stats_counters)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	char reqbuf[512] = { 0 };
	char rsp_body[1024];
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};
	const struct api_client_opts opts = {
		.conf = &test_conf,
		.stats = &f->stats,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	(void)memset(rsp_body, 'x', sizeof(rsp_body));
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb, &opts));
	T_CHECK(f->ctx != NULL);
	T_EXPECT(S.dialer_byt_sent == &f->stats.byt_dial_send);
	T_EXPECT(S.dialer_byt_recv == &f->stats.byt_dial_recv);
	T_CHECK(read_request_headers(
		loop, f->sv[1], reqbuf, sizeof(reqbuf),
		TEST_WAIT_RESPONSE_SEC));
	T_CHECK(send_response(
		f->sv[1], "200 OK", MIME_RPCALL, "keep-alive", rsp_body,
		sizeof(rsp_body)));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(f->out.called);
	T_EXPECT_EQ(f->out.errlen, 0);
	T_EXPECT_EQ(f->stats.num_api_client_request, 1);
	T_EXPECT(f->stats.api_client_byt_recv > sizeof(rsp_body));
	T_EXPECT(f->stats.api_client_byt_send > 0);
	T_EXPECT(f->stats.api_client_byt_send < sizeof(rsp_body));

	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
}

T_DECLARE_CASE(rpcall_chunked_response_reports_error)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
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
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(f->ctx != NULL);
	T_CHECK(read_request_headers(
		loop, f->sv[1], reqbuf, sizeof(reqbuf),
		TEST_WAIT_RESPONSE_SEC));
	T_CHECK(write_all(f->sv[1], resp, sizeof(resp) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(f->out.called);
	/* an error, not a silent empty-body success */
	T_EXPECT(f->out.errlen > 0);
	T_EXPECT(!f->out.has_stream);
	T_EXPECT(strstr(f->out.errmsg, "chunked") != NULL);

	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
}

/* Run one rpcall against a peer that answers with the raw bytes of `resp`
 * and then closes, and capture what the callback reports. */
T_DECLARE_SUBCASE(
	rpcall_raw_response, const char *restrict resp, const size_t resplen,
	struct cb_result *restrict out)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(read_request_headers(
		loop, f->sv[1], reqbuf, sizeof(reqbuf),
		TEST_WAIT_RESPONSE_SEC));
	T_CHECK(write_all(f->sv[1], resp, resplen));
	T_CHECK(fixture_close_peer(f) == 0);
	T_EXPECT(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC));

	*out = f->out;
	fixture_finish(f);
}

T_DECLARE_CASE(rpcall_malformed_status_reports_protocol_error)
{
	static const char *const codes[] = {
		"200junk", "+200", "-200", "0200",
		"2000",	   "20",   "2",	   "a00",
		"2a0",	   "20a",  "0xC8", "200000000000000000000000",
	};
	for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); i++) {
		struct cb_result out = { 0 };
		char response[256];
		const int n = snprintf(
			response, sizeof(response),
			"HTTP/1.1 %s OK\r\nContent-Type: " MIME_RPCALL "\r\n"
			"Content-Length: 2\r\nConnection: close\r\n\r\nok",
			codes[i]);
		T_CHECK(n > 0 && (size_t)n < sizeof(response));
		T_CALL_SUBCASE(rpcall_raw_response, response, (size_t)n, &out);
		T_EXPECT(out.called);
		T_EXPECT(!out.has_stream);
		T_EXPECT(out.errlen > 0);
		T_EXPECT_STREQ(out.errmsg, "error receiving response");
	}
}

T_DECLARE_CASE(rpcall_malformed_interim_status_reports_protocol_error)
{
	struct cb_result out = { 0 };
	static const char response[] =
		"HTTP/1.1 103junk Early Hints\r\n\r\n"
		"HTTP/1.1 200 OK\r\nContent-Type: " MIME_RPCALL "\r\n"
		"Content-Length: 2\r\n\r\nok";
	T_CALL_SUBCASE(
		rpcall_raw_response, response, sizeof(response) - 1, &out);
	T_EXPECT(out.called);
	T_EXPECT(!out.has_stream);
	T_EXPECT_STREQ(out.errmsg, "error receiving response");
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
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(f->ctx != NULL);
	T_CHECK(read_request_headers(
		loop, f->sv[1], reqbuf, sizeof(reqbuf),
		TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(strstr(reqbuf, "POST /ruleset/rpcall HTTP/1.1") != NULL);
	/* Regression: a 2xx rpcall response with Content-Length: 0 leaves the
	 * content vbuffer unallocated (NULL); this must not crash the caller. */
	T_CHECK(send_response(
		f->sv[1], "200 OK", MIME_RPCALL, "keep-alive", NULL, 0));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(f->out.called);
	T_EXPECT_EQ(f->out.errlen, 0);
	T_EXPECT(f->out.errmsg[0] == '\0');
	T_EXPECT(f->out.has_stream);
	T_EXPECT_EQ(f->out.stream_len, 0);

	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
}

T_DECLARE_CASE(invoke_uses_invoke_path)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	struct fd_closed_ctx closed_ctx = { 0 };
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	f->invoke = true;
	api_client_invoke(loop, req, payload, sizeof(payload) - 1, &test_opts);
	T_CHECK(read_request_headers(
		loop, f->sv[1], reqbuf, sizeof(reqbuf),
		TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(strstr(reqbuf, "POST /ruleset/invoke HTTP/1.1") != NULL);
	T_CHECK(send_response(
		f->sv[1], "204 No Content", NULL, "close", NULL, 0));
	closed_ctx.fd = f->sv[1];
	T_CHECK(test_wait_until(
		loop, fd_closed_predicate, &closed_ctx,
		TEST_WAIT_RESPONSE_SEC));

	/* Peer EOF can precede the deferred process callback. Run that callback
	 * before destroying the loop. Count and release any abandoned context
	 * while its loop still exists, so a failed check also cleans up safely. */
	const int active = ev_run(loop, EVRUN_NOWAIT);
	const unsigned int pending = ev_pending_count(loop);
	const size_t abandoned = gc_finalizeall();
	const int close_result = fixture_close_peer(f);
	fixture_finish(f);

	T_EXPECT_EQ(active, 0);
	T_EXPECT_EQ(pending, 0u);
	T_EXPECT_EQ(abandoned, (size_t)0);
	T_EXPECT_EQ(close_result, 0);
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
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	const struct api_client_opts opts = {
		.conf = &test_conf,
		.stats = &f->stats,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	S.dialer_result_fd = -1;
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	logcap_start(LOG_LEVEL_WARNING);
	f->invoke = true;
	api_client_invoke(loop, req, payload, sizeof(payload) - 1, &opts);
	const bool logged = test_wait_until(
		loop, logcap_has_invoke_error, NULL, TEST_WAIT_SHORT_SEC);
	logcap_stop();

	T_CHECK(logged);
	T_EXPECT(strstr(g_logcap.buf, "api invoke: connection failed") != NULL);
	T_EXPECT_EQ(S.dialer_do_calls, 1);
	T_EXPECT_EQ(f->stats.num_api_client_request, 1);

	fixture_finish(f);
}

/*
 * A request whose body cannot be built is never issued: api_client_do() must
 * report the failure, free the dialreq itself (nothing downstream consumes it),
 * leave *pctx alone, and leave the request counter where it was -- it counts
 * requests that went out, not requests that were attempted.
 */
T_DECLARE_CASE(rpcall_request_build_failure_issues_nothing)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	static const char payload[RPCALL_COMPRESS_THRESHOLD + 1] = { 0 };
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};
	const struct api_client_opts opts = {
		.conf = &test_conf,
		.stats = &f->stats,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	/* fail every allocation, so content_writer() cannot reserve the request
	 * body buffer and make_request() gives up before anything is sent */
	g_realloc_fail = true;
	const bool ok = api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb, &opts);
	g_realloc_fail = false;

	T_EXPECT(!ok);
	T_EXPECT(f->ctx == NULL);
	T_EXPECT_EQ(S.dialreq_free_calls, 1);
	T_EXPECT_EQ(S.dialer_do_calls, 0);
	T_EXPECT_EQ(f->stats.num_api_client_request, 0);
	T_EXPECT(!f->out.called);

	fixture_finish(f);
}

T_DECLARE_CASE(rpcall_unsupported_content_type)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	static const char rsp_body[] = "x";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(send_response(
		f->sv[1], "200 OK", "text/plain", "keep-alive", rsp_body,
		sizeof(rsp_body) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(f->out.called);
	T_EXPECT_STREQ(f->out.errmsg, "unsupported content-type");
	T_EXPECT(!f->out.has_stream);

	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
}

T_DECLARE_CASE(rpcall_dialer_failure)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	S.dialer_result_fd = -1;
	S.dialer_defer = true;
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(S.pending_dialer != NULL);
	const size_t allocations = g_realloc_allocations;
	g_realloc_fail = true;
	const struct dialer_cb done = S.pending_dialer->finish_cb;
	S.pending_dialer = NULL;
	S.pending_loop = NULL;
	done.func(loop, done.data, -1);
	T_EXPECT(!f->out.called);
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_SHORT_SEC));
	g_realloc_fail = false;
	T_EXPECT_EQ(g_realloc_allocations, allocations);
	T_EXPECT(f->out.called);
	T_EXPECT_STREQ(f->out.errmsg, "connection failed");
	T_EXPECT_EQ(S.dialer_do_calls, 1);

	fixture_finish(f);
}

T_DECLARE_CASE(rpcall_timeout)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	/* A zero timeout arms the request deadline to fire on the next event-loop
	 * iteration, so the "timeout" result is reached deterministically without
	 * waiting out a real wall-clock deadline. */
	test_conf.timeout = 0;
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_LONG_SEC));
	T_EXPECT(f->out.called);
	T_EXPECT_STREQ(f->out.errmsg, "timeout");

	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
}

T_DECLARE_CASE(rpcall_http_error_status_line)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(send_response(
		f->sv[1], "404 Not Found", NULL, "close", NULL, 0));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(f->out.called);
	T_EXPECT(strstr(f->out.errmsg, "404") != NULL);

	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
}

/* Generic HTTP diagnostics remain exact even when body allocation fails. */
T_DECLARE_CASE(rpcall_status_diagnostic_needs_no_body_allocation)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(send_response(
		f->sv[1], "404 Not Found", NULL, "close", NULL, 0));

	/* A bounded status diagnostic uses context storage even with vbuffer
	 * allocation disabled. */
	g_realloc_fail = true;
	const bool waited = test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC);
	g_realloc_fail = false;

	T_CHECK(waited);
	T_EXPECT(f->out.called);
	/* the error must be reported, never delivered as a NULL/NULL success */
	T_EXPECT(f->out.errlen > 0);
	T_EXPECT(!f->out.has_stream);
	T_EXPECT_STREQ(f->out.errmsg, "HTTP/1.1 404 Not Found");

	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
}

T_DECLARE_CASE(rpcall_structured_error_body)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	static const char rsp_body[] = "backend failed";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(send_response(
		f->sv[1], "500 Internal Server Error", MIME_RPCALL, "close",
		rsp_body, sizeof(rsp_body) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(f->out.called);
	T_EXPECT_EQ(f->out.errlen, sizeof(rsp_body) - 1);
	T_EXPECT_STREQ(f->out.errmsg, rsp_body);
	T_EXPECT(!f->out.has_stream);

	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
}

/* A structured (rpcall-MIME) error body carrying Content-Encoding: deflate must
 * be decoded before reaching the caller, mirroring the success path; otherwise
 * the raw compressed bytes were delivered as the error message. */
T_DECLARE_CASE(rpcall_structured_error_body_deflate_is_decoded)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	static const char plain[] = "backend failed: structured error detail";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();

	/* deflate-compress the known error text to use as the response body */
	struct io_stream *w =
		content_writer(&f->cbuf, sizeof(plain) - 1, CENCODING_DEFLATE);
	T_CHECK(w != NULL);
	size_t wn = sizeof(plain) - 1;
	T_CHECK(io_stream_write(w, plain, &wn) == 0);
	T_CHECK(wn == sizeof(plain) - 1);
	T_CHECK(io_stream_close(w) == 0);
	T_CHECK(f->cbuf != NULL);
	T_CHECK(VBUF_LEN(f->cbuf) > 0);

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(send_encoded_response(
		f->sv[1], "500 Internal Server Error", MIME_RPCALL, "deflate",
		VBUF_DATA(f->cbuf), VBUF_LEN(f->cbuf)));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(f->out.called);
	/* the decoded plain text, not the raw deflate bytes */
	T_EXPECT_EQ(f->out.errlen, sizeof(plain) - 1);
	T_EXPECT_STREQ(f->out.errmsg, plain);
	T_EXPECT(!f->out.has_stream);

	VBUF_FREE(f->cbuf);
	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
}

enum reader_failure {
	READER_BUFFER_OOM,
	READER_BASE_OOM,
	READER_CODEC_OOM,
	READER_GROW_OOM,
	READER_BAD_HEADER,
	READER_BAD_TRAILER,
	READER_OK,
	READER_LARGE_OK,
};

/* Receive the backing body first, then isolate a constructor, decoded buffer,
 * or format failure. Successful chains record their native allocations. */
T_DECLARE_SUBCASE(
	check_response_reader_fault, const enum reader_failure failure,
	const bool structured, const enum content_encodings encoding)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	static const char plain[] = "backend failed: structured error detail";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};
	const struct api_client_opts opts = {
		.conf = &test_conf,
		.stats = &f->stats,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();

	char large[8192];
	memset(large, 'x', sizeof(large));
	const bool large_text =
		failure == READER_GROW_OOM || failure == READER_LARGE_OK;
	const size_t plainlen = large_text ? sizeof(large) : sizeof(plain) - 1;
	const void *const text =
		large_text ? (const void *)large : (const void *)plain;
	struct io_stream *w = content_writer(&f->cbuf, plainlen, encoding);
	T_CHECK(w != NULL);
	size_t wn = plainlen;
	T_CHECK(io_stream_write(w, text, &wn) == 0);
	T_CHECK(wn == plainlen);
	T_CHECK(io_stream_close(w) == 0);
	T_CHECK(f->cbuf != NULL);
	T_CHECK(VBUF_LEN(f->cbuf) > 0);
	if (failure == READER_BAD_HEADER) {
		f->cbuf->data[0] ^= 0xff;
	} else if (failure == READER_BAD_TRAILER) {
		f->cbuf->data[f->cbuf->len - 1] ^= 0xff;
	}

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb, &opts));
	char reqbuf[512];
	T_CHECK(read_request_headers(
		loop, f->sv[1], reqbuf, sizeof(reqbuf),
		TEST_WAIT_RESPONSE_SEC));

	/* Allocate and receive the backing content before arming the selected
	 * reader-constructor or decoded-buffer failure. */
	char encoding_header[64] = "";
	if (encoding != CENCODING_NONE) {
		(void)snprintf(
			encoding_header, sizeof(encoding_header),
			"Content-Encoding: %s\r\n",
			http_content_encoding_str[encoding]);
	}
	unsigned char resp[512];
	const int hn = snprintf(
		(char *)resp, sizeof(resp),
		"HTTP/1.1 %s\r\n"
		"Content-Type: %s\r\n"
		"%s"
		"Connection: close\r\n"
		"Content-Length: %zu\r\n\r\n",
		structured ? "500 Internal Server Error" : "200 OK",
		MIME_RPCALL, encoding_header, VBUF_LEN(f->cbuf));
	T_CHECK(hn > 0);
	const size_t total = (size_t)hn + VBUF_LEN(f->cbuf);
	T_CHECK(total <= sizeof(resp) && VBUF_LEN(f->cbuf) >= 1);
	memcpy(resp + hn, VBUF_DATA(f->cbuf), VBUF_LEN(f->cbuf));

	/* Phase 1: deliver everything but the last body byte and let the client
	 * parse the headers and allocate its content buffer while allocations
	 * still succeed. The response stays incomplete, so the callback does not
	 * fire. */
	const struct response_phase phase = {
		.stats = &f->stats,
		.result = &f->out,
		.received = total - 1,
		.allocations = g_realloc_allocations,
	};
	T_CHECK(write_all(f->sv[1], resp, total - 1));
	T_CHECK(test_wait_until(
		loop, response_phase_consumed, (void *)&phase,
		TEST_WAIT_RESPONSE_SEC));
	T_CHECK(!f->out.called);
	T_EXPECT_EQ(f->stats.api_client_byt_recv, total - 1);
	T_EXPECT(g_realloc_allocations > phase.allocations);

	/* Finish the response with either its decoded buffer allocation or a
	 * native stream constructor failing. */
	g_realloc_fail = failure == READER_BUFFER_OOM;
	if (failure == READER_GROW_OOM) {
		g_realloc_fail_at = g_realloc_allocations + 2;
	}
	native_calls = native_live = 0;
	native_fail_at = 0;
	if (failure == READER_OK || failure == READER_LARGE_OK) {
		native_fail_at = SIZE_MAX;
	} else if (failure == READER_BASE_OOM || failure == READER_CODEC_OOM) {
		native_fail_at = (size_t)failure;
	}
	T_CHECK(write_all(f->sv[1], resp + total - 1, 1));
	const bool waited = test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC);
	g_realloc_fail = false;
	g_realloc_fail_at = 0;
	native_fail_at = 0;

	T_CHECK(waited);
	T_EXPECT(f->out.called);
	if (failure == READER_OK || failure == READER_LARGE_OK) {
		T_EXPECT_EQ(
			native_calls,
			encoding == CENCODING_NONE ? (size_t)1 : (size_t)2);
		if (structured && failure == READER_LARGE_OK) {
			T_EXPECT_EQ(f->out.errlen, sizeof(large));
			T_EXPECT_EQ(f->out.errsum, sizeof(large) * (size_t)'x');
		} else if (structured) {
			T_EXPECT_STREQ(f->out.errmsg, plain);
		} else {
			T_EXPECT_EQ(f->out.errlen, (size_t)0);
			T_EXPECT(f->out.has_stream);
			T_EXPECT_EQ(f->out.stream_len, sizeof(plain) - 1);
			T_EXPECT_MEMEQ(
				f->out.stream_buf, plain, sizeof(plain) - 1);
		}
	} else {
		T_EXPECT(f->out.errlen > 0);
		T_EXPECT(!f->out.has_stream);
		T_EXPECT_STREQ(
			f->out.errmsg, structured ?
					       "cannot decode error content" :
					       "out of memory");
		if (failure == READER_BASE_OOM || failure == READER_CODEC_OOM) {
			T_EXPECT_EQ(native_calls, (size_t)failure);
		}
	}
	T_EXPECT_EQ(native_live, (size_t)0);
	T_EXPECT_EQ(gc_finalizeall(), (size_t)0);

	VBUF_FREE(f->cbuf);
	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
}

T_DECLARE_CASE(rpcall_structured_error_decode_oom_reports_error)
{
	T_CALL_SUBCASE(
		check_response_reader_fault, READER_BUFFER_OOM, true,
		CENCODING_DEFLATE);
}

T_DECLARE_CASE(rpcall_response_reader_native_allocation_failures)
{
	T_CALL_SUBCASE(
		check_response_reader_fault, READER_BASE_OOM, false,
		CENCODING_NONE);
	T_CALL_SUBCASE(
		check_response_reader_fault, READER_OK, false, CENCODING_NONE);
	T_CALL_SUBCASE(
		check_response_reader_fault, READER_OK, false,
		CENCODING_DEFLATE);
	T_CALL_SUBCASE(
		check_response_reader_fault, READER_OK, true,
		CENCODING_DEFLATE);
	T_CALL_SUBCASE(
		check_response_reader_fault, READER_OK, false, CENCODING_GZIP);
	T_CALL_SUBCASE(
		check_response_reader_fault, READER_OK, true, CENCODING_GZIP);
	for (size_t fail_at = 1; fail_at <= 2; fail_at++) {
		T_CALL_SUBCASE(
			check_response_reader_fault,
			(enum reader_failure)fail_at, false, CENCODING_DEFLATE);
		T_CALL_SUBCASE(
			check_response_reader_fault,
			(enum reader_failure)fail_at, true, CENCODING_DEFLATE);
		T_CALL_SUBCASE(
			check_response_reader_fault,
			(enum reader_failure)fail_at, false, CENCODING_GZIP);
		T_CALL_SUBCASE(
			check_response_reader_fault,
			(enum reader_failure)fail_at, true, CENCODING_GZIP);
	}
}

T_DECLARE_CASE(rpcall_structured_decode_growth_and_format_failures)
{
	T_CALL_SUBCASE(
		check_response_reader_fault, READER_LARGE_OK, true,
		CENCODING_DEFLATE);
	T_CALL_SUBCASE(
		check_response_reader_fault, READER_LARGE_OK, true,
		CENCODING_GZIP);
	for (enum reader_failure failure = READER_GROW_OOM;
	     failure <= READER_BAD_TRAILER; failure++) {
		T_CALL_SUBCASE(
			check_response_reader_fault, failure, true,
			CENCODING_DEFLATE);
		T_CALL_SUBCASE(
			check_response_reader_fault, failure, true,
			CENCODING_GZIP);
	}
}

T_DECLARE_CASE(cancel_during_connect_calls_dialer_cancel)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	S.dialer_defer = true;
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(f->ctx != NULL);
	api_client_cancel(loop, f->ctx);
	f->ctx = NULL;
	T_EXPECT_EQ(S.dialer_cancel_calls, 1);
	T_EXPECT(!f->out.called);

	fixture_finish(f);
}

/* Complete an rpcall with `resp`, then cancel it after the exchange finished
 * but before the deferred callback ran -- the window in which a ruleset
 * coroutine closed early cancels a finished request. The callback must never
 * fire, and the recorded result must be released (the sanitizer builds catch
 * a leak or a dispatch onto the freed request). */
T_DECLARE_SUBCASE(cancel_after_response, const char *restrict resp)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	struct fd_closed_ctx closed_ctx = { 0 };
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(f->ctx != NULL);
	T_CHECK(read_request_headers(
		loop, f->sv[1], reqbuf, sizeof(reqbuf),
		TEST_WAIT_RESPONSE_SEC));
	T_CHECK(write_all(f->sv[1], resp, strlen(resp)));
	/* the client closes its socket in the same callback that records the
	 * result and defers the user callback, which the loop dispatches no
	 * earlier than its next iteration */
	closed_ctx.fd = f->sv[1];
	T_CHECK(test_wait_until(
		loop, fd_closed_predicate, &closed_ctx,
		TEST_WAIT_RESPONSE_SEC));
	T_CHECK(!f->out.called);

	api_client_cancel(loop, f->ctx);
	f->ctx = NULL;
	T_EXPECT(!test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_SHORT_SEC));
	T_EXPECT(!f->out.called);

	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
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
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";
	static const char host[] = "api.example";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);
	req->addr.type = ATYP_DOMAIN;
	req->addr.port = 9080;
	req->addr.domain.len = (uint_least8_t)(sizeof(host) - 1);
	(void)memcpy(req->addr.domain.name, host, sizeof(host) - 1);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(read_request_headers(
		loop, f->sv[1], reqbuf, sizeof(reqbuf),
		TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(strstr(reqbuf, "\r\nHost: api.example:9080\r\n") != NULL);

	T_CHECK(send_response(
		f->sv[1], "204 No Content", MIME_RPCALL, "close", NULL, 0));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(f->out.called);

	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
}

/* The client never pools connections, so every request advertises
 * Connection: close and the exchange completes regardless of what the peer
 * offers in its own Connection header. */
T_DECLARE_CASE(request_advertises_connection_close)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	char reqbuf[512] = { 0 };
	static const char payload[] = "{}";
	static const char rsp_body[] = "ok";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(read_request_headers(
		loop, f->sv[1], reqbuf, sizeof(reqbuf),
		TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(strstr(reqbuf, "Connection: close") != NULL);
	T_EXPECT(strstr(reqbuf, "keep-alive") == NULL);

	/* peer offers keep-alive; the client must still finish normally */
	T_CHECK(send_response(
		f->sv[1], "200 OK", MIME_RPCALL, "keep-alive", rsp_body,
		sizeof(rsp_body) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(f->out.called);
	T_EXPECT_EQ(f->out.errlen, 0);

	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
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
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fixture_close_peer(f) == 0);
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(f->out.called);
	T_EXPECT(f->out.errlen > 0);
	T_EXPECT(f->out.errmsg[0] != '\0');
	T_EXPECT_EQ(S.dialer_do_calls, 1);

	fixture_finish(f);
}

/* Plain requests need no body allocation; threshold-sized and larger ones
 * retain compression and exact binary payloads. */
T_DECLARE_SUBCASE(check_request_body, const size_t payloadlen)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;

	unsigned char payload[RPCALL_COMPRESS_THRESHOLD + 64];
	static const char rsp_body[] = "ok";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};
	const struct api_client_opts opts = {
		.conf = &test_conf,
		.stats = &f->stats,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();
	/* Include binary bytes in both representations. */
	for (size_t i = 0; i < sizeof(payload); i++) {
		payload[i] = (unsigned char)i;
	}
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	const size_t allocations = g_realloc_allocations;
	g_realloc_fail = payloadlen < RPCALL_COMPRESS_THRESHOLD;
	const bool started = api_client_rpcall(
		loop, &f->ctx, req, payload, payloadlen, &cb, &opts);
	g_realloc_fail = false;
	if (!started) {
		T_CHECK(close(f->sv[0]) == 0);
		f->sv[0] = -1;
	}
	T_CHECK(started);
	if (payloadlen < RPCALL_COMPRESS_THRESHOLD) {
		T_EXPECT_EQ(g_realloc_allocations, allocations);
	}
	size_t received = 0;
	T_CHECK(read_request_headers_with_size(
		loop, f->sv[1], f->reqbuf, sizeof(f->reqbuf),
		TEST_WAIT_RESPONSE_SEC, &received));
	T_EXPECT(strstr(f->reqbuf, "POST /ruleset/rpcall HTTP/1.1") != NULL);
	const bool compressed = payloadlen >= RPCALL_COMPRESS_THRESHOLD;
	T_EXPECT(
		(strstr(f->reqbuf, "Content-Encoding: deflate") != NULL) ==
		compressed);
	char *const length_header = strstr(f->reqbuf, "\r\nContent-Length: ");
	T_CHECK(length_header != NULL);
	char *const length_value =
		length_header + strlen("\r\nContent-Length: ");
	char *const length_end = strstr(length_value, "\r\n");
	T_CHECK(length_end != NULL);
	*length_end = '\0';
	size_t body_len = 0;
	T_CHECK(http_parse_content_length(length_value, &body_len));
	*length_end = '\r';
	char *const body = strstr(f->reqbuf, "\r\n\r\n") + 4;
	const size_t header_len = (size_t)(body - f->reqbuf);
	T_CHECK(body_len <= sizeof(f->reqbuf) - header_len);
	struct request_body_capture capture = {
		.fd = f->sv[1],
		.buf = f->reqbuf,
		.received = received,
		.total = header_len + body_len,
	};
	T_CHECK(test_wait_until(
		loop, request_body_complete, &capture, TEST_WAIT_RESPONSE_SEC));
	/* The sender's counter also catches bytes transmitted beyond the
	 * declared body, even when they arrive after the captured prefix. */
	T_EXPECT_EQ(f->stats.api_client_byt_send, capture.total);
	f->stream = content_reader(
		body, body_len,
		compressed ? CENCODING_DEFLATE : CENCODING_NONE);
	T_CHECK(f->stream != NULL);
	unsigned char decoded[sizeof(payload) + 1];
	size_t decoded_len = sizeof(decoded);
	T_CHECK(io_stream_read(f->stream, decoded, &decoded_len) == 0);
	T_EXPECT_EQ(decoded_len, payloadlen);
	T_EXPECT_MEMEQ(decoded, payload, payloadlen);
	size_t extra = 1;
	T_CHECK(io_stream_read(f->stream, decoded, &extra) == 0);
	T_EXPECT_EQ(extra, 0);
	T_EXPECT_EQ(fixture_close_stream(f), 0);

	/* respond so the exchange completes cleanly */
	T_CHECK(send_response(
		f->sv[1], "200 OK", MIME_RPCALL, "close", rsp_body,
		sizeof(rsp_body) - 1));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC));
	T_EXPECT(f->out.called);
	T_EXPECT_EQ(f->out.errlen, 0);

	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
}

T_DECLARE_CASE(rpcall_payload_boundaries_preserve_bytes_and_framing)
{
	static const size_t lengths[] = {
		0,
		1,
		RPCALL_COMPRESS_THRESHOLD - 1,
		RPCALL_COMPRESS_THRESHOLD,
		RPCALL_COMPRESS_THRESHOLD + 64,
	};
	for (size_t i = 0; i < sizeof(lengths) / sizeof(*lengths); i++) {
		T_CALL_SUBCASE(check_request_body, lengths[i]);
	}
}

/* A Content-Encoding: deflate response body must be decoded before reaching
 * the caller (on_http_client_done's content_reader path). Every other case
 * returns identity-encoded bodies, so this decode path was unexercised. */
T_DECLARE_CASE(rpcall_deflate_response_is_decoded)
{
	struct client_fixture *f = fixture_new(_t_);
	struct ev_loop *loop = f->loop;
	struct dialreq *req = NULL;
	static const char payload[] = "{}";
	static const char plain[] = "decoded rpcall response body";
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};

	T_CHECK(loop != NULL);
	reset_stub_state();

	/* deflate-compress the known plaintext to use as the response body */
	struct io_stream *w =
		content_writer(&f->cbuf, sizeof(plain) - 1, CENCODING_DEFLATE);
	T_CHECK(w != NULL);
	size_t wn = sizeof(plain) - 1;
	T_CHECK(io_stream_write(w, plain, &wn) == 0);
	T_CHECK(wn == sizeof(plain) - 1);
	T_CHECK(io_stream_close(w) == 0);
	T_CHECK(f->cbuf != NULL);
	T_CHECK(VBUF_LEN(f->cbuf) > 0);

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	S.dialer_result_fd = f->sv[0];
	req = new_test_dialreq();
	T_CHECK(req != NULL);

	T_CHECK(api_client_rpcall(
		loop, &f->ctx, req, payload, sizeof(payload) - 1, &cb,
		&test_opts));
	T_CHECK(send_encoded_response(
		f->sv[1], "200 OK", MIME_RPCALL, "deflate", VBUF_DATA(f->cbuf),
		VBUF_LEN(f->cbuf)));
	T_CHECK(test_wait_until(
		loop, cb_called_predicate, &f->out, TEST_WAIT_RESPONSE_SEC));

	T_EXPECT(f->out.called);
	T_EXPECT_EQ(f->out.errlen, 0);
	T_EXPECT(f->out.has_stream);
	T_EXPECT_EQ(f->out.stream_len, sizeof(plain) - 1);
	T_EXPECT_MEMEQ(f->out.stream_buf, plain, sizeof(plain) - 1);

	VBUF_FREE(f->cbuf);
	T_CHECK(fixture_close_peer(f) == 0);
	fixture_finish(f);
}

/* Exercise cleanup after aborting at each request ownership boundary. */
static int failure_peer, failure_socket;
static unsigned failure_phase;

T_DECLARE_CASE(api_client_fixture_intentional_failure)
{
	struct client_fixture *f = fixture_new(_t_);
	reset_stub_state();
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv) == 0);
	T_CHECK(fd_set_nonblock(f->sv[0]));
	T_CHECK(fd_set_nonblock(f->sv[1]));
	failure_socket = f->sv[0];
	failure_peer = f->sv[1];
	S.dialer_result_fd = f->sv[0];
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};
	const struct api_client_opts opts = {
		.conf = &test_conf,
		.stats = &f->stats,
	};
	struct dialreq *req = new_test_dialreq();
	T_CHECK(req != NULL);
	if (failure_phase == 0) {
		/* No socket has been handed to a deferred dialer yet. */
		T_CHECK(close(f->sv[0]) == 0);
		S.dialer_result_fd = -1;
		S.dialer_defer = true;
	}
	if (failure_phase == 3) {
		f->invoke = true;
		api_client_invoke(f->loop, req, "{}", 2, &opts);
	} else {
		T_CHECK(api_client_rpcall(
			f->loop, &f->ctx, req, "{}", 2, &cb, &opts));
	}
	if (failure_phase == 2) {
		T_CHECK(send_response(
			f->sv[1], "200 OK", MIME_RPCALL, "close", "ok", 2));
		T_CHECK(test_wait_until(
			f->loop, cb_called_predicate, &f->out,
			TEST_WAIT_RESPONSE_SEC));
		T_CHECK(f->ctx == NULL);
	}
	/* These are test-owned, independent of the request's response stream. */
	f->stream = content_writer(&f->cbuf, 1024, CENCODING_DEFLATE);
	T_CHECK(f->stream != NULL);
	size_t len = 2;
	T_CHECK(io_stream_write(f->stream, "{}", &len) == 0);
	logcap_start(LOG_LEVEL_WARNING);
	g_realloc_fail = true;
	T_EXPECT(false);
}

T_DECLARE_CASE(api_client_failed_expectation_cleans_fixture)
{
	for (failure_phase = 0; failure_phase < 4; failure_phase++) {
		const unsigned before = fixture_cleanup_count;
		T_DECLARE_CTX(nested);
		T_RUN_CASE(nested, api_client_fixture_intentional_failure);
		T_EXPECT_EQ(nested.failed, 1);
		T_EXPECT_EQ(fixture_cleanup_count, before + 1);
		T_EXPECT_EQ(fcntl(failure_peer, F_GETFD), -1);
		T_EXPECT_EQ(errno, EBADF);
		T_EXPECT_EQ(fcntl(failure_socket, F_GETFD), -1);
		T_EXPECT_EQ(errno, EBADF);
		T_EXPECT(S.pending_dialer == NULL);
		T_EXPECT(S.pending_loop == NULL);
		T_EXPECT(S.dialer_byt_sent == NULL);
		T_EXPECT(S.dialer_byt_recv == NULL);
		T_EXPECT(!g_realloc_fail);
		T_EXPECT_EQ(gc_finalizeall(), (size_t)0);
		T_RUN_CASE(nested, rpcall_success_returns_stream);
		T_EXPECT_EQ(nested.passed, 1);
	}
}

T_DECLARE_CASE(context_allocation_failure)
{
	struct client_fixture *f = fixture_new(_t_);
	reset_stub_state();
	const struct api_client_cb cb = {
		.func = fixture_capture_cb,
		.data = f,
	};
	const struct api_client_opts opts = {
		.conf = &test_conf,
		.stats = &f->stats,
	};
	struct dialreq *req = new_test_dialreq();
	T_CHECK(req != NULL);
	context_alloc_fail = true;
	const bool ok =
		api_client_rpcall(f->loop, &f->ctx, req, "{}", 2, &cb, &opts);
	T_EXPECT(!context_alloc_fail);
	T_EXPECT(!ok);
	T_EXPECT(f->ctx == NULL);
	T_EXPECT(!f->out.called);
	T_EXPECT_EQ(S.dialreq_free_calls, 1);
	T_EXPECT_EQ(S.dialer_do_calls, 0);
	T_EXPECT(S.pending_dialer == NULL);
	T_EXPECT_EQ(f->stats.num_api_client_request, 0);
	T_EXPECT_EQ(gc_finalizeall(), 0);
	T_EXPECT_EQ(ev_run(f->loop, EVRUN_NOWAIT), 0);
}

T_DECLARE_CASE(context_allocation_failure_recovers)
{
	T_DECLARE_CTX(nested);
	T_RUN_CASE(nested, context_allocation_failure);
	T_EXPECT_EQ(nested.failed, 0);
	T_RUN_CASE(nested, rpcall_success_returns_stream);
	T_EXPECT_EQ(nested.failed, 0);
	T_EXPECT_EQ(nested.passed, 2);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner (a trivial runner is used when ruleset is disabled).
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(context_allocation_failure_recovers),
	T_CASE(api_client_failed_expectation_cleans_fixture),
	T_CASE(wait_tick_allows_idle_progress),
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
	T_CASE(rpcall_status_diagnostic_needs_no_body_allocation),
	T_CASE(rpcall_structured_error_body),
	T_CASE(rpcall_structured_error_body_deflate_is_decoded),
	T_CASE(rpcall_structured_error_decode_oom_reports_error),
	T_CASE(rpcall_response_reader_native_allocation_failures),
	T_CASE(rpcall_structured_decode_growth_and_format_failures),
	T_CASE(cancel_during_connect_calls_dialer_cancel),
	T_CASE(cancel_after_success_drops_stream),
	T_CASE(cancel_after_error_drops_message),
	T_CASE(request_carries_host_header),
	T_CASE(request_advertises_connection_close),
	T_CASE(rpcall_write_error_reports_message),
	T_CASE(rpcall_payload_boundaries_preserve_bytes_and_framing),
	T_CASE(rpcall_malformed_status_reports_protocol_error),
	T_CASE(rpcall_malformed_interim_status_reports_protocol_error),
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
