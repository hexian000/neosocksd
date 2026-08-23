/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for http_proxy.c; mocked: dialer, transfer, ruleset, server. */

#include "http_proxy.h"

#include "conf.h"
#include "dialer.h"
#include "ruleset/ruleset.h"
#include "server.h"
#include "transfer.h"

#include "meta/arraysize.h"
#include "os/socket.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * virtual clock - fire the connection idle/connect/process timeouts (ev_timers
 * inside production ctx structs the test cannot reach) deterministically, with
 * no wall-clock wait. The strong-symbol interposers return a test-advanced
 * virtual time while enabled and pass through to the real clock otherwise, so
 * non-timeout cases are unaffected.
 * ---------------------------------------------------------------------- */

static bool g_vclock_on = false;
static double g_vclock_sec = 0.0;

/* Read the real clock for the pass-through path. Both clock_gettime() and
 * gettimeofday() are interposed here, so the underlying clock has to be reached
 * through a third entry point: ISO C11 timespec_get(), which libc services from
 * its own internal clock rather than through the shadowed symbols. It is also
 * the only such entry point that stays declared under the strict
 * _POSIX_C_SOURCE the FORCE_POSIX build selects. */
static int real_clock(struct timespec *restrict ts)
{
	if (timespec_get(ts, TIME_UTC) != TIME_UTC) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

int clock_gettime(clockid_t clk, struct timespec *ts)
{
	if (g_vclock_on) {
		ts->tv_sec = (time_t)g_vclock_sec;
		ts->tv_nsec = (long)((g_vclock_sec - (double)ts->tv_sec) * 1e9);
		return 0;
	}
	(void)clk;
	return real_clock(ts);
}

int gettimeofday(struct timeval *tv, void *tz)
{
	if (g_vclock_on) {
		tv->tv_sec = (time_t)g_vclock_sec;
		tv->tv_usec = (long)((g_vclock_sec - (double)tv->tv_sec) * 1e6);
		return 0;
	}
	(void)tz;
	struct timespec ts;
	if (real_clock(&ts) != 0) {
		return -1;
	}
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = (long)(ts.tv_nsec / 1000);
	return 0;
}

/* Freeze virtual time at the current real instant. Engage it before the case
 * arms the timer under test, so both the arming and the crossing happen on
 * virtual time; a case that must first drive real-time reads engages it later
 * and instead keeps its timeout too large for real elapsed time to reach. */
static void vclock_freeze_now(void)
{
	struct timespec ts;
	T_CHECK(real_clock(&ts) == 0);
	g_vclock_sec = (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
	g_vclock_on = true;
}

static void vclock_advance(const double sec)
{
	g_vclock_sec += sec;
}

static void vclock_stop(void)
{
	g_vclock_on = false;
}

/* Watchers invoked during the current drive_loop() round, via a custom
 * invoke-pending callback, so a round that invokes none marks quiescence. */
static unsigned int g_drive_invoked;

static void drive_invoke_pending(struct ev_loop *loop)
{
	g_drive_invoked += ev_pending_count(loop);
	ev_invoke_pending(loop);
}

/* -------------------------------------------------------------------------
 * mock - collaborator stubs (dialer, transfer, ruleset, server) and shared fixtures.
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

/* test-only definition of struct globals, used to stub G.conf/G.ruleset */
struct globals {
	const struct config *conf;
	struct resolver *resolver;
	struct ruleset *ruleset;
	struct server *server;
	struct dialreq *basereq;
};

struct globals G = { 0 };

static struct config test_conf = {
	.timeout = 1.0,
	.auth_required = false,
};

/* Watchdog bound on the event-driven drive/read helpers: a hung-test backstop,
 * never a completion signal (completion is loop quiescence or a peer EOF). */
static const ev_tstamp TEST_WAIT_RECV_SEC = 0.128;

const char *const proxy_protocol_str[PROTO_MAX] = {
	[PROTO_HTTP] = "http",
	[PROTO_SOCKS4A] = "socks4a",
	[PROTO_SOCKS5] = "socks5",
};

struct stub_state {
	bool dialreq_new_ok;
	bool dialaddr_parse_ok;
	bool dialer_invoke_now;
	int dialer_result_fd;
	enum dialer_error dialer_err;
	int dialer_syserr;
	int_least32_t dialreq_free_calls;
	int_least32_t dialreq_invalid_free_calls;
	bool ruleset_resolve_ok;
	bool ruleset_reply_with_req;
	bool ruleset_finish_now;
	bool ruleset_state_nonnull;
	struct ev_loop *ruleset_loop;
	struct ruleset_state *ruleset_state_ptr;
	/* the ctx's callback and the ctx->ruleset_state slot, captured at
	 * dispatch so a case can emulate the ruleset completing out of band */
	struct ruleset_callback *ruleset_cb_ptr;
	struct ruleset_state **ruleset_state_slot;
	int_least32_t ruleset_cancel_calls;
	int_least32_t dialer_cancel_calls;
	int_least32_t dialer_do_calls;
	bool captured_creds;
	char captured_username[64];
	char captured_password[64];
};

static struct stub_state S = {
	.dialreq_new_ok = false,
	.dialaddr_parse_ok = false,
	.dialer_invoke_now = true,
	.dialer_result_fd = -1,
	.dialer_err = DIALER_ERR_CONNECT,
	.dialer_syserr = ECONNREFUSED,
	.ruleset_resolve_ok = false,
	.ruleset_reply_with_req = false,
	.ruleset_finish_now = false,
	.ruleset_state_nonnull = false,
	.ruleset_loop = NULL,
	.ruleset_state_ptr = NULL,
	.ruleset_cb_ptr = NULL,
	.ruleset_state_slot = NULL,
	.ruleset_cancel_calls = 0,
	.dialer_cancel_calls = 0,
	.dialer_do_calls = 0,
};

static int_fast32_t ruleset_state_token = 0;
static struct dialreq *dialreq_allocations[32];
static size_t num_dialreq_allocations = 0;

static void reset_dialreq_allocations(void)
{
	num_dialreq_allocations = 0;
	memset((void *)dialreq_allocations, 0, sizeof(dialreq_allocations));
}

static void track_dialreq_allocation(struct dialreq *restrict req)
{
	T_CHECK(num_dialreq_allocations < ARRAY_SIZE(dialreq_allocations));
	dialreq_allocations[num_dialreq_allocations++] = req;
}

static bool untrack_dialreq_allocation(struct dialreq *restrict req)
{
	for (size_t i = 0; i < num_dialreq_allocations; i++) {
		if (dialreq_allocations[i] != req) {
			continue;
		}
		num_dialreq_allocations--;
		dialreq_allocations[i] =
			dialreq_allocations[num_dialreq_allocations];
		dialreq_allocations[num_dialreq_allocations] = NULL;
		return true;
	}
	return false;
}

struct stub_xfer_ctx;
static struct stub_xfer_ctx *stub_xfer_ctxs[8];
static int stub_xfer_ctx_count = 0;

/* set the minimal server fields required by production code */
static void test_server_init(struct server *restrict s)
{
	s->conf = &test_conf;
	s->resolver = NULL;
	s->xfer = transfer_create(s->loop, 1);
	s->ruleset = G.ruleset;
	s->basereq = NULL;
}

static void reset_stub_state(void)
{
	/* clear a virtual clock a prior timeout case may have left enabled on a
	 * T_EXPECT failure path */
	vclock_stop();
	S.dialreq_new_ok = false;
	S.dialaddr_parse_ok = false;
	S.dialer_invoke_now = true;
	S.dialer_result_fd = -1;
	S.dialer_err = DIALER_ERR_CONNECT;
	S.dialer_syserr = ECONNREFUSED;
	S.dialreq_free_calls = 0;
	S.dialreq_invalid_free_calls = 0;
	for (int i = 0; i < stub_xfer_ctx_count; i++) {
		free(stub_xfer_ctxs[i]);
		stub_xfer_ctxs[i] = NULL;
	}
	stub_xfer_ctx_count = 0;
	S.ruleset_resolve_ok = false;
	S.ruleset_reply_with_req = false;
	S.ruleset_finish_now = false;
	S.ruleset_state_nonnull = false;
	S.ruleset_loop = NULL;
	S.ruleset_state_ptr = NULL;
	S.ruleset_cb_ptr = NULL;
	S.ruleset_state_slot = NULL;
	S.ruleset_cancel_calls = 0;
	S.dialer_cancel_calls = 0;
	S.dialer_do_calls = 0;
	S.captured_creds = false;
	S.captured_username[0] = '\0';
	S.captured_password[0] = '\0';
	reset_dialreq_allocations();
	test_conf.timeout = 1.0;
	test_conf.auth_required = false;
	G.ruleset = NULL;
}

const char *dialer_strerror(const enum dialer_error err)
{
	(void)err;
	return "stub";
}

struct dialreq *dialreq_new(const struct dialreq *base, const size_t num_proxy)
{
	(void)base;
	(void)num_proxy;
	if (!S.dialreq_new_ok) {
		return NULL;
	}
	struct dialreq *restrict req = calloc(1, sizeof(struct dialreq));
	if (req != NULL) {
		track_dialreq_allocation(req);
	}
	return req;
}

bool dialreq_addproxy(
	struct dialreq *restrict req, const char *restrict proxy_uri,
	const size_t urilen)
{
	(void)req;
	(void)proxy_uri;
	(void)urilen;
	return false;
}

struct dialreq *
dialreq_parse(const char *restrict addr, const char *restrict csv)
{
	(void)addr;
	(void)csv;
	return NULL;
}

int dialreq_format(
	char *restrict s, const size_t maxlen, const struct dialreq *restrict r)
{
	(void)s;
	(void)maxlen;
	(void)r;
	return -1;
}

void dialreq_free(struct dialreq *req)
{
	if (req == NULL) {
		return;
	}
	if (!untrack_dialreq_allocation(req)) {
		S.dialreq_invalid_free_calls++;
		return;
	}
	S.dialreq_free_calls++;
	free(req);
}

bool dialaddr_parse(
	struct dialaddr *restrict addr, const char *restrict s,
	const size_t len)
{
	(void)s;
	(void)len;
	if (!S.dialaddr_parse_ok) {
		return false;
	}
	addr->type = ATYP_DOMAIN;
	addr->port = 80;
	addr->domain.len = 7;
	(void)memcpy(addr->domain.name, "example", 7);
	return true;
}

bool dialaddr_set(
	struct dialaddr *restrict addr, const struct sockaddr *restrict sa,
	const socklen_t len)
{
	(void)addr;
	(void)sa;
	(void)len;
	return false;
}

void dialaddr_copy(
	struct dialaddr *restrict dst, const struct dialaddr *restrict src)
{
	(void)dst;
	(void)src;
}

int dialaddr_format(
	char *restrict s, const size_t maxlen,
	const struct dialaddr *restrict addr)
{
	(void)addr;
	if (s != NULL && maxlen > 0) {
		(void)snprintf(s, maxlen, "(stub)");
	}
	return 6;
}

void dialer_init(
	struct dialer *restrict d, const struct dialer_cb *callback,
	uint_least64_t *byt_sent, uint_least64_t *byt_recv)
{
	(void)byt_sent;
	(void)byt_recv;
	d->finish_cb = *callback;
	d->err = DIALER_OK;
	d->syserr = 0;
}

void dialer_do(
	struct dialer *d, struct ev_loop *loop, const struct dialreq *req,
	const struct config *conf, struct resolver *resolver,
	struct server *server)
{
	d->req = req;
	S.dialer_do_calls++;
	(void)loop;
	(void)conf;
	(void)resolver;
	(void)server;
	d->err = S.dialer_err;
	d->syserr = S.dialer_syserr;
	if (!S.dialer_invoke_now) {
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

struct stub_xfer_ctx {
#if WITH_THREADS
	atomic_size_t *num_sessions;
#else
	size_t *num_sessions;
#endif
};

struct transfer *
transfer_create(struct ev_loop *restrict loop, const unsigned int nworkers)
{
	(void)loop;
	(void)nworkers;
	static int token;
	return (struct transfer *)&token;
}

void transfer_join(struct transfer *restrict xfer)
{
	(void)xfer;
}

bool transfer_serve(
	struct transfer *restrict xfer, const int acc_fd, const int dial_fd,
	const struct transfer_opts *restrict opts)
{
	(void)xfer;
	(void)acc_fd;
	(void)dial_fd;
	T_CHECK(stub_xfer_ctx_count < (int)ARRAY_SIZE(stub_xfer_ctxs));
	struct stub_xfer_ctx *restrict xctx = malloc(sizeof(*xctx));
	if (xctx == NULL) {
		return false;
	}
	xctx->num_sessions = opts->num_sessions;
	stub_xfer_ctxs[stub_xfer_ctx_count++] = xctx;
	return true;
}

void ruleset_cancel(struct ev_loop *loop, struct ruleset_state *restrict state)
{
	(void)loop;
	(void)state;
	S.ruleset_cancel_calls++;
}

void ruleset_request_cancel(
	struct ev_loop *loop, struct ruleset_callback *restrict cb)
{
	if (!ev_is_pending(&cb->w_finish)) {
		return;
	}
	dialreq_free(cb->request.req);
	cb->request.req = NULL;
	ev_clear_pending(loop, &cb->w_finish);
}

bool ruleset_resolve(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	(void)r;
	(void)request;
	S.captured_creds = true;
	(void)snprintf(
		S.captured_username, sizeof(S.captured_username), "%s",
		username != NULL ? username : "");
	(void)snprintf(
		S.captured_password, sizeof(S.captured_password), "%s",
		password != NULL ? password : "");
	S.ruleset_cb_ptr = callback;
	S.ruleset_state_slot = state;
	if (S.ruleset_state_nonnull) {
		S.ruleset_state_ptr =
			(struct ruleset_state *)&ruleset_state_token;
		*state = S.ruleset_state_ptr;
	} else {
		*state = NULL;
	}
	if (!S.ruleset_resolve_ok) {
		return false;
	}
	callback->request.req = NULL;
	if (S.ruleset_reply_with_req) {
		callback->request.req = dialreq_new(NULL, 0);
	}
	if (S.ruleset_finish_now && S.ruleset_loop != NULL) {
		callback->w_finish.cb(
			S.ruleset_loop, &callback->w_finish, EV_CUSTOM);
	}
	return true;
}

bool ruleset_route(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	(void)r;
	(void)state;
	(void)request;
	(void)username;
	(void)password;
	(void)callback;
	return false;
}

bool ruleset_route6(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	(void)r;
	(void)state;
	(void)request;
	(void)username;
	(void)password;
	(void)callback;
	return false;
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

/* Drive the loop until it quiesces: pump non-blocking rounds until a round
 * invokes no watchers, i.e. all reachable I/O has been processed. No iteration
 * count and no wall-clock wait; the watchdog only backstops a runaway loop.
 * Works under the virtual clock too (a frozen clock never advances real time,
 * so only ready I/O drives progress). */
static void drive_loop(struct ev_loop *loop)
{
	struct test_watchdog watchdog = { 0 };
	ev_timer w_timeout;
	ev_timer_init(&w_timeout, test_watchdog_cb, TEST_WAIT_RECV_SEC, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	ev_set_invoke_pending_cb(loop, drive_invoke_pending);
	do {
		g_drive_invoked = 0;
		ev_run(loop, EVRUN_NOWAIT);
	} while (g_drive_invoked > 0 && !watchdog.fired);
	ev_set_invoke_pending_cb(loop, ev_invoke_pending);
	ev_timer_stop(loop, &w_timeout);
}

static bool test_wait_until(
	struct ev_loop *loop, bool (*predicate)(void *), void *data,
	const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired && !predicate(data)) {
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_timeout);
	return predicate(data);
}

struct server_success_wait_ctx {
	const struct server *s;
	int_least32_t expected;
};

static bool server_success_reached(void *data)
{
	const struct server_success_wait_ctx *const ctx = data;
	return (int_least32_t)ctx->s->stats.num_success >= ctx->expected;
}

static void init_server(struct ev_loop **loop, struct server *restrict s)
{
	*loop = ev_loop_new(0);
	T_CHECK(*loop != NULL);
	s->loop = *loop;
	test_server_init(s);
}

static void start_serve(
	struct ev_loop *loop, struct server *restrict s, int *restrict peer_fd)
{
	int sv[2] = { -1, -1 };
	struct sockaddr_in sa = { .sin_family = AF_INET };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(socket_set_cloexec(sv[0]) == 0);
	T_CHECK(socket_set_nonblock(sv[0]) == 0);
	T_CHECK(socket_set_cloexec(sv[1]) == 0);
	T_CHECK(socket_set_nonblock(sv[1]) == 0);
	S.ruleset_loop = loop;
	http_proxy_serve(s, loop, sv[0], (const struct sockaddr *)&sa);
	*peer_fd = sv[1];
}

static int write_all(const int fd, const void *buf, size_t len)
{
	const unsigned char *p = buf;
	while (len > 0) {
		const ssize_t n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* transient send-buffer backpressure on the
				 * nonblocking socketpair: wait for writability
				 * rather than failing on the first short window */
				struct pollfd pfd = { .fd = fd,
						      .events = POLLOUT };
				if (poll(&pfd, 1, 1000) <= 0) {
					return -1;
				}
				continue;
			}
			return -1;
		}
		if (n == 0) {
			return -1;
		}
		p += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

static void serve_payload(
	struct ev_loop *loop, struct server *restrict s,
	const char *restrict req, int *restrict peer_fd)
{
	int sv[2] = { -1, -1 };
	struct sockaddr_in sa = { .sin_family = AF_INET };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(socket_set_cloexec(sv[0]) == 0);
	T_CHECK(socket_set_nonblock(sv[0]) == 0);
	T_CHECK(socket_set_cloexec(sv[1]) == 0);
	T_CHECK(socket_set_nonblock(sv[1]) == 0);
	S.ruleset_loop = loop;
	http_proxy_serve(s, loop, sv[0], (const struct sockaddr *)&sa);
	T_CHECK(write_all(sv[1], req, strlen(req)) == 0);

	*peer_fd = sv[1];
}

/* Drain everything currently readable on fd into buf without blocking. */
static size_t drain_fd(
	const int fd, unsigned char *restrict buf, size_t off, const size_t cap)
{
	while (off < cap) {
		const ssize_t n = recv(fd, buf + off, cap - off, MSG_DONTWAIT);
		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR) {
			continue;
		}
		break; /* EOF or EAGAIN: nothing more buffered right now */
	}
	return off;
}

/* Drive the loop to quiescence -- every reachable round of in-loop I/O is
 * processed, so the server has written its full response into fd's socket
 * buffer -- then drain fd. Completion tracks the loop reaching a fixed point
 * (drive_loop's ev_pending_count pump), not a magic quiet-tick count.
 * min_bytes is the caller's asserted floor; a short read fails the caller. */
static ssize_t recv_at_least(
	struct ev_loop *loop, const int fd, unsigned char *restrict buf,
	const size_t cap, const size_t min_bytes)
{
	size_t off = 0;
	/* Drive the proxy and drain until the caller's floor is met, the buffer
	 * fills, or a round makes no progress (data source exhausted); each
	 * round is bounded by drive_loop's watchdog. */
	for (;;) {
		drive_loop(loop);
		const size_t got = drain_fd(fd, buf, off, cap);
		if (got >= min_bytes || got == off || got >= cap) {
			return (ssize_t)got;
		}
		off = got;
	}
}

static bool has_http_status(
	const unsigned char *restrict rsp, const size_t n,
	const char *restrict code_str)
{
	const size_t code_len = strlen(code_str);
	if (n < 12 + code_len) {
		return false;
	}
	if (memmem(rsp, n, "HTTP/1.", 7) == NULL) {
		return false;
	}
	if (memmem(rsp, n, code_str, code_len) == NULL) {
		return false;
	}
	return true;
}

static bool assert_response_status(
	struct ev_loop *loop, const int peer_fd, const char *restrict status)
{
	unsigned char rsp[1024];
	/* Expect at least: "HTTP/1.1 200 OK\r\n\r\n" (17 bytes minimum) */
	const ssize_t n = recv_at_least(loop, peer_fd, rsp, sizeof(rsp), 17);
	if (n <= 0) {
		return false;
	}
	/* Gracefully close: SHUT_WR prevents further recv, verifies no trailing data */
	(void)shutdown(peer_fd, SHUT_WR);
	return has_http_status(rsp, (size_t)n, status);
}

static void make_fd_pair(int *restrict a, int *restrict b)
{
	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(socket_set_cloexec(sv[0]) == 0);
	T_CHECK(socket_set_nonblock(sv[0]) == 0);
	T_CHECK(socket_set_cloexec(sv[1]) == 0);
	T_CHECK(socket_set_nonblock(sv[1]) == 0);
	*a = sv[0];
	*b = sv[1];
}

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - request-form handling, CONNECT tunneling and proxy behavior.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(split_request_is_parsed_incrementally)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;

	reset_stub_state();
	init_server(&loop, &s);
	start_serve(loop, &s, &peer_fd);

	T_CHECK(write_all(peer_fd, "GET / HTTP/1.1\r\nHost: ex", 24) == 0);
	drive_loop(loop);
	T_CHECK(write_all(peer_fd, "ample\r\n\r\n", 9) == 0);
	drive_loop(loop);

	/* a non-CONNECT method is not implemented → 501 */
	T_EXPECT(assert_response_status(loop, peer_fd, "501"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(malformed_proxy_authorization_returns_400)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "Proxy-Authorization: BasicOnly\r\n"
			   "\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
	reset_stub_state();
	test_server_init(&s);

	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[1024];
		const ssize_t n =
			recv_at_least(loop, peer_fd, rsp, sizeof(rsp), 17);
		T_EXPECT(n >= 17);
		T_EXPECT(has_http_status(rsp, (size_t)n, "400"));
		(void)shutdown(peer_fd, SHUT_WR);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* A CONNECT carrying a TE the proxy does not offer must not fail the request:
 * it reaches the dialer (502 here) rather than being rejected with a 400. */
T_DECLARE_CASE(connect_with_te_hint_is_accepted)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "TE: gzip\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	S.dialer_result_fd = -1;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	T_EXPECT(assert_response_status(loop, peer_fd, "502"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* An unparsable client-supplied CONNECT target is a client error (400), not a
 * server error (500). dialreq_new succeeds; only the address parse fails. */
T_DECLARE_CASE(connect_with_invalid_target_returns_400)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	const char req[] = "CONNECT not-a-valid-hostport HTTP/1.1\r\n"
			   "Host: ignored\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true; /* the failure is the target parse, not OOM */
	init_server(&loop, &s);

	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[1024];
		const ssize_t n =
			recv_at_least(loop, peer_fd, rsp, sizeof(rsp), 17);
		T_EXPECT(n >= 17);
		T_EXPECT(has_http_status(rsp, (size_t)n, "400"));
		(void)shutdown(peer_fd, SHUT_WR);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(valid_connect_dialer_error_returns_502)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "Host: ignored\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	S.dialer_result_fd = -1;
	S.dialer_err = DIALER_ERR_CONNECT;
	S.dialer_syserr = ECONNREFUSED;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	T_EXPECT(assert_response_status(loop, peer_fd, "502"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(valid_connect_established_with_hijack)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	unsigned char rsp[1024];
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "Host: ignored\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		const ssize_t n =
			recv_at_least(loop, peer_fd, rsp, sizeof(rsp), 30);
		T_EXPECT(n >= 30);
		T_EXPECT(
			memmem(rsp, (size_t)n, "200 Connection established",
			       26) != NULL);
		(void)shutdown(peer_fd, SHUT_WR);
	}

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(connect_hijack_finalize_does_not_touch_overwritten_dialreq)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	unsigned char rsp[1024];
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "Host: ignored\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		const ssize_t n =
			recv_at_least(loop, peer_fd, rsp, sizeof(rsp), 30);
		T_EXPECT(n >= 30);
		T_EXPECT(
			memmem(rsp, (size_t)n, "200 Connection established",
			       26) != NULL);
		(void)shutdown(peer_fd, SHUT_WR);
	}
	T_EXPECT_EQ(S.dialreq_free_calls, 1);
	T_EXPECT_EQ(S.dialreq_invalid_free_calls, 0);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(connect_with_transfer_encoding_chunked_is_accepted)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "Connection: close\r\n"
			   "Keep-Alive: timeout=1\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "Authorization: Basic dXNlcjpwYXNz\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	S.dialer_result_fd = -1;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	T_EXPECT(assert_response_status(loop, peer_fd, "502"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* A CONNECT tunnel ignores request headers the proxy does not consume; an
 * Authorization header (even a malformed one) must not fail the request. */
T_DECLARE_CASE(connect_ignores_malformed_authorization)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	unsigned char rsp[1024];
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "Authorization: BasicOnly\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		const ssize_t n =
			recv_at_least(loop, peer_fd, rsp, sizeof(rsp), 30);
		T_EXPECT(n >= 30);
		T_EXPECT(
			memmem(rsp, (size_t)n, "200 Connection established",
			       26) != NULL);
		(void)shutdown(peer_fd, SHUT_WR);
	}

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_auth_required_without_basic_credentials_returns_407)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int_fast32_t ruleset_stub = 0;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "Proxy-Authorization: Bearer token\r\n"
			   "\r\n";

	reset_stub_state();
	test_conf.auth_required = true;
	G.ruleset = (struct ruleset *)&ruleset_stub;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	T_EXPECT(assert_response_status(loop, peer_fd, "407"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_auth_required_with_invalid_basic_returns_407)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int_fast32_t ruleset_stub = 0;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "Proxy-Authorization: Basic dXNlcm9ubHk=\r\n"
			   "\r\n";

	reset_stub_state();
	test_conf.auth_required = true;
	G.ruleset = (struct ruleset *)&ruleset_stub;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	T_EXPECT(assert_response_status(loop, peer_fd, "407"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* auth_required with valid Basic credentials: the decoded username/password
 * must reach the ruleset verbatim (exercises parse_proxy_auth's decode/split). */
T_DECLARE_CASE(ruleset_auth_required_valid_basic_decodes_credentials)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int_fast32_t ruleset_stub = 0;
	/* "user:pass" base64-encoded */
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
			   "\r\n";

	reset_stub_state();
	test_conf.auth_required = true;
	G.ruleset = (struct ruleset *)&ruleset_stub;
	S.ruleset_resolve_ok = true;
	S.ruleset_state_nonnull = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	T_EXPECT(S.captured_creds);
	T_EXPECT_STREQ(S.captured_username, "user");
	T_EXPECT_STREQ(S.captured_password, "pass");

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* Regression: RFC 9110 §11.1 makes the authentication scheme token
 * case-insensitive. Lower- and mixed-case "Basic" must be accepted like the
 * canonical spelling, so the decoded credentials still reach the ruleset.
 * Pre-fix the case-sensitive scheme match dropped them and, with auth_required,
 * the request was answered 407. */
T_DECLARE_CASE(ruleset_auth_scheme_is_case_insensitive)
{
	/* "user:pass" base64-encoded, varying only the scheme token case */
	static const char *const schemes[] = { "basic", "BASIC", "bAsIc" };
	for (size_t k = 0; k < ARRAY_SIZE(schemes); ++k) {
		struct ev_loop *loop = NULL;
		struct server s = { 0 };
		int peer_fd = -1;
		int_fast32_t ruleset_stub = 0;
		char req[128];
		(void)snprintf(
			req, sizeof(req),
			"CONNECT example.com:80 HTTP/1.1\r\n"
			"Proxy-Authorization: %s dXNlcjpwYXNz\r\n"
			"\r\n",
			schemes[k]);

		reset_stub_state();
		test_conf.auth_required = true;
		G.ruleset = (struct ruleset *)&ruleset_stub;
		S.ruleset_resolve_ok = true;
		S.ruleset_state_nonnull = true;

		init_server(&loop, &s);
		serve_payload(loop, &s, req, &peer_fd);
		drive_loop(loop);

		T_EXPECT(S.captured_creds);
		T_EXPECT_STREQ(S.captured_username, "user");
		T_EXPECT_STREQ(S.captured_password, "pass");

		T_CHECK(close(peer_fd) == 0);
		ev_loop_destroy(loop);
	}
}

T_DECLARE_CASE(ruleset_resolve_failure_returns_500)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int_fast32_t ruleset_stub = 0;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
			   "\r\n";

	reset_stub_state();
	test_conf.auth_required = true;
	G.ruleset = (struct ruleset *)&ruleset_stub;
	S.ruleset_resolve_ok = false;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	T_EXPECT(assert_response_status(loop, peer_fd, "500"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_finish_without_req_returns_403)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int_fast32_t ruleset_stub = 0;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "\r\n";

	reset_stub_state();
	G.ruleset = (struct ruleset *)&ruleset_stub;
	S.ruleset_resolve_ok = true;
	S.ruleset_reply_with_req = false;
	S.ruleset_finish_now = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	T_EXPECT(assert_response_status(loop, peer_fd, "403"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_finish_with_req_and_dialer_error_returns_502)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int_fast32_t ruleset_stub = 0;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	G.ruleset = (struct ruleset *)&ruleset_stub;
	S.ruleset_resolve_ok = true;
	S.ruleset_reply_with_req = true;
	S.ruleset_finish_now = true;
	S.dialer_result_fd = -1;
	S.dialer_err = DIALER_ERR_CONNECT;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	T_EXPECT(assert_response_status(loop, peer_fd, "502"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(timeout_in_process_state_cancels_ruleset)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int_fast32_t ruleset_stub = 0;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "\r\n";

	reset_stub_state();
	test_conf.timeout = 10.0;
	G.ruleset = (struct ruleset *)&ruleset_stub;
	S.ruleset_resolve_ok = true;
	S.ruleset_reply_with_req = true;
	S.ruleset_finish_now = false;
	S.ruleset_state_nonnull = true;

	/* engage the virtual clock before the loop exists, so w_timeout is armed
	 * on virtual time and no amount of real setup time can cross it */
	vclock_freeze_now();
	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	/* drive to the process state (ruleset pending, w_timeout armed), then
	 * cross the deadline on the virtual clock and fire it -- no real wait */
	drive_loop(loop);
	vclock_advance(test_conf.timeout + 1.0);
	drive_loop(loop);

	T_EXPECT(S.ruleset_cancel_calls > 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	vclock_stop();
}

/* Emulate ruleset state_complete() from an ev_check: hand the request over,
 * detach the caller's ruleset_state, and queue the completion event.
 *
 * The timing is the point. libev flushes events fed before ev_run() ahead of
 * that sweep's timers, so feeding w_finish from the case body would dispatch it
 * before the deadline expires -- the opposite of the window under test. A check
 * watcher is queued after the timers are, so running it at EV_MAXPRI (and
 * w_finish at EV_MINPRI) leaves w_finish pending exactly while the timeout
 * callback tears the ctx down, which is what a ruleset worker completing a
 * request just as its deadline expires produces in production. */
static void
complete_ruleset_cb(struct ev_loop *loop, ev_check *watcher, const int revents)
{
	(void)revents;
	ev_check_stop(loop, watcher);
	*S.ruleset_state_slot = NULL;
	S.ruleset_cb_ptr->request.req = dialreq_new(NULL, 0);
	T_CHECK(S.ruleset_cb_ptr->request.req != NULL);
	ev_set_priority(&S.ruleset_cb_ptr->w_finish, EV_MINPRI);
	ev_feed_event(loop, &S.ruleset_cb_ptr->w_finish, EV_CUSTOM);
}

/* Regression: ruleset_cancel() reaches an operation only while it is still
 * pending. Once the request completes, state_complete() has already detached
 * the caller's ruleset_state and fed w_finish, which stays queued with the
 * delivered dialreq. If the ctx is torn down in that window, http_ctx_stop must
 * also ruleset_request_cancel(), or the pending event later fires ruleset_cb()
 * on the freed ctx and the delivered request leaks. */
T_DECLARE_CASE(process_teardown_cancels_completed_ruleset_request)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int_fast32_t ruleset_stub = 0;
	ev_check w_complete;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "\r\n";

	reset_stub_state();
	test_conf.timeout = 10.0;
	G.ruleset = (struct ruleset *)&ruleset_stub;
	S.dialreq_new_ok = true;
	S.ruleset_resolve_ok = true;
	S.ruleset_reply_with_req = false; /* delivered by complete_ruleset_cb */
	S.ruleset_finish_now = false;
	S.ruleset_state_nonnull = true;

	vclock_freeze_now();
	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop); /* -> STATE_PROCESS, the request still pending */
	T_CHECK(S.ruleset_cb_ptr != NULL);
	T_CHECK(S.ruleset_state_slot != NULL);

	/* complete the request and cross the deadline in the same sweep */
	ev_check_init(&w_complete, complete_ruleset_cb);
	ev_set_priority(&w_complete, EV_MAXPRI);
	ev_check_start(loop, &w_complete);
	vclock_advance(test_conf.timeout + 1.0);
	drive_loop(loop);

	/* the state was already detached, so the teardown could not have gone
	 * through ruleset_cancel... */
	T_EXPECT_EQ(S.ruleset_cancel_calls, 0);
	/* ...the completion never dispatched into the torn-down ctx, so no dial
	 * was ever started from it... */
	T_EXPECT_EQ(S.dialer_do_calls, 0);
	/* ...yet the delivered request was released rather than leaked, which
	 * only ruleset_request_cancel() does */
	T_EXPECT_EQ(S.dialreq_free_calls, 1);
	T_EXPECT_EQ(S.dialreq_invalid_free_calls, 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	vclock_stop();
}

T_DECLARE_CASE(timeout_in_connect_state_cancels_dialer)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "\r\n";

	reset_stub_state();
	test_conf.timeout = 10.0;
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	S.dialer_invoke_now = false;

	/* engage the virtual clock before the loop exists, so w_timeout is armed
	 * on virtual time and no amount of real setup time can cross it */
	vclock_freeze_now();
	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	/* drive to the connect state (dialer pending, w_timeout armed), then
	 * cross the deadline on the virtual clock and fire it -- no real wait */
	drive_loop(loop);
	vclock_advance(test_conf.timeout + 1.0);
	drive_loop(loop);
	/* the 504 reply is queued on w_send; restore real time so it flushes
	 * (the frozen vclock trips drive_loop's watchdog before the async send) */
	vclock_stop();

	T_EXPECT(S.dialer_cancel_calls > 0);
	T_EXPECT_EQ((uintmax_t)s.stats.num_reject_timeout, (uintmax_t)1);
	/* the dial deadline answers 504 rather than closing with no status */
	{
		unsigned char b[1024];
		const ssize_t n =
			recv_at_least(loop, peer_fd, b, sizeof(b), 17);
		T_EXPECT(n >= 17);
		T_EXPECT(has_http_status(b, (size_t)n, "504"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * Regression: a client that doesn't wait for the "200 Connection
 * established" reply before sending payload (e.g. TCP fast open) has its
 * CONNECT request and payload delivered in a single recv(). Any bytes past
 * the request/headers must be replayed to the upstream once the tunnel opens,
 * not silently dropped.
 */
T_DECLARE_CASE(connect_pipelined_bytes_forwarded_to_upstream)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	struct server_success_wait_ctx wait_ctx = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	static const char payload[] = "hello upstream";
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n\r\n"
			   "hello upstream";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	wait_ctx.s = &s;
	wait_ctx.expected = 1;
	T_EXPECT(test_wait_until(
		loop, server_success_reached, &wait_ctx, TEST_WAIT_RECV_SEC));

	T_EXPECT(s.stats.num_success == 1);
	{
		unsigned char got[sizeof(payload) - 1] = { 0 };
		const ssize_t n = recv_at_least(
			loop, upstream_fd, got, sizeof(got), sizeof(got));
		T_EXPECT_EQ(n, (ssize_t)sizeof(got));
		T_EXPECT(memcmp(got, payload, sizeof(got)) == 0);
	}
	/* the replayed bytes bypass the relay, so only the readahead call site
	 * can count them; uncounted, they would be missing from the uplink */
	T_EXPECT((uintmax_t)s.byt_up >= (uintmax_t)(sizeof(payload) - 1));

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* A successful CONNECT tunnel must count exactly one success (dialer_cb must
 * not double-increment before mark_ready). */
T_DECLARE_CASE(connect_success_counted_once)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	struct server_success_wait_ctx wait_ctx = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	wait_ctx.s = &s;
	wait_ctx.expected = 1;
	T_EXPECT(test_wait_until(
		loop, server_success_reached, &wait_ctx, TEST_WAIT_RECV_SEC));

	T_EXPECT(s.stats.num_success == 1);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(request_header_value_with_bare_cr_is_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* Bare CR in a field value is a CTL; RFC 9112 §2.2 SHOULD reject.
	 * The \r before "Injected" is not followed by \n so strstr("\r\n")
	 * finds the real CRLF later; value = "foo\rInjected: bar". */
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "X-Custom: foo\r"
			   "Injected: bar\r\n"
			   "\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
	reset_stub_state();
	test_server_init(&s);

	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[1024];
		const ssize_t n =
			recv_at_least(loop, peer_fd, rsp, sizeof(rsp), 17);
		T_EXPECT(n >= 17);
		T_EXPECT(has_http_status(rsp, (size_t)n, "400"));
		(void)shutdown(peer_fd, SHUT_WR);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(request_header_value_with_ctl_is_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* SOH (0x01) in value is a CTL; must be rejected */
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "X-Custom: foo\x01"
			   "bar\r\n"
			   "\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
	reset_stub_state();
	test_server_init(&s);

	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[1024];
		const ssize_t n =
			recv_at_least(loop, peer_fd, rsp, sizeof(rsp), 17);
		T_EXPECT(n >= 17);
		T_EXPECT(has_http_status(rsp, (size_t)n, "400"));
		(void)shutdown(peer_fd, SHUT_WR);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(request_header_name_with_invalid_token_is_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* Space in field name is not a tchar; RFC 7230 §3.2.6 requires rejection */
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "X Invalid: foo\r\n"
			   "\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
	reset_stub_state();
	test_server_init(&s);

	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[1024];
		const ssize_t n =
			recv_at_least(loop, peer_fd, rsp, sizeof(rsp), 17);
		T_EXPECT(n >= 17);
		T_EXPECT(has_http_status(rsp, (size_t)n, "400"));
		(void)shutdown(peer_fd, SHUT_WR);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* RFC 9112 §2.3: the proxy speaks HTTP/1.x only. A request whose version is not
 * HTTP/1.x must be rejected with 400 rather than mis-parsed. */
T_DECLARE_CASE(request_unsupported_http_version_returns_400)
{
	static const char *const versions[] = {
		"HTTP/2.0", "HTTP/0.9",	 "HTTP/1",
		"HTTP/3",   "HTTPS/1.1", "ICE/1.0",
	};
	for (size_t i = 0; i < ARRAY_SIZE(versions); i++) {
		struct ev_loop *loop = NULL;
		struct server s = { 0 };
		int peer_fd = -1;
		char req[128];
		(void)snprintf(
			req, sizeof(req),
			"GET http://example.com/ %s\r\n"
			"Host: example.com\r\n\r\n",
			versions[i]);

		reset_stub_state();
		init_server(&loop, &s);
		serve_payload(loop, &s, req, &peer_fd);
		drive_loop(loop);

		unsigned char rsp[1024];
		const ssize_t n =
			recv_at_least(loop, peer_fd, rsp, sizeof(rsp), 17);
		T_EXPECT(n >= 17);
		/* version `%s' must be rejected */
		T_EXPECT(has_http_status(rsp, (size_t)n, "400"));
		(void)shutdown(peer_fd, SHUT_WR);

		T_CHECK(close(peer_fd) == 0);
		ev_loop_destroy(loop);
	}
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(split_request_is_parsed_incrementally),
	T_CASE(malformed_proxy_authorization_returns_400),
	T_CASE(connect_with_te_hint_is_accepted),
	T_CASE(connect_with_invalid_target_returns_400),
	T_CASE(valid_connect_dialer_error_returns_502),
	T_CASE(valid_connect_established_with_hijack),
	T_CASE(connect_hijack_finalize_does_not_touch_overwritten_dialreq),
	T_CASE(connect_with_transfer_encoding_chunked_is_accepted),
	T_CASE(connect_success_counted_once),
	T_CASE(connect_pipelined_bytes_forwarded_to_upstream),
	T_CASE(connect_ignores_malformed_authorization),
	T_CASE(ruleset_auth_required_without_basic_credentials_returns_407),
	T_CASE(ruleset_auth_required_with_invalid_basic_returns_407),
	T_CASE(ruleset_auth_required_valid_basic_decodes_credentials),
	T_CASE(ruleset_auth_scheme_is_case_insensitive),
	T_CASE(ruleset_resolve_failure_returns_500),
	T_CASE(ruleset_finish_without_req_returns_403),
	T_CASE(ruleset_finish_with_req_and_dialer_error_returns_502),
	T_CASE(timeout_in_process_state_cancels_ruleset),
	T_CASE(process_teardown_cancels_completed_ruleset_request),
	T_CASE(timeout_in_connect_state_cancels_dialer),
	T_CASE(request_header_value_with_bare_cr_is_rejected),
	T_CASE(request_header_value_with_ctl_is_rejected),
	T_CASE(request_header_name_with_invalid_token_is_rejected),
	T_CASE(request_unsupported_http_version_returns_400),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	reset_stub_state();
	const int ret = testing_main(argc, argv, suite);
	reset_stub_state();
	return ret;
}
