/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * socks_test - white-box unit tests for socks.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   socks.c          module under test
 * All stateful collaborators of socks.c (dialer, transfer, ruleset) are
 * replaced by the mocks in the mock section below; randomized socks parsing
 * is fuzzed by the fuzz section's fuzz_socks case, which drives the real
 * socks.c parser against the stubbed dialer/transfer (the real-module
 * main_test cannot run this safely).
 */

#include "socks.h"

#include "conf.h"
#include "dialer.h"
#include "proto/socks.h"
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
 * mock - collaborator stubs (dialer, transfer, ruleset) and shared fixtures.
 *
 * These tests focus on protocol parsing paths in socks.c. Dependencies for
 * dialing and transfer are stubbed so parser behavior can be asserted in
 * isolation.
 * ---------------------------------------------------------------------- */

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

/* Reset the shared mutable test_conf fields to their defaults. Called from
 * stub_reset() at the top of each case so a T_EXPECT longjmp out of a prior
 * case cannot leak socks5_bind / socks5_udp / timeout / auth_required into the
 * next one (the bottom-of-case restores are skipped on the failure path). */
static void test_conf_reset(void)
{
	test_conf.timeout = 1.0;
	test_conf.auth_required = false;
	test_conf.socks5_bind = false;
	test_conf.socks5_udp = false;
}

static const ev_tstamp TEST_WAIT_SHORT_SEC = 0.016;
/* Watchdog bound on the event-driven read/drive helpers: a hung-test backstop,
 * never a completion signal (completion is a structurally complete reply or a
 * driven terminal state). */
static const ev_tstamp TEST_WAIT_TIMEOUT_SEC = 0.128;

static ev_tstamp test_timeout_wait_window(const ev_tstamp timeout_sec)
{
	ev_tstamp wait_sec = timeout_sec * 4.0;
	if (wait_sec < TEST_WAIT_SHORT_SEC) {
		wait_sec = TEST_WAIT_SHORT_SEC;
	}
	return wait_sec;
}

/* -------------------------------------------------------------------------
 * virtual clock - deterministic timeout tests without wall-clock waits.
 *
 * The timeouts under test are libev ev_timers armed inside production socks_ctx
 * structs the test never gets a handle to, so firing one in a specific state
 * requires controlling the clock libev reads. These strong-symbol interposers
 * shadow clock_gettime/gettimeofday: while enabled they return a virtual time
 * the test advances, so a deadline is crossed by advancing the clock and
 * pumping the loop -- no real waiting. Disabled by default (real time), so
 * every non-timeout case is unaffected.
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

/* Start virtual time at a fixed base; call before creating the loop so every
 * timer this case arms has a virtual-time deadline. */
static void vclock_start(void)
{
	g_vclock_sec = 1000.0;
	g_vclock_on = true;
}

/* Advance virtual time by @p sec; the caller then pumps the loop so libev fires
 * any timer whose deadline the advance crossed. */
static void vclock_advance(const double sec)
{
	g_vclock_sec += sec;
}

static void vclock_stop(void)
{
	g_vclock_on = false;
}

/* Backstop bound on the virtual-clock pump loops below: since the clock is
 * frozen no watchdog timer can fire, so this caps a hung/never-satisfied test
 * instead. It is not a completion count -- completion is the awaited flag or a
 * full/EOF read; a test that relies on the backstop to terminate has failed. */
enum { VCLOCK_PUMP_MAX = 100000 };

/* Pump the frozen-clock loop until *flag becomes nonzero: the production code
 * has reached the awaited point (e.g. dialer_do issued -> connect state). */
static void
vclock_pump_until(struct ev_loop *loop, const uint_least32_t *restrict flag)
{
	for (int i = 0; i < VCLOCK_PUMP_MAX && *flag == 0; i++) {
		ev_run(loop, EVRUN_NOWAIT);
	}
}

/* Pump the frozen-clock loop, reading from @p fd until @p need bytes have
 * arrived or the peer closes (EOF). Pass need == cap to read a whole reply that
 * ends in a teardown: a socks_ctx that replies then closes marks completion
 * with EOF, so no byte length need be hardcoded. Pass a smaller need to stop
 * after one reply on a connection that stays open (e.g. before advancing the
 * clock to trigger a later timeout reply). */
static ssize_t vclock_recv(
	struct ev_loop *loop, const int fd, void *restrict buf,
	const size_t cap, const size_t need)
{
	const size_t want = need < cap ? need : cap;
	size_t off = 0;
	for (int i = 0; i < VCLOCK_PUMP_MAX && off < want; i++) {
		ev_run(loop, EVRUN_NOWAIT);
		const ssize_t n =
			recv(fd, (char *)buf + off, cap - off, MSG_DONTWAIT);
		if (n > 0) {
			off += (size_t)n;
		} else if (n == 0) {
			break; /* EOF: the reply is complete */
		}
		/* n < 0 EAGAIN: nothing more yet, pump again */
	}
	return (ssize_t)off;
}

enum stub_dialer_mode {
	STUB_DIALER_NONE,
	STUB_DIALER_FAIL,
	STUB_DIALER_SUCCESS,
};

enum stub_ruleset_mode {
	STUB_RULESET_FAIL,
	STUB_RULESET_ASYNC_OK,
};

static struct {
	bool dialreq_available;

	enum stub_dialer_mode dialer_mode;
	enum dialer_error dialer_err;
	int dialer_syserr;
	int dialer_success_fd;
	uint_least32_t dialer_cancel_count;
	uint_least32_t dialer_do_count;

	enum stub_ruleset_mode ruleset_mode;
	struct ruleset_callback *ruleset_pending_cb;
	uint_least32_t ruleset_cancel_count;
	uint_least32_t ruleset_dispatch_count;
} STUB = {
	.dialreq_available = false,
	.dialer_mode = STUB_DIALER_NONE,
	.dialer_err = DIALER_OK,
	.dialer_syserr = 0,
	.dialer_success_fd = -1,
	.ruleset_mode = STUB_RULESET_FAIL,
	.ruleset_pending_cb = NULL,
	.ruleset_cancel_count = 0,
};

static int stub_ruleset_state_tag = 0;

struct stub_xfer_ctx;
static struct stub_xfer_ctx *stub_xfer_ctxs[8];
static int_least32_t stub_xfer_ctx_count = 0;

static void stub_reset(void)
{
	/* clear a virtual clock a prior timeout case may have left enabled on a
	 * T_EXPECT failure path (its bottom-of-case vclock_stop() was skipped) */
	vclock_stop();
	STUB.dialreq_available = false;
	STUB.dialer_mode = STUB_DIALER_NONE;
	STUB.dialer_err = DIALER_OK;
	STUB.dialer_syserr = 0;
	STUB.dialer_success_fd = -1;
	STUB.dialer_cancel_count = 0;
	STUB.dialer_do_count = 0;
	for (int_fast32_t i = 0; i < stub_xfer_ctx_count; i++) {
		free(stub_xfer_ctxs[i]);
		stub_xfer_ctxs[i] = NULL;
	}
	stub_xfer_ctx_count = 0;
	STUB.ruleset_mode = STUB_RULESET_FAIL;
	STUB.ruleset_pending_cb = NULL;
	STUB.ruleset_cancel_count = 0;
	STUB.ruleset_dispatch_count = 0;
	G.ruleset = NULL;
	test_conf_reset();
}

/* set the minimal server fields required by production code */
static void test_server_init(struct server *restrict s)
{
	s->conf = &test_conf;
	s->resolver = NULL;
	s->xfer = transfer_create(s->loop, 1);
	s->ruleset = G.ruleset;
	s->basereq = NULL;
}

static void finish_ruleset(struct ev_loop *loop)
{
	if (STUB.ruleset_pending_cb == NULL) {
		return;
	}
	/* Production fills request.req only when the async ruleset completes, so
	 * the stub must too: allocating it eagerly at dispatch would leak it on
	 * the cancel-before-finish path (ruleset_request_cancel frees the req
	 * only while w_finish is pending, which a timeout teardown never is). */
	STUB.ruleset_pending_cb->request.req = dialreq_new(NULL, 0);
	ev_feed_event(loop, &STUB.ruleset_pending_cb->w_finish, EV_CUSTOM);
	STUB.ruleset_pending_cb = NULL;
}

const char *dialer_strerror(const enum dialer_error err)
{
	(void)err;
	return "stub";
}

struct dialreq *dialreq_new(const struct dialreq *base, const size_t num_proxy)
{
	(void)base;
	if (!STUB.dialreq_available) {
		return NULL;
	}
	if (num_proxy != 0) {
		return NULL;
	}
	struct dialreq *req = malloc(sizeof(*req));
	if (req == NULL) {
		return NULL;
	}
	memset(req, 0, sizeof(*req));
	return req;
}

void dialreq_free(struct dialreq *req)
{
	free(req);
}

void dialaddr_copy(
	struct dialaddr *restrict dst, const struct dialaddr *restrict src)
{
	*dst = *src;
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
	(void)req;
	(void)conf;
	(void)resolver;
	(void)server;

	STUB.dialer_do_count++;
	switch (STUB.dialer_mode) {
	case STUB_DIALER_NONE:
		return;
	case STUB_DIALER_FAIL:
		d->err = STUB.dialer_err;
		d->syserr = STUB.dialer_syserr;
		d->finish_cb.func(loop, d->finish_cb.data, -1);
		return;
	case STUB_DIALER_SUCCESS: {
		int fd = STUB.dialer_success_fd;
		if (fd < 0) {
			fd = socket(AF_INET, SOCK_STREAM, 0);
		}
		if (fd < 0) {
			d->err = DIALER_ERR_SYSTEM;
			d->syserr = errno;
			d->finish_cb.func(loop, d->finish_cb.data, -1);
			return;
		}
		d->err = DIALER_OK;
		d->syserr = 0;
		d->finish_cb.func(loop, d->finish_cb.data, fd);
		return;
	}
	default:
		return;
	}
}

void dialer_cancel(struct dialer *restrict d, struct ev_loop *restrict loop)
{
	(void)d;
	(void)loop;
	STUB.dialer_cancel_count++;
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

bool transfer_serve(
	struct transfer *restrict xfer, const int acc_fd, const int dial_fd,
	const struct transfer_opts *restrict opts)
{
	(void)xfer;
	(void)acc_fd;
	(void)dial_fd;
	T_CHECK(stub_xfer_ctx_count < (int_fast32_t)ARRAY_SIZE(stub_xfer_ctxs));
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
	STUB.ruleset_cancel_count++;
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

static bool ruleset_stub_resolve(
	struct ruleset_state **state, struct ruleset_callback *callback)
{
	if (STUB.ruleset_mode == STUB_RULESET_FAIL) {
		return false;
	}
	if (STUB.ruleset_mode != STUB_RULESET_ASYNC_OK) {
		return false;
	}

	/* The dialreq is produced when the async request completes
	 * (finish_ruleset), not at dispatch — mirroring production. */
	callback->request.req = NULL;
	*state = (struct ruleset_state *)&stub_ruleset_state_tag;
	STUB.ruleset_pending_cb = callback;
	STUB.ruleset_dispatch_count++;
	return true;
}

bool ruleset_dispatch(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const int atype,
	const char *restrict username, const char *restrict password,
	struct ruleset_callback *callback)
{
	(void)r;
	(void)request;
	(void)atype;
	(void)username;
	(void)password;
	return ruleset_stub_resolve(state, callback);
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

struct recv_reply_ctx {
	int fd;
	unsigned char *buf;
	size_t cap;
	size_t off;
	bool eof;
};

static void recv_reply_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	(void)loop;
	(void)revents;
	struct recv_reply_ctx *restrict c = w->data;
	while (c->off < c->cap) {
		const ssize_t n = recv(
			c->fd, c->buf + c->off, c->cap - c->off, MSG_DONTWAIT);
		if (n > 0) {
			c->off += (size_t)n;
			continue;
		}
		if (n == 0) {
			c->eof = true;
			return; /* peer closed */
		}
		if (errno == EINTR) {
			continue;
		}
		return; /* EAGAIN/EWOULDBLOCK: nothing more buffered yet */
	}
}

/* Receive a reply of at least @p need bytes -- the length the caller asserts,
 * i.e. the structurally complete reply -- or until the peer closes (EOF). The
 * fd is registered with the loop, so the read is event-driven: ev_run() wakes
 * when the server produces output or closes, with no quiescence tick count. The
 * watchdog is a hung-test backstop, never the completion signal. */
static ssize_t recv_reply(
	struct ev_loop *loop, const int fd, void *restrict buf,
	const size_t cap, const size_t need)
{
	struct recv_reply_ctx c = {
		.fd = fd, .buf = buf, .cap = cap, .off = 0, .eof = false
	};
	const size_t want = need < cap ? need : cap;
	struct test_watchdog watchdog = { 0 };
	ev_io w_io;
	ev_timer w_timeout;

	ev_io_init(&w_io, recv_reply_cb, fd, EV_READ);
	w_io.data = &c;
	ev_io_start(loop, &w_io);
	ev_timer_init(&w_timeout, test_watchdog_cb, TEST_WAIT_TIMEOUT_SEC, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired && !c.eof && c.off < want) {
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_timeout);
	ev_io_stop(loop, &w_io);
	return (ssize_t)c.off;
}

/* Watchers invoked during the current drive_loop() round. A custom
 * invoke-pending callback accumulates ev_pending_count() so a round that
 * invokes none can be recognised as quiescence. */
static unsigned int g_drive_invoked;

static void drive_invoke_pending(struct ev_loop *loop)
{
	g_drive_invoked += ev_pending_count(loop);
	ev_invoke_pending(loop);
}

/* Drive the loop until it quiesces: pump non-blocking rounds until a round
 * invokes no watchers, i.e. all reachable I/O has been processed. Local
 * socketpair/loopback writes make the next round's events ready, so this drains
 * the whole exchange with no magic iteration count and no wall-clock wait. The
 * watchdog only backstops a runaway loop; it is never the completion signal. */
static void drive_loop(struct ev_loop *loop)
{
	struct test_watchdog watchdog = { 0 };
	ev_timer w_timeout;
	ev_timer_init(&w_timeout, test_watchdog_cb, TEST_WAIT_TIMEOUT_SEC, 0.0);
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

static void serve_payload(
	struct ev_loop *loop, struct server *restrict s,
	const unsigned char *restrict payload, const size_t payload_len,
	int *restrict peer_fd)
{
	int sv[2] = { -1, -1 };
	struct sockaddr_in sa = { .sin_family = AF_INET };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	/* production dispatches accepted fds non-blocking; match it so the
	 * EAGAIN paths in socks_recv/send_rsp are exercised */
	T_CHECK(socket_set_nonblock(sv[0]));
	socks_serve(s, loop, sv[0], (const struct sockaddr *)&sa);
	T_CHECK(write_all(sv[1], payload, payload_len) == 0);

	*peer_fd = sv[1];
}

static void serve_payload_split(
	struct ev_loop *loop, struct server *restrict s,
	const unsigned char *restrict first, const size_t first_len,
	const unsigned char *restrict second, const size_t second_len,
	int *restrict peer_fd)
{
	int sv[2] = { -1, -1 };
	struct sockaddr_in sa = { .sin_family = AF_INET };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(socket_set_nonblock(sv[0]));
	socks_serve(s, loop, sv[0], (const struct sockaddr *)&sa);
	if (first_len > 0) {
		T_CHECK(write_all(sv[1], first, first_len) == 0);
	}
	drive_loop(loop);
	if (second_len > 0) {
		T_CHECK(write_all(sv[1], second, second_len) == 0);
	}

	*peer_fd = sv[1];
}

/* Wire the stubbed server to `loop` with auth disabled, run test_server_init(),
 * and serve `req` to a fresh socks_ctx; returns the peer (client) fd. Collapses
 * the setup skeleton shared by the no-auth cases; call it after any
 * stub_reset()/STUB overrides the case needs. */
static int serve_socks5_noauth(
	struct ev_loop *loop, struct server *restrict s,
	const unsigned char *restrict req, const size_t reqlen)
{
	s->loop = loop;
	test_conf.auth_required = false;
	test_server_init(s);
	int peer_fd = -1;
	serve_payload(loop, s, req, reqlen, &peer_fd);
	return peer_fd;
}

/* Receive the SOCKS5 reply and assert a NOAUTH method-selection followed by a
 * reply carrying `status` in the REP byte -- the response-assert shared by the
 * error/reject cases. A subcase so the T_EXPECT macros reach the case's `_t_`. */
T_DECLARE_SUBCASE(
	expect_socks5_reply, struct ev_loop *loop, const int peer_fd,
	const unsigned char status)
{
	unsigned char rsp[64];
	const ssize_t n = recv_reply(loop, peer_fd, rsp, sizeof(rsp), 4);
	T_EXPECT(n >= 4);
	T_EXPECT_EQ(rsp[0], SOCKS5);
	T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
	T_EXPECT_EQ(rsp[2], SOCKS5);
	T_EXPECT_EQ(rsp[3], status);
}

/* -------------------------------------------------------------------------
 * fuzz - randomized SOCKS4/4a/5 handshake bytes driven through socks_serve
 * against the stubbed dialer/transfer/ruleset above. Tunable via the
 * FUZZ_SEED and FUZZ_ITER environment variables.
 * ---------------------------------------------------------------------- */

#define FUZZ_DEFAULT_ITERATIONS 1000
#define FUZZ_MAX_CODEC_INPUT 512
#define FUZZ_MAX_HEADER_VALUE 256
#define FUZZ_MAX_HTTP_INPUT 1024
#define FUZZ_MAX_SOCKS_INPUT 512
#define FUZZ_MAX_STREAM_OUTPUT 65536

struct prng {
	uint64_t state[4];
};

static uint64_t fuzz_seed = UINT64_C(0x42);
static size_t fuzz_iterations = FUZZ_DEFAULT_ITERATIONS;

static uint64_t splitmix64_next(uint64_t *restrict state)
{
	uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
	z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
	return z ^ (z >> 31);
}

static void prng_seed(struct prng *restrict p, const uint64_t seed)
{
	uint64_t state = seed;
	for (size_t i = 0; i < 4; i++) {
		p->state[i] = splitmix64_next(&state);
	}
}

static uint64_t rotl64(const uint64_t x, const int k)
{
	return (x << k) | (x >> (64 - k));
}

static uint64_t prng_next(struct prng *restrict p)
{
	const uint64_t result = rotl64(p->state[1] * 5, 7) * 9;
	const uint64_t t = p->state[1] << 17;

	p->state[2] ^= p->state[0];
	p->state[3] ^= p->state[1];
	p->state[1] ^= p->state[2];
	p->state[0] ^= p->state[3];
	p->state[2] ^= t;
	p->state[3] = rotl64(p->state[3], 45);

	return result;
}

static void
prng_fill(struct prng *restrict p, void *restrict buf, const size_t len)
{
	unsigned char *restrict out = buf;
	size_t pos = 0;
	while (pos < len) {
		uint64_t value = prng_next(p);
		for (size_t i = 0; i < sizeof(value) && pos < len; i++) {
			out[pos++] = (unsigned char)(value & UINT64_C(0xff));
			value >>= 8;
		}
	}
}

static size_t
prng_size(struct prng *restrict p, const size_t min, const size_t max)
{
	if (max <= min) {
		return min;
	}
	return min + (size_t)(prng_next(p) % (uint64_t)(max - min + 1));
}

static bool prng_bool(struct prng *restrict p)
{
	return (prng_next(p) & 1) != 0;
}

static bool read_uintmax_env(const char *restrict name, uintmax_t *restrict out)
{
	const char *const value = getenv(name);
	if (value == NULL || value[0] == '\0') {
		return false;
	}

	errno = 0;
	char *end = NULL;
	const uintmax_t parsed = strtoumax(value, &end, 0);
	if (errno != 0 || end == value || *end != '\0') {
		return false;
	}
	*out = parsed;
	return true;
}

static uint64_t read_seed(void)
{
	uintmax_t value;
	if (!read_uintmax_env("FUZZ_SEED", &value) || value > UINT64_MAX) {
		return UINT64_C(0x42);
	}
	return (uint64_t)value;
}

static size_t read_iterations(void)
{
	uintmax_t value;
	if (!read_uintmax_env("FUZZ_ITER", &value) || value > SIZE_MAX) {
		return FUZZ_DEFAULT_ITERATIONS;
	}
	return (size_t)value;
}

static uint64_t fuzz_case_seed(const uint64_t tag)
{
	return fuzz_seed ^ (tag * UINT64_C(0x9e3779b97f4a7c15));
}

static size_t fuzz_append_random(
	struct prng *restrict p, unsigned char *restrict buf, size_t len,
	const size_t cap, const size_t max_tail)
{
	const size_t space = cap - len;
	const size_t tail =
		prng_size(p, 0, space < max_tail ? space : max_tail);
	prng_fill(p, buf + len, tail);
	return len + tail;
}

static void fuzz_printable(
	struct prng *restrict p, unsigned char *restrict buf, const size_t len)
{
	for (size_t i = 0; i < len; i++) {
		buf[i] = (unsigned char)('a' + (prng_next(p) % 26));
	}
}

static size_t make_socks5_ipv4(
	struct prng *restrict p, unsigned char *restrict buf, const size_t cap)
{
	static const unsigned char prefix[] = {
		SOCKS5,
		0x01,
		SOCKS5AUTH_NOAUTH,
		SOCKS5,
		SOCKS5CMD_CONNECT,
		0x00,
		SOCKS5ADDR_IPV4,
	};
	(void)memcpy(buf, prefix, sizeof(prefix));
	size_t len = sizeof(prefix);
	prng_fill(p, buf + len, 6);
	len += 6;
	return fuzz_append_random(p, buf, len, cap, 16);
}

static size_t make_socks5_domain(
	struct prng *restrict p, unsigned char *restrict buf, const size_t cap)
{
	static const unsigned char prefix[] = {
		SOCKS5,
		0x01,
		SOCKS5AUTH_NOAUTH,
		SOCKS5,
		SOCKS5CMD_CONNECT,
		0x00,
		SOCKS5ADDR_DOMAIN,
	};
	(void)memcpy(buf, prefix, sizeof(prefix));
	size_t len = sizeof(prefix);
	const size_t domain_len = prng_size(p, 1, 32);
	buf[len++] = (unsigned char)domain_len;
	fuzz_printable(p, buf + len, domain_len);
	len += domain_len;
	prng_fill(p, buf + len, 2);
	len += 2;
	return fuzz_append_random(p, buf, len, cap, 16);
}

static size_t make_socks5_userpass(
	struct prng *restrict p, unsigned char *restrict buf, const size_t cap)
{
	static const unsigned char prefix[] = {
		SOCKS5,
		0x01,
		SOCKS5AUTH_USERPASS,
		0x01,
	};
	(void)memcpy(buf, prefix, sizeof(prefix));
	size_t len = sizeof(prefix);
	const size_t user_len = prng_size(p, 1, 16);
	const size_t pass_len = prng_size(p, 1, 16);
	buf[len++] = (unsigned char)user_len;
	fuzz_printable(p, buf + len, user_len);
	len += user_len;
	buf[len++] = (unsigned char)pass_len;
	fuzz_printable(p, buf + len, pass_len);
	len += pass_len;
	static const unsigned char req[] = {
		SOCKS5,
		SOCKS5CMD_CONNECT,
		0x00,
		SOCKS5ADDR_IPV4,
	};
	(void)memcpy(buf + len, req, sizeof(req));
	len += sizeof(req);
	prng_fill(p, buf + len, 6);
	len += 6;
	return fuzz_append_random(p, buf, len, cap, 16);
}

static size_t make_socks5_unsupported(
	struct prng *restrict p, unsigned char *restrict buf, const size_t cap)
{
	static const unsigned char prefix[] = {
		SOCKS5,		0x01, SOCKS5AUTH_NOAUTH, SOCKS5,
		SOCKS5CMD_BIND, 0x00, SOCKS5ADDR_IPV4,
	};
	(void)memcpy(buf, prefix, sizeof(prefix));
	size_t len = sizeof(prefix);
	prng_fill(p, buf + len, 6);
	len += 6;
	return fuzz_append_random(p, buf, len, cap, 16);
}

/* A SOCKS5 UDP ASSOCIATE request; with socks5_udp enabled it reaches
 * socks_udp_start instead of being rejected as an unsupported command. */
static size_t make_socks5_udp(
	struct prng *restrict p, unsigned char *restrict buf, const size_t cap)
{
	static const unsigned char prefix[] = {
		SOCKS5,
		0x01,
		SOCKS5AUTH_NOAUTH,
		SOCKS5,
		SOCKS5CMD_UDPASSOCIATE,
		0x00,
		SOCKS5ADDR_IPV4,
	};
	(void)memcpy(buf, prefix, sizeof(prefix));
	size_t len = sizeof(prefix);
	prng_fill(p, buf + len, 6);
	len += 6;
	return fuzz_append_random(p, buf, len, cap, 16);
}

static size_t make_socks4(
	struct prng *restrict p, unsigned char *restrict buf, const size_t cap)
{
	buf[0] = SOCKS4;
	buf[1] = SOCKS4CMD_CONNECT;
	prng_fill(p, buf + 2, 6);
	size_t len = SOCKS4_HDR_LEN;
	const size_t user_len = prng_size(p, 0, 32);
	fuzz_printable(p, buf + len, user_len);
	len += user_len;
	buf[len++] = '\0';
	return fuzz_append_random(p, buf, len, cap, 16);
}

static size_t make_socks4a(
	struct prng *restrict p, unsigned char *restrict buf, const size_t cap)
{
	buf[0] = SOCKS4;
	buf[1] = SOCKS4CMD_CONNECT;
	prng_fill(p, buf + 2, 2);
	buf[4] = 0x00;
	buf[5] = 0x00;
	buf[6] = 0x00;
	buf[7] = 0x01;
	size_t len = SOCKS4_HDR_LEN;
	buf[len++] = 'u';
	buf[len++] = '\0';
	const size_t domain_len = prng_size(p, 1, 32);
	fuzz_printable(p, buf + len, domain_len);
	len += domain_len;
	buf[len++] = '\0';
	return fuzz_append_random(p, buf, len, cap, 16);
}

static size_t make_socks_payload(
	struct prng *restrict p, unsigned char *restrict buf, const size_t cap)
{
	switch (prng_next(p) % 9) {
	case 0: {
		const size_t len = prng_size(p, 0, cap);
		prng_fill(p, buf, len);
		return len;
	}
	case 1:
		return make_socks5_ipv4(p, buf, cap);
	case 2:
		return make_socks5_domain(p, buf, cap);
	case 3:
		return make_socks5_userpass(p, buf, cap);
	case 4:
		return make_socks5_unsupported(p, buf, cap);
	case 5:
		return make_socks5_udp(p, buf, cap);
	case 6:
		return make_socks4(p, buf, cap);
	case 7:
		return make_socks4a(p, buf, cap);
	default:
		buf[0] = SOCKS5;
		return fuzz_append_random(p, buf, 1, cap, 32);
	}
}

static void fuzz_socks_once(struct prng *restrict p)
{
	int sv[2] = { -1, -1 };
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in sa = { .sin_family = AF_INET };
	unsigned char input[FUZZ_MAX_SOCKS_INPUT];
	const size_t len = make_socks_payload(p, input, sizeof(input));

	T_CHECK(loop != NULL);
	s.loop = loop;
	/* a short timeout keeps a BIND/UDP session (which waits for traffic that
	 * never comes) from lingering across 1000 iterations */
	test_conf.timeout = 0.02;
	test_conf.auth_required = prng_bool(p);
	test_conf.socks5_bind = prng_bool(p);
	test_conf.socks5_udp = prng_bool(p);
	test_server_init(&s);

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(socket_set_nonblock(sv[0]));
	socks_serve(&s, loop, sv[0], (const struct sockaddr *)&sa);
	sv[0] = -1;
	T_CHECK(write_all(sv[1], input, len) == 0);
	T_CHECK(shutdown(sv[1], SHUT_WR) == 0);
	/* Every blocking wait carries a timeout: a fuzzed input that leaves a
	 * watcher active with no timer (e.g. the UDP-relay shape) must fail the
	 * test, not hang the binary. ev_unref keeps the watchdog from itself
	 * holding the loop open, so ev_run still returns as soon as the session
	 * tears down. */
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;
	ev_timer_init(
		&w_timeout, test_watchdog_cb,
		test_timeout_wait_window(test_conf.timeout), 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	ev_unref(loop);
	ev_run(loop, 0);
	ev_ref(loop);
	ev_timer_stop(loop, &w_timeout);
	T_CHECK(!watchdog.fired);

	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(fuzz_socks)
{
	(void)_t_;

	struct prng p;
	prng_seed(&p, fuzz_case_seed(7));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_socks_once(&p);
	}
}

/* The control-path fuzzer above reaches socks_udp_start but never feeds the
 * relay's own UDP socket, so udp_relay_cb / udp_parse_addr / udp_frag_client_recv
 * (the bounds-arithmetic-heavy fragment reassembly) stay unfuzzed. Establish a
 * relay with a valid ASSOCIATE, then flood it with random SOCKS5 UDP datagrams
 * (random FRAG / ATYP / length) and drive the loop. */
static void fuzz_udp_relay_once(struct prng *restrict p)
{
	int sv[2] = { -1, -1 };
	int client_udp = -1;
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	const struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
	static const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_server_init(&s);

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(socket_set_nonblock(sv[0]));
	socks_serve(&s, loop, sv[0], (const struct sockaddr *)&accepted_sa);
	sv[0] = -1;
	T_CHECK(write_all(sv[1], req, sizeof(req)) == 0);
	drive_loop(loop);

	/* The relay must come up every iteration (valid ASSOCIATE, socks5_udp
	 * enabled), otherwise the datagram path below is never fuzzed. */
	unsigned char rsp[64];
	const ssize_t nrsp = recv(sv[1], rsp, sizeof(rsp), MSG_DONTWAIT);
	T_CHECK(nrsp >= 12 && rsp[3] == SOCKS5RSP_SUCCEEDED);

	in_port_t relay_port;
	memcpy(&relay_port, rsp + 10, sizeof(relay_port));
	const struct sockaddr_in relay_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = relay_port,
	};
	client_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);

	static const unsigned char atyps[] = {
		SOCKS5ADDR_IPV4,
		SOCKS5ADDR_IPV6,
		SOCKS5ADDR_DOMAIN,
	};
	const size_t ndatagrams = prng_size(p, 1, 8);
	for (size_t i = 0; i < ndatagrams; i++) {
		unsigned char dg[FUZZ_MAX_SOCKS_INPUT];
		const size_t dglen = prng_size(p, 0, sizeof(dg));
		prng_fill(p, dg, dglen);
		/* Bias toward the SOCKS5 UDP header shape so the parser's
		 * ATYP/FRAG branches are exercised, not just early-rejected. */
		if (dglen >= 4) {
			dg[0] = 0;
			dg[1] = 0; /* RSV */
			if (prng_bool(p)) {
				dg[3] = atyps[prng_size(p, 0, 2)];
			}
		}
		(void)sendto(
			client_udp, dg, dglen, 0,
			(const struct sockaddr *)&relay_sa, sizeof(relay_sa));
		drive_loop(loop);
	}

	/* Close the control connection to tear the (timer-less) relay down; a
	 * datagram that wedges a watcher open would surface as a leak here. */
	T_CHECK(shutdown(sv[1], SHUT_WR) == 0);
	drive_loop(loop);

	if (client_udp >= 0) {
		T_CHECK(close(client_udp) == 0);
	}
	T_CHECK(close(sv[1]) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(fuzz_udp_relay)
{
	(void)_t_;

	struct prng p;
	prng_seed(&p, fuzz_case_seed(8));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_udp_relay_once(&p);
	}
}

/* -------------------------------------------------------------------------
 * regression - protocol handshake, addressing, auth, bind/udp and dialer
 * error cases driven over a socketpair.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(invalid_version_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x06,
		0x00,
		0x00,
		0x00,
	};

	T_CHECK(loop != NULL);
	test_conf_reset();
	s.loop = loop;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[16];
		const ssize_t n = recv_nowait(peer_fd, rsp, sizeof(rsp));
		T_EXPECT(n == 0 || (n < 0 && errno == EAGAIN));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * socks5_req() rejects a request whose own header version byte is not SOCKS5:
 * it logs and drops the connection with no response. That is a distinct path
 * from invalid_version_rejected, whose leading 0x06 is the *auth-negotiation*
 * version and so never gets past socks_dispatch. Complete the auth first, then
 * send a request header with a bad version.
 */
T_DECLARE_CASE(socks5_request_version_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		/* auth: version 5, 1 method, no-auth */
		0x05,
		0x01,
		0x00,
		/* request: version 4 (wrong), CONNECT, rsv, IPv4 1.2.3.4:80 */
		0x04,
		0x01,
		0x00,
		0x01,
		0x01,
		0x02,
		0x03,
		0x04,
		0x00,
		0x50,
	};

	T_CHECK(loop != NULL);
	s.loop = loop;
	/* Reset defensively: the regression-detecting power of this case relies
	 * on dialreq_new() returning NULL (dialreq_available == false), so that a
	 * bug letting the bad version through would build no dialreq and send a
	 * failure reply of length != 2. Ambient STUB.dialreq_available == true
	 * from a prior case would mask that, letting the case pass with the bug. */
	stub_reset();
	test_conf.auth_required = false;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		/* the auth-method reply still arrives ... */
		unsigned char rsp[64];
		const ssize_t n =
			recv_reply(loop, peer_fd, rsp, sizeof(rsp), 2);
		T_EXPECT(n >= 2);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		/* ... and nothing more: the bad request header is dropped
		 * without a reply, unlike an unsupported command/atyp */
		T_EXPECT_EQ(n, (ssize_t)2);
	}
	drive_loop(loop);
	{
		/* the connection is dropped, not left half-open: rejecting the bad
		 * version finalizes the session synchronously (gc_unref -> finalize
		 * -> socket_close in recv_cb), so the peer read observes EOF, not a
		 * still-open EAGAIN */
		unsigned char ch;
		const ssize_t n = recv_nowait(peer_fd, &ch, sizeof(ch));
		T_EXPECT_EQ(n, (ssize_t)0);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_unsupported_command_rsp)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x02, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	T_CHECK(loop != NULL);
	test_conf_reset();
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	T_CALL_SUBCASE(
		expect_socks5_reply, loop, peer_fd, SOCKS5RSP_CMDNOSUPPORT);

	/* A rejected handshake still received the request and sent a reply, so
	 * both client-facing counters must move: accounting the receive side
	 * only at transfer start left this one at zero next to a nonzero send. */
	T_EXPECT_EQ((uintmax_t)s.stats.byt_client_recv, sizeof(req));
	T_EXPECT((uintmax_t)s.stats.byt_client_send > 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_unsupported_atyp_rsp)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x09,
	};

	T_CHECK(loop != NULL);
	test_conf_reset();
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	T_CALL_SUBCASE(
		expect_socks5_reply, loop, peer_fd, SOCKS5RSP_ATYPNOSUPPORT);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_userpass_empty_username_fails)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x02, 0x01, 0x00, 0x00,
	};

	T_CHECK(loop != NULL);
	test_conf_reset();
	s.loop = loop;
	test_conf.auth_required = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n =
			recv_reply(loop, peer_fd, rsp, sizeof(rsp), 4);
		T_EXPECT(n >= 4);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_USERPASS);
		T_EXPECT_EQ(rsp[2], 0x01);
		T_EXPECT_EQ(rsp[3], 0x01);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_no_acceptable_auth_method)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05,
		0x01,
		0x00,
	};

	T_CHECK(loop != NULL);
	test_conf_reset();
	s.loop = loop;
	test_conf.auth_required = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n =
			recv_reply(loop, peer_fd, rsp, sizeof(rsp), 2);
		T_EXPECT(n >= 2);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOACCEPTABLE);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_valid_ipv4_request_connect_fail_rsp)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	T_CHECK(loop != NULL);
	s.loop = loop;
	stub_reset();
	/* parse succeeds and a dialreq is built, so SOCKS5RSP_FAIL comes from
	 * the dialer failing -- not from dialreq_new() returning NULL */
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_PROXY_PROTO;
	test_conf.auth_required = false;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	T_CALL_SUBCASE(expect_socks5_reply, loop, peer_fd, SOCKS5RSP_FAIL);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_userpass_domain_request_connect_fail_rsp)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x02, 0x01, 0x04, 'u',  's',  'e',	'r',  0x04, 'p',
		'a',  's',  's',  0x05, 0x01, 0x00, 0x03, 0x0b, 'e',  'x',  'a',
		'm',  'p',  'l',  'e',	'.',  'c',  'o',  'm',	0x01, 0xbb,
	};

	T_CHECK(loop != NULL);
	s.loop = loop;
	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_PROXY_PROTO;
	test_conf.auth_required = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n =
			recv_reply(loop, peer_fd, rsp, sizeof(rsp), 6);
		T_EXPECT(n >= 6);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_USERPASS);
		T_EXPECT_EQ(rsp[2], 0x01);
		T_EXPECT_EQ(rsp[3], 0x00);
		T_EXPECT_EQ(rsp[4], SOCKS5);
		T_EXPECT_EQ(rsp[5], SOCKS5RSP_FAIL);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_valid_ipv6_request_connect_fail_rsp)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x04, 0x20, 0x01,
		0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x35,
	};

	T_CHECK(loop != NULL);
	s.loop = loop;
	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_PROXY_PROTO;
	test_conf.auth_required = false;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	T_CALL_SUBCASE(expect_socks5_reply, loop, peer_fd, SOCKS5RSP_FAIL);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks4_long_userid_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	unsigned char req[SOCKS4_HDR_LEN + 300];

	T_CHECK(loop != NULL);
	test_conf_reset();
	s.loop = loop;
	test_conf.auth_required = false;
	test_server_init(&s);

	memset(req, 'A', sizeof(req));
	req[0] = SOCKS4;
	req[1] = SOCKS4CMD_CONNECT;
	req[2] = 0x00;
	req[3] = 0x50;
	req[4] = 0x01;
	req[5] = 0x02;
	req[6] = 0x03;
	req[7] = 0x04;

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_reply(
			loop, peer_fd, rsp, sizeof(rsp), SOCKS4_HDR_LEN);
		T_EXPECT(n >= (ssize_t)SOCKS4_HDR_LEN);
		T_EXPECT_EQ(rsp[0], 0x00);
		T_EXPECT_EQ(rsp[1], SOCKS4RSP_REJECTED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks4_valid_connect_rejected_when_dialreq_unavailable)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		SOCKS4, SOCKS4CMD_CONNECT,
		0x00,	0x50,
		0x7f,	0x00,
		0x00,	0x01,
		'u',	's',
		'e',	'r',
		0x00,
	};

	T_CHECK(loop != NULL);
	/* stub_reset (not just test_conf_reset): without it this inherits a prior
	 * case's dialreq_available/dialer_mode, so the REJECTED reply would come
	 * from the dialer-failure path instead of the dialreq==NULL branch this
	 * case targets, masking the regression */
	stub_reset();
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	{
		unsigned char rsp[64];
		const ssize_t n = recv_reply(
			loop, peer_fd, rsp, sizeof(rsp), SOCKS4_HDR_LEN);
		T_EXPECT(n >= (ssize_t)SOCKS4_HDR_LEN);
		T_EXPECT_EQ(rsp[0], 0x00);
		T_EXPECT_EQ(rsp[1], SOCKS4RSP_REJECTED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks4a_domain_connect_dialer_fail_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		SOCKS4, SOCKS4CMD_CONNECT,
		0x01,	0xbb,
		0x00,	0x00,
		0x00,	0x01,
		'u',	0x00,
		'a',	'.',
		'c',	'o',
		'm',	0x00,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_CONNECT;
	STUB.dialer_syserr = EHOSTUNREACH;

	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	{
		unsigned char rsp[64];
		const ssize_t n = recv_reply(
			loop, peer_fd, rsp, sizeof(rsp), SOCKS4_HDR_LEN);
		T_EXPECT(n >= (ssize_t)SOCKS4_HDR_LEN);
		T_EXPECT_EQ(rsp[0], 0x00);
		T_EXPECT_EQ(rsp[1], SOCKS4RSP_REJECTED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_split_payload_connect_fail_rsp)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char part1[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00,
	};
	const unsigned char part2[] = {
		0x01, 0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_CONNECT;
	STUB.dialer_syserr = ECONNREFUSED;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_server_init(&s);

	serve_payload_split(
		loop, &s, part1, sizeof(part1), part2, sizeof(part2), &peer_fd);
	drive_loop(loop);

	T_CALL_SUBCASE(
		expect_socks5_reply, loop, peer_fd, SOCKS5RSP_CONNREFUSED);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_connect_timeout_rsp_ttl_expired)
{
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_NONE;
	test_conf.auth_required = false;
	test_conf.timeout = 0.02;

	/* drive the request handshake under a virtual clock so the connect
	 * timeout fires deterministically without a wall-clock wait */
	vclock_start();
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	/* pump until the dialer is issued: the connection is now in the connect
	 * state with w_timeout armed */
	vclock_pump_until(loop, &STUB.dialer_do_count);
	/* cross the deadline; the next pump fires w_timeout in the connect state */
	vclock_advance(test_conf.timeout + 1.0);

	{
		unsigned char rsp[32];
		const ssize_t n = vclock_recv(
			loop, peer_fd, rsp, sizeof(rsp), sizeof(rsp));
		T_EXPECT(n >= 6);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_TTLEXPIRED);
	}
	T_EXPECT(STUB.dialer_cancel_count > 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	vclock_stop();
}

T_DECLARE_CASE(socks5_ruleset_reject_rsp_fail)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.ruleset_mode = STUB_RULESET_FAIL;
	G.ruleset = (struct ruleset *)&test_conf;

	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));
	drive_loop(loop);

	T_CALL_SUBCASE(expect_socks5_reply, loop, peer_fd, SOCKS5RSP_FAIL);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	G.ruleset = NULL;
}

/* With a ruleset active the SOCKS path routes only TCP CONNECT; a SOCKS5 BIND
 * (or UDP ASSOCIATE) must be rejected with CMDNOSUPPORT rather than misrouted as
 * a CONNECT dial. */
T_DECLARE_CASE(socks5_bind_rejected_under_ruleset)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_BIND, 0x00, SOCKS5ADDR_IPV4,
		0x01, 0x02, 0x03, 0x04, 0x00,		0x50,
	};

	stub_reset();
	test_conf.socks5_bind = true; /* allowed by config... */
	G.ruleset =
		(struct ruleset *)&test_conf; /* ...but a ruleset is active */

	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));
	drive_loop(loop);

	T_CALL_SUBCASE(
		expect_socks5_reply, loop, peer_fd, SOCKS5RSP_CMDNOSUPPORT);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	G.ruleset = NULL;
}

/* A SOCKS4 dial that times out gets 91/REJECTED (SOCKS4 has no TTL code),
 * matching every other SOCKS4 failure path rather than a bare close. */
T_DECLARE_CASE(socks4_connect_timeout_rejected)
{
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		SOCKS4, SOCKS4CMD_CONNECT, 0x00, 0x50, 0x01, 0x02, 0x03, 0x04,
		0x00,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_NONE;
	test_conf.timeout = 0.02;

	vclock_start();
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	vclock_pump_until(loop, &STUB.dialer_do_count);
	vclock_advance(test_conf.timeout + 1.0);

	{
		unsigned char rsp[32];
		const ssize_t n = vclock_recv(
			loop, peer_fd, rsp, sizeof(rsp), SOCKS4_HDR_LEN);
		T_EXPECT(n >= (ssize_t)SOCKS4_HDR_LEN);
		T_EXPECT_EQ(rsp[0], 0x00);
		T_EXPECT_EQ(rsp[1], SOCKS4RSP_REJECTED);
	}
	T_EXPECT(STUB.dialer_cancel_count > 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	vclock_stop();
}

T_DECLARE_CASE(socks5_ruleset_async_then_dialer_fail_noallowed)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.ruleset_mode = STUB_RULESET_ASYNC_OK;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_PROXY_AUTH;
	STUB.dialer_syserr = 0;
	G.ruleset = (struct ruleset *)&test_conf;

	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));
	drive_loop(loop);
	finish_ruleset(loop);
	drive_loop(loop);

	T_CALL_SUBCASE(expect_socks5_reply, loop, peer_fd, SOCKS5RSP_NOALLOWED);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	G.ruleset = NULL;
}

/* A connection torn down while an async ruleset request is still outstanding
 * must cancel that request (socks_ctx_stop STATE_PROCESS ->
 * ruleset_cancel(ctx->ruleset_state)). Drive it via the connect timeout: with
 * the ruleset dispatched but never finished, advancing past the deadline fires
 * w_timeout in STATE_PROCESS, which replies TTL-expired and gc_unrefs the ctx,
 * running the cancellation path. */
T_DECLARE_CASE(socks5_ruleset_async_cancelled_on_timeout)
{
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.ruleset_mode = STUB_RULESET_ASYNC_OK;
	test_conf.timeout = 0.02;
	G.ruleset = (struct ruleset *)&test_conf;

	vclock_start();
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);

	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));
	/* pump until the async ruleset is dispatched: the connection now sits in
	 * STATE_PROCESS holding a ruleset_state, waiting on a finish that never
	 * comes */
	vclock_pump_until(loop, &STUB.ruleset_dispatch_count);
	T_EXPECT(STUB.ruleset_pending_cb != NULL);
	/* cross the deadline; the next pump fires w_timeout in STATE_PROCESS */
	vclock_advance(test_conf.timeout + 1.0);

	{
		unsigned char rsp[32];
		const ssize_t n = vclock_recv(
			loop, peer_fd, rsp, sizeof(rsp), sizeof(rsp));
		T_EXPECT(n >= 6);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_TTLEXPIRED);
	}
	T_EXPECT_EQ(STUB.ruleset_cancel_count, 1);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	G.ruleset = NULL;
	vclock_stop();
}

T_DECLARE_CASE(socks5_dialer_system_error_netunreach)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_SYSTEM;
	STUB.dialer_syserr = ENETUNREACH;

	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	T_CALL_SUBCASE(
		expect_socks5_reply, loop, peer_fd, SOCKS5RSP_NETUNREACH);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_dialer_success_transfer_finished)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_SUCCESS;

	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	T_CALL_SUBCASE(expect_socks5_reply, loop, peer_fd, SOCKS5RSP_SUCCEEDED);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * Regression: a client that doesn't wait for the SOCKS reply before sending
 * payload (e.g. TCP fast open) has its request and payload delivered in a
 * single recv(). The auth negotiation message precedes the connect request
 * in rbuf, so ctx->next has already advanced past it by the time socks5_req
 * finishes -- the forwarded byte count must account for that offset, not
 * just the connect request's own size, or pipelined bytes are computed from
 * the wrong position (or a bogus, oversized count) and never reach upstream.
 */
T_DECLARE_CASE(socks5_pipelined_bytes_forwarded_to_upstream)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int listen_fd = -1, upstream_fd = -1, upstream_peer_fd = -1;
	static const unsigned char payload[] = "hello upstream";
	const unsigned char
		req[] = {
			0x05, 0x01, 0x00, /* auth negotiation: NOAUTH */
			0x05, 0x01, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04,
			0x00, 0x50, /* connect 1.2.3.4:80 */
			'h',  'e',  'l',  'l',	'o',  ' ',  'u',  'p',
			's',  't',  'r',  'e',	'a',  'm', /* pipelined payload */
		};

	/* socks5_sendrsp() calls getsockname() on the dialed fd to report a
	 * bound address, and only understands AF_INET/AF_INET6 -- so the
	 * stubbed upstream must be a real loopback TCP connection, not an
	 * AF_UNIX socketpair. */
	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(listen_fd >= 0);
	struct sockaddr_in listen_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	T_CHECK(bind(listen_fd, (struct sockaddr *)&listen_sa,
		     sizeof(listen_sa)) == 0);
	T_CHECK(listen(listen_fd, 1) == 0);
	socklen_t listen_sa_len = sizeof(listen_sa);
	T_CHECK(getsockname(
			listen_fd, (struct sockaddr *)&listen_sa,
			&listen_sa_len) == 0);
	upstream_fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(upstream_fd >= 0);
	T_CHECK(connect(upstream_fd, (struct sockaddr *)&listen_sa,
			sizeof(listen_sa)) == 0);
	upstream_peer_fd = accept(listen_fd, NULL, NULL);
	T_CHECK(upstream_peer_fd >= 0);
	T_CHECK(close(listen_fd) == 0);

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_SUCCESS;
	STUB.dialer_success_fd = upstream_fd;

	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	{
		unsigned char rsp[64];
		const ssize_t n =
			recv_reply(loop, peer_fd, rsp, sizeof(rsp), 6);
		T_EXPECT(n >= 6);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	}
	{
		unsigned char got[sizeof(payload) - 1] = { 0 };
		const ssize_t n = recv_reply(
			loop, upstream_peer_fd, got, sizeof(got), sizeof(got));
		T_EXPECT_EQ(n, (ssize_t)sizeof(got));
		T_EXPECT(memcmp(got, payload, sizeof(got)) == 0);
	}
	/* the replayed bytes bypass the relay, so only the readahead call site
	 * can count them; uncounted, they would be missing from the uplink */
	T_EXPECT((uintmax_t)s.byt_up >= (uintmax_t)(sizeof(payload) - 1));

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	T_CHECK(close(upstream_peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* 127.0.0.0/8 is entirely loopback on Linux, but a second address in it needs
 * an explicit alias elsewhere. Fill *out with 127.0.0.2:0 and report whether it
 * is bindable here. */
static bool probe_alt_loopback(struct sockaddr_in *restrict out)
{
	*out = (struct sockaddr_in){
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK + 1),
		.sin_port = 0,
	};
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return false;
	}
	const bool ok =
		bind(fd, (const struct sockaddr *)out, sizeof(*out)) == 0;
	(void)close(fd);
	return ok;
}

/*
 * Regression: RFC 1928 section 6 defines the CONNECT reply's BND as the
 * endpoint the server connected from, which the outbound socket reports
 * directly -- not the control-connection host that the wildcard-bound BIND/UDP
 * sockets have to borrow. The two answers only differ when the control and
 * outbound sockets sit on different loopback hosts, so put the control
 * connection on 127.0.0.2 and the upstream on 127.0.0.1.
 */
T_DECLARE_CASE(socks5_connect_reply_reports_outbound_sockname)
{
	/* probe before allocating: T_SKIPNOW longjmps past any cleanup */
	struct sockaddr_in ctl_sa;
	if (!probe_alt_loopback(&ctl_sa)) {
		T_SKIPNOW();
	}

	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int ctl_listen_fd = -1, client_fd = -1, accepted_fd = -1;
	int up_listen_fd = -1, upstream_fd = -1, upstream_peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, /* auth negotiation: NOAUTH */
		0x05, 0x01, 0x00, 0x01, 0x01,
		0x02, 0x03, 0x04, 0x00, 0x50, /* connect 1.2.3.4:80 */
	};

	T_CHECK(loop != NULL);
	stub_reset();
	s.loop = loop;
	test_conf.auth_required = false;
	test_server_init(&s);

	/* control connection: the accepted fd's local host is 127.0.0.2 */
	ctl_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(ctl_listen_fd >= 0);
	T_CHECK(bind(ctl_listen_fd, (struct sockaddr *)&ctl_sa,
		     sizeof(ctl_sa)) == 0);
	T_CHECK(listen(ctl_listen_fd, 1) == 0);
	socklen_t ctl_len = sizeof(ctl_sa);
	T_CHECK(getsockname(
			ctl_listen_fd, (struct sockaddr *)&ctl_sa, &ctl_len) ==
		0);
	client_fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(client_fd >= 0);
	T_CHECK(connect(client_fd, (struct sockaddr *)&ctl_sa,
			sizeof(ctl_sa)) == 0);
	struct sockaddr_in peer_sa;
	socklen_t peer_len = sizeof(peer_sa);
	accepted_fd =
		accept(ctl_listen_fd, (struct sockaddr *)&peer_sa, &peer_len);
	T_CHECK(accepted_fd >= 0);
	T_CHECK(close(ctl_listen_fd) == 0);
	T_CHECK(socket_set_nonblock(accepted_fd));

	/* upstream connection: both ends on 127.0.0.1 */
	struct sockaddr_in up_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	up_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(up_listen_fd >= 0);
	T_CHECK(bind(up_listen_fd, (struct sockaddr *)&up_sa, sizeof(up_sa)) ==
		0);
	T_CHECK(listen(up_listen_fd, 1) == 0);
	socklen_t up_len = sizeof(up_sa);
	T_CHECK(getsockname(up_listen_fd, (struct sockaddr *)&up_sa, &up_len) ==
		0);
	upstream_fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(upstream_fd >= 0);
	T_CHECK(connect(upstream_fd, (struct sockaddr *)&up_sa,
			sizeof(up_sa)) == 0);
	upstream_peer_fd = accept(up_listen_fd, NULL, NULL);
	T_CHECK(upstream_peer_fd >= 0);
	T_CHECK(close(up_listen_fd) == 0);

	struct sockaddr_in outbound = { 0 };
	socklen_t outbound_len = sizeof(outbound);
	T_CHECK(getsockname(
			upstream_fd, (struct sockaddr *)&outbound,
			&outbound_len) == 0);
	/* the premise of the case: the two hosts really do differ */
	T_CHECK(outbound.sin_addr.s_addr != ctl_sa.sin_addr.s_addr);

	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_SUCCESS;
	STUB.dialer_success_fd = upstream_fd;

	socks_serve(&s, loop, accepted_fd, (const struct sockaddr *)&peer_sa);
	T_CHECK(write_all(client_fd, req, sizeof(req)) == 0);
	drive_loop(loop);

	{
		unsigned char rsp[64];
		/* method-select(2) + reply header(4) + IPv4 BND(4) + port(2) */
		const ssize_t n =
			recv_reply(loop, client_fd, rsp, sizeof(rsp), 12);
		T_EXPECT(n >= 12);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
		T_EXPECT_EQ(rsp[5], SOCKS5ADDR_IPV4);
		T_EXPECT(
			memcmp(&rsp[6], &outbound.sin_addr,
			       sizeof(outbound.sin_addr)) == 0);
		T_EXPECT(
			memcmp(&rsp[10], &outbound.sin_port,
			       sizeof(outbound.sin_port)) == 0);
	}

	T_CHECK(close(client_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	T_CHECK(close(upstream_peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_dialer_success_connected_transition)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_SUCCESS;

	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	T_CALL_SUBCASE(expect_socks5_reply, loop, peer_fd, SOCKS5RSP_SUCCEEDED);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_bind_disabled_cmdnosupport)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* auth + BIND request (IPv4 0.0.0.0:0) */
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_BIND, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00,		0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	T_CALL_SUBCASE(
		expect_socks5_reply, loop, peer_fd, SOCKS5RSP_CMDNOSUPPORT);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_udp_disabled_cmdnosupport)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* auth + UDP ASSOCIATE request (IPv4 0.0.0.0:0) */
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	T_CALL_SUBCASE(
		expect_socks5_reply, loop, peer_fd, SOCKS5RSP_CMDNOSUPPORT);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_bind_first_reply_succeeded)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_BIND, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00,		0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_bind = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n =
			recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
		/* auth(2) + BIND first reply: hdr(4) + IPv4(4) + port(2) = 12 */
		T_EXPECT(n >= 12);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
		T_EXPECT_EQ(rsp[4], 0x00); /* reserved */
		T_EXPECT_EQ(rsp[5], SOCKS5ADDR_IPV4);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_bind_full_flow)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int connector_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_BIND, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00,		0x00,
	};

	stub_reset();

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_bind = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	/* auth(2) + BIND first reply hdr(4) + IPv4(4) + port(2) = 12 bytes */
	unsigned char rsp[64];
	ssize_t n = recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
	T_EXPECT(n >= 12);
	T_EXPECT_EQ(rsp[2], SOCKS5);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	T_EXPECT_EQ(rsp[5], SOCKS5ADDR_IPV4);

	/* Extract the port from the first BIND response (big-endian at rsp[10]) */
	in_port_t bind_port;
	memcpy(&bind_port, rsp + 10, sizeof(bind_port));

	connector_fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(connector_fd >= 0);
	{
		struct sockaddr_in sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = bind_port,
		};
		T_CHECK(connect(connector_fd, (const struct sockaddr *)&sa,
				sizeof(sa)) == 0);
	}

	drive_loop(loop);

	/* BIND second reply: hdr(4) + IPv4(4) + port(2) = 10 bytes */
	unsigned char rsp2[32];
	const ssize_t n2 = recv_reply(loop, peer_fd, rsp2, sizeof(rsp2), 10);
	T_EXPECT(n2 >= 10);
	T_EXPECT_EQ(rsp2[0], SOCKS5);
	T_EXPECT_EQ(rsp2[1], SOCKS5RSP_SUCCEEDED);
	T_EXPECT_EQ(rsp2[3], SOCKS5ADDR_IPV4);

	T_CHECK(close(connector_fd) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* Client bytes pipelined after the BIND request must be replayed to the peer
 * once it connects, mirroring the CONNECT path's readahead handling; the BIND
 * flow used to silently drop them. */
T_DECLARE_CASE(socks5_bind_pipelined_bytes_forwarded_to_peer)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int connector_fd = -1;
	static const unsigned char pipelined[] = "peerdata";
	static const unsigned char bind_req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_BIND, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00,		0x00,
	};
	/* the BIND request followed by client bytes pipelined in the same recv */
	unsigned char req[sizeof(bind_req) + sizeof(pipelined) - 1];
	memcpy(req, bind_req, sizeof(bind_req));
	memcpy(req + sizeof(bind_req), pipelined, sizeof(pipelined) - 1);

	stub_reset();

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_bind = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	unsigned char rsp[64];
	ssize_t n = recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
	T_EXPECT(n >= 12);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	in_port_t bind_port;
	memcpy(&bind_port, rsp + 10, sizeof(bind_port));

	connector_fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(connector_fd >= 0);
	{
		struct sockaddr_in sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = bind_port,
		};
		T_CHECK(connect(connector_fd, (const struct sockaddr *)&sa,
				sizeof(sa)) == 0);
	}

	drive_loop(loop);

	/* BIND second reply: hdr(4) + IPv4(4) + port(2) = 10 bytes */
	unsigned char rsp2[32];
	const ssize_t n2 = recv_reply(loop, peer_fd, rsp2, sizeof(rsp2), 10);
	T_EXPECT(n2 >= 10);
	T_EXPECT_EQ(rsp2[1], SOCKS5RSP_SUCCEEDED);

	/* The pipelined client bytes must have been replayed to the peer */
	{
		unsigned char got[sizeof(pipelined) - 1] = { 0 };
		const ssize_t ng = recv_reply(
			loop, connector_fd, got, sizeof(got), sizeof(got));
		T_EXPECT_EQ(ng, (ssize_t)sizeof(got));
		T_EXPECT(memcmp(got, pipelined, sizeof(got)) == 0);
	}
	/* the replay to the peer is the BIND path's uplink, counted the same
	 * way as the CONNECT path's */
	T_EXPECT((uintmax_t)s.byt_up >= (uintmax_t)(sizeof(pipelined) - 1));

	T_CHECK(close(connector_fd) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_bind_mismatch_allows)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int connector_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_BIND, 0x00, 0x01,
		127,  0,    0,	  2,	0x00,		0x00,
	};

	stub_reset();

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_bind = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	unsigned char rsp[64];
	ssize_t n = recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
	T_EXPECT(n >= 12);
	T_EXPECT_EQ(rsp[2], SOCKS5);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	T_EXPECT_EQ(rsp[5], SOCKS5ADDR_IPV4);

	in_port_t bind_port;
	memcpy(&bind_port, rsp + 10, sizeof(bind_port));

	connector_fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(connector_fd >= 0);
	{
		struct sockaddr_in sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = bind_port,
		};
		T_CHECK(connect(connector_fd, (const struct sockaddr *)&sa,
				sizeof(sa)) == 0);
	}

	drive_loop(loop);

	unsigned char rsp2[32];
	const ssize_t n2 = recv_reply(loop, peer_fd, rsp2, sizeof(rsp2), 10);
	T_EXPECT(n2 >= 10);
	T_EXPECT_EQ(rsp2[0], SOCKS5);
	T_EXPECT_EQ(rsp2[1], SOCKS5RSP_SUCCEEDED);
	T_EXPECT_EQ(rsp2[3], SOCKS5ADDR_IPV4);

	T_CHECK(close(connector_fd) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_bind_timeout_ttlexpired)
{
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_BIND, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00,		0x00,
	};

	stub_reset();
	test_conf.auth_required = false;
	test_conf.socks5_bind = true;
	test_conf.timeout = 0.02;

	vclock_start();
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		/* first reply: method-select (2) + BIND SUCCEEDED (10); the
		 * connection then waits on w_timeout for an inbound peer */
		size_t off = (size_t)vclock_recv(
			loop, peer_fd, rsp, sizeof(rsp), 12);
		/* cross the deadline; the next pump fires w_timeout -> TTL reply */
		vclock_advance(test_conf.timeout + 1.0);
		off += (size_t)vclock_recv(
			loop, peer_fd, rsp + off, sizeof(rsp) - off,
			sizeof(rsp));
		T_EXPECT(off >= 14);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		/* First BIND reply: SUCCEEDED */
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
		/* Timeout reply: TTLEXPIRED */
		T_EXPECT_EQ(rsp[12], SOCKS5);
		T_EXPECT_EQ(rsp[13], SOCKS5RSP_TTLEXPIRED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	vclock_stop();
}

T_DECLARE_CASE(socks5_udp_first_reply_succeeded)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n =
			recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
		/* auth(2) + UDP reply: hdr(4) + IPv4(4) + port(2) = 12 */
		T_EXPECT(n >= 12);
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
		T_EXPECT_EQ(rsp[4], 0x00); /* reserved */
		T_EXPECT_EQ(rsp[5], SOCKS5ADDR_IPV4);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* The UDP ASSOCIATE reply's BND.ADDR must carry the client-facing address (the
 * local end of the TCP control connection), not the relay socket's INADDR_ANY.
 * A real loopback control connection is required: an AF_UNIX socketpair has no
 * meaningful getsockname() host, which is what masked this in the other cases. */
T_DECLARE_CASE(socks5_udp_associate_advertises_control_addr)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int client_fd = -1;
	int accepted_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_server_init(&s);

	/* Establish a real loopback TCP control connection so the served fd has a
	 * 127.0.0.1 local address to advertise. */
	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(listen_fd >= 0);
	struct sockaddr_in lsa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0,
	};
	T_CHECK(bind(listen_fd, (struct sockaddr *)&lsa, sizeof(lsa)) == 0);
	T_CHECK(listen(listen_fd, 1) == 0);
	socklen_t lsa_len = sizeof(lsa);
	T_CHECK(getsockname(listen_fd, (struct sockaddr *)&lsa, &lsa_len) == 0);
	client_fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(client_fd >= 0);
	T_CHECK(connect(client_fd, (struct sockaddr *)&lsa, sizeof(lsa)) == 0);
	struct sockaddr_in peer_sa;
	socklen_t peer_len = sizeof(peer_sa);
	accepted_fd = accept(listen_fd, (struct sockaddr *)&peer_sa, &peer_len);
	T_CHECK(accepted_fd >= 0);
	T_CHECK(close(listen_fd) == 0);
	T_CHECK(socket_set_nonblock(accepted_fd));

	socks_serve(&s, loop, accepted_fd, (const struct sockaddr *)&peer_sa);
	T_CHECK(write_all(client_fd, req, sizeof(req)) == 0);
	drive_loop(loop);

	{
		unsigned char rsp[64];
		const ssize_t n =
			recv_reply(loop, client_fd, rsp, sizeof(rsp), 12);
		T_EXPECT(n >= 12);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
		T_EXPECT_EQ(rsp[5], SOCKS5ADDR_IPV4);
		/* BND.ADDR (rsp[6..9]) is the control connection's local host */
		T_EXPECT_EQ(rsp[6], 127);
		T_EXPECT_EQ(rsp[7], 0);
		T_EXPECT_EQ(rsp[8], 0);
		T_EXPECT_EQ(rsp[9], 1);
	}

	T_CHECK(close(client_fd) == 0);
	ev_loop_destroy(loop);
}

/* True when a UDP drop-path recv finds the queue empty (EAGAIN/EWOULDBLOCK)
 * rather than a genuine socket error, which a bare `< 0` would also accept,
 * weakening the "datagram was dropped" claim. */
static bool recv_is_empty(const int fd)
{
	unsigned char buf[2048];
	const ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	return n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
}

T_DECLARE_CASE(socks5_udp_relay_roundtrip)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int client_udp = -1;
	int target_udp = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	/* Read UDP relay port from the SOCKS5 response */
	unsigned char rsp[64];
	const ssize_t nrsp = recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
	T_EXPECT(nrsp >= 12);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	/* the handshake never reaches socks_start_transfer, so it is only
	 * accounted if socks_recv counts as it reads */
	T_EXPECT_EQ((uintmax_t)s.stats.byt_client_recv, sizeof(req));
	in_port_t relay_port;
	memcpy(&relay_port, rsp + 10, sizeof(relay_port));

	/* Create a target UDP socket bound to 127.0.0.1:0 */
	target_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(target_udp >= 0);
	{
		struct sockaddr_in target_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(target_udp, (const struct sockaddr *)&target_sa,
			     sizeof(target_sa)) == 0);
	}
	struct sockaddr_in target_bound;
	socklen_t target_bound_len = sizeof(target_bound);
	T_CHECK(getsockname(
			target_udp, (struct sockaddr *)&target_bound,
			&target_bound_len) == 0);

	/* Create client UDP socket bound to 127.0.0.1:0 */
	client_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);
	{
		struct sockaddr_in cli_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(client_udp, (const struct sockaddr *)&cli_sa,
			     sizeof(cli_sa)) == 0);
	}

	/* Build SOCKS5 UDP packet: RSV(2)+FRAG(1)+ATYP(1)+IPv4(4)+port(2)+data */
	unsigned char udp_pkt[10 + 5]; /* header + "hello" */
	udp_pkt[0] = 0;
	udp_pkt[1] = 0; /* RSV */
	udp_pkt[2] = 0; /* FRAG */
	udp_pkt[3] = SOCKS5ADDR_IPV4;
	memcpy(udp_pkt + 4, &target_bound.sin_addr, 4);
	memcpy(udp_pkt + 8, &target_bound.sin_port, 2);
	memcpy(udp_pkt + 10, "hello", 5);

	const struct sockaddr_in relay_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = relay_port,
	};
	T_CHECK(sendto(client_udp, udp_pkt, sizeof(udp_pkt), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(udp_pkt));

	drive_loop(loop);

	/* Check that target received the raw data "hello" */
	{
		unsigned char buf[32];
		const ssize_t n =
			recv(target_udp, buf, sizeof(buf), MSG_DONTWAIT);
		T_EXPECT(n == 5);
		T_EXPECT(memcmp(buf, "hello", 5) == 0);
	}
	/* the payload forwarded to the target, header stripped */
	T_EXPECT_EQ((uintmax_t)s.byt_up, 5);

	/* Target sends reply "world" back to relay */
	T_CHECK(sendto(target_udp, "world", 5, 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == 5);

	drive_loop(loop);

	/* Client should receive SOCKS5-wrapped "world" */
	{
		unsigned char buf[32];
		const ssize_t n =
			recv(client_udp, buf, sizeof(buf), MSG_DONTWAIT);
		/* RSV(2)+FRAG(1)+ATYP(1)+IPv4(4)+port(2)+data(5) = 15 */
		T_EXPECT(n == 15);
		T_EXPECT_EQ(buf[0], 0x00);
		T_EXPECT_EQ(buf[1], 0x00);
		T_EXPECT_EQ(buf[2], 0x00);
		T_EXPECT_EQ(buf[3], SOCKS5ADDR_IPV4);
		T_EXPECT(memcmp(buf + 10, "world", 5) == 0);
	}
	/* what reached the client socket: the rebuilt header plus the payload */
	T_EXPECT_EQ((uintmax_t)s.byt_down, 15);

	T_CHECK(close(client_udp) == 0);
	T_CHECK(close(target_udp) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* The relay forwards a target->client datagram only from a source the client
 * has actually sent to. After the client contacts one target, a datagram from
 * an unsolicited third-party source is dropped, while a reply from the real
 * target is still delivered. */
T_DECLARE_CASE(socks5_udp_relay_filters_unsolicited_source)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int client_udp = -1;
	int target_udp = -1;
	int attacker_udp = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	unsigned char rsp[64];
	const ssize_t nrsp = recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
	T_EXPECT(nrsp >= 12);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	in_port_t relay_port;
	memcpy(&relay_port, rsp + 10, sizeof(relay_port));

	const struct sockaddr_in relay_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = relay_port,
	};

	/* Target and client sockets, both on 127.0.0.1 (distinct ports) */
	target_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(target_udp >= 0);
	client_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);
	attacker_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(attacker_udp >= 0);
	{
		const struct sockaddr_in any = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(target_udp, (const struct sockaddr *)&any,
			     sizeof(any)) == 0);
		T_CHECK(bind(client_udp, (const struct sockaddr *)&any,
			     sizeof(any)) == 0);
		T_CHECK(bind(attacker_udp, (const struct sockaddr *)&any,
			     sizeof(any)) == 0);
	}
	struct sockaddr_in target_bound;
	socklen_t target_bound_len = sizeof(target_bound);
	T_CHECK(getsockname(
			target_udp, (struct sockaddr *)&target_bound,
			&target_bound_len) == 0);

	/* Client sends "hello" to the target, learning the client as the peer
	 * and remembering the target for the source filter. */
	unsigned char udp_pkt[10 + 5];
	udp_pkt[0] = 0;
	udp_pkt[1] = 0;
	udp_pkt[2] = 0;
	udp_pkt[3] = SOCKS5ADDR_IPV4;
	memcpy(udp_pkt + 4, &target_bound.sin_addr, 4);
	memcpy(udp_pkt + 8, &target_bound.sin_port, 2);
	memcpy(udp_pkt + 10, "hello", 5);
	T_CHECK(sendto(client_udp, udp_pkt, sizeof(udp_pkt), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(udp_pkt));
	drive_loop(loop);
	{
		unsigned char buf[32];
		const ssize_t n =
			recv(target_udp, buf, sizeof(buf), MSG_DONTWAIT);
		T_EXPECT(n == 5);
		T_EXPECT(memcmp(buf, "hello", 5) == 0);
	}

	/* An unsolicited third party sends to the relay port: must be dropped */
	T_CHECK(sendto(attacker_udp, "evil", 4, 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == 4);
	drive_loop(loop);
	T_EXPECT(recv_is_empty(client_udp));

	/* A reply from the real target is still delivered to the client */
	T_CHECK(sendto(target_udp, "world", 5, 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == 5);
	drive_loop(loop);
	{
		unsigned char buf[32];
		const ssize_t n =
			recv(client_udp, buf, sizeof(buf), MSG_DONTWAIT);
		T_EXPECT(n == 15);
		T_EXPECT_EQ(buf[3], SOCKS5ADDR_IPV4);
		T_EXPECT(memcmp(buf + 10, "world", 5) == 0);
	}

	T_CHECK(close(attacker_udp) == 0);
	T_CHECK(close(client_udp) == 0);
	T_CHECK(close(target_udp) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * Regression: a datagram larger than the relay's recv buffer (IO_BUFSIZE, 4096)
 * is truncated by the kernel; forwarding the partial payload would silently
 * corrupt it, so the relay must drop it and still handle later datagrams.
 */
T_DECLARE_CASE(socks5_udp_relay_drops_oversized_datagram)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int client_udp = -1;
	int target_udp = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	unsigned char rsp[64];
	const ssize_t nrsp = recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
	T_EXPECT(nrsp >= 12);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	in_port_t relay_port;
	memcpy(&relay_port, rsp + 10, sizeof(relay_port));
	const struct sockaddr_in relay_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = relay_port,
	};

	const struct sockaddr_in any = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0,
	};
	target_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(target_udp >= 0);
	client_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);
	T_CHECK(bind(target_udp, (const struct sockaddr *)&any, sizeof(any)) ==
		0);
	T_CHECK(bind(client_udp, (const struct sockaddr *)&any, sizeof(any)) ==
		0);
	struct sockaddr_in target_bound;
	socklen_t target_bound_len = sizeof(target_bound);
	T_CHECK(getsockname(
			target_udp, (struct sockaddr *)&target_bound,
			&target_bound_len) == 0);

	/* client -> target "hello": learn the client peer, remember the target */
	unsigned char udp_pkt[10 + 5];
	udp_pkt[0] = 0;
	udp_pkt[1] = 0;
	udp_pkt[2] = 0;
	udp_pkt[3] = SOCKS5ADDR_IPV4;
	memcpy(udp_pkt + 4, &target_bound.sin_addr, 4);
	memcpy(udp_pkt + 8, &target_bound.sin_port, 2);
	memcpy(udp_pkt + 10, "hello", 5);
	T_CHECK(sendto(client_udp, udp_pkt, sizeof(udp_pkt), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(udp_pkt));
	drive_loop(loop);
	{
		unsigned char buf[32];
		T_EXPECT(recv(target_udp, buf, sizeof(buf), MSG_DONTWAIT) == 5);
	}

	/* target -> client oversized (> 4096-byte relay buffer): dropped */
	static unsigned char big[8192];
	memset(big, 'A', sizeof(big));
	T_CHECK(sendto(target_udp, big, sizeof(big), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(big));
	drive_loop(loop);
	{
		/* the truncated datagram must not reach the client */
		T_EXPECT(recv_is_empty(client_udp));
	}

	/* a normal-size reply still passes after the drop */
	T_CHECK(sendto(target_udp, "world", 5, 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == 5);
	drive_loop(loop);
	{
		unsigned char buf[64];
		const ssize_t n =
			recv(client_udp, buf, sizeof(buf), MSG_DONTWAIT);
		T_EXPECT(n == 15);
		T_EXPECT(memcmp(buf + 10, "world", 5) == 0);
	}

	T_CHECK(close(client_udp) == 0);
	T_CHECK(close(target_udp) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * The UDP source filter is a bounded (SOCKS_UDP_TARGETS_MAX = 32) move-to-front
 * LRU: sending to more than the cap distinct targets evicts the least-recent.
 * A reply from an evicted target is dropped while a reply from a recent target
 * still passes. NTARGET exceeds the cap; if the cap is ever raised past NTARGET
 * this fails loudly (the eviction assertion) rather than silently losing
 * coverage.
 */
T_DECLARE_CASE(socks5_udp_relay_evicts_oldest_target_at_capacity)
{
	enum { NTARGET = 33 }; /* > SOCKS_UDP_TARGETS_MAX (32) */
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int client_udp = -1;
	int target_udp[NTARGET];
	for (int i = 0; i < NTARGET; i++) {
		target_udp[i] = -1;
	}
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	unsigned char rsp[64];
	const ssize_t nrsp = recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
	T_EXPECT(nrsp >= 12);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	in_port_t relay_port;
	memcpy(&relay_port, rsp + 10, sizeof(relay_port));
	const struct sockaddr_in relay_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = relay_port,
	};

	const struct sockaddr_in any = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0,
	};
	client_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);
	T_CHECK(bind(client_udp, (const struct sockaddr *)&any, sizeof(any)) ==
		0);

	struct sockaddr_in target_bound[NTARGET];
	for (int i = 0; i < NTARGET; i++) {
		target_udp[i] = socket(AF_INET, SOCK_DGRAM, 0);
		T_CHECK(target_udp[i] >= 0);
		T_CHECK(bind(target_udp[i], (const struct sockaddr *)&any,
			     sizeof(any)) == 0);
		socklen_t len = sizeof(target_bound[i]);
		T_CHECK(getsockname(
				target_udp[i],
				(struct sockaddr *)&target_bound[i],
				&len) == 0);
		/* client -> target[i]: relay remembers target[i] (most recent) */
		unsigned char udp_pkt[10 + 1];
		udp_pkt[0] = 0;
		udp_pkt[1] = 0;
		udp_pkt[2] = 0;
		udp_pkt[3] = SOCKS5ADDR_IPV4;
		memcpy(udp_pkt + 4, &target_bound[i].sin_addr, 4);
		memcpy(udp_pkt + 8, &target_bound[i].sin_port, 2);
		udp_pkt[10] = 'x';
		T_CHECK(sendto(client_udp, udp_pkt, sizeof(udp_pkt), 0,
			       (const struct sockaddr *)&relay_sa,
			       sizeof(relay_sa)) == (ssize_t)sizeof(udp_pkt));
		drive_loop(loop);
	}

	/* target[0] is the least-recent of NTARGET > cap targets, so it was
	 * evicted: its reply is dropped by the source filter */
	T_CHECK(sendto(target_udp[0], "old", 3, 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == 3);
	drive_loop(loop);
	{
		T_EXPECT(recv_is_empty(client_udp));
	}

	/* the most-recent target's reply still passes */
	T_CHECK(sendto(target_udp[NTARGET - 1], "new", 3, 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == 3);
	drive_loop(loop);
	{
		unsigned char buf[64];
		const ssize_t n =
			recv(client_udp, buf, sizeof(buf), MSG_DONTWAIT);
		T_EXPECT(n == 13); /* 10-byte SOCKS5 UDP header + "new" */
		T_EXPECT(memcmp(buf + 10, "new", 3) == 0);
	}

	for (int i = 0; i < NTARGET; i++) {
		if (target_udp[i] >= 0) {
			T_CHECK(close(target_udp[i]) == 0);
		}
	}
	T_CHECK(close(client_udp) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * The relay binds its client identity to the first datagram, but only from a
 * source whose IP matches the authenticated TCP client (#91). An off-IP host
 * that reaches the ephemeral relay port first is rejected; the real client
 * (matching IP, different UDP source port) is still accepted.
 */
T_DECLARE_CASE(socks5_udp_relay_rejects_off_ip_first_datagram)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int client_udp = -1;
	int target_udp = -1;
	int attacker_udp = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_server_init(&s);

	/* Inline socks_serve with a concrete TCP client IP (127.0.0.1) so the
	 * source match is active; serve_payload's placeholder 0.0.0.0 would
	 * impose no constraint. */
	int sv[2] = { -1, -1 };
	const struct sockaddr_in tcp_client = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(socket_set_nonblock(sv[0]));
	socks_serve(&s, loop, sv[0], (const struct sockaddr *)&tcp_client);
	peer_fd = sv[1];
	T_CHECK(write_all(peer_fd, req, sizeof(req)) == 0);
	drive_loop(loop);

	unsigned char rsp[64];
	const ssize_t nrsp = recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
	T_EXPECT(nrsp >= 12);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	in_port_t relay_port;
	memcpy(&relay_port, rsp + 10, sizeof(relay_port));
	const struct sockaddr_in relay_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = relay_port,
	};

	target_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(target_udp >= 0);
	client_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);
	attacker_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(attacker_udp >= 0);
	{
		const struct sockaddr_in loop1 = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		};
		/* a different loopback address (127.0.0.2) for the off-IP host */
		const struct sockaddr_in loop2 = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK + 1),
		};
		T_CHECK(bind(target_udp, (const struct sockaddr *)&loop1,
			     sizeof(loop1)) == 0);
		T_CHECK(bind(client_udp, (const struct sockaddr *)&loop1,
			     sizeof(loop1)) == 0);
		T_CHECK(bind(attacker_udp, (const struct sockaddr *)&loop2,
			     sizeof(loop2)) == 0);
	}
	struct sockaddr_in target_bound;
	socklen_t target_bound_len = sizeof(target_bound);
	T_CHECK(getsockname(
			target_udp, (struct sockaddr *)&target_bound,
			&target_bound_len) == 0);

	/* a client->target datagram addressed to the target */
	unsigned char udp_pkt[10 + 5];
	udp_pkt[0] = 0;
	udp_pkt[1] = 0;
	udp_pkt[2] = 0;
	udp_pkt[3] = SOCKS5ADDR_IPV4;
	memcpy(udp_pkt + 4, &target_bound.sin_addr, 4);
	memcpy(udp_pkt + 8, &target_bound.sin_port, 2);
	memcpy(udp_pkt + 10, "hello", 5);

	/* the off-IP host sends first: its source (127.0.0.2) does not match the
	 * TCP client (127.0.0.1), so the relay drops it and does not adopt it as
	 * the client -- nothing reaches the target */
	T_CHECK(sendto(attacker_udp, udp_pkt, sizeof(udp_pkt), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(udp_pkt));
	drive_loop(loop);
	{
		T_EXPECT(recv_is_empty(target_udp));
	}

	/* the real client (127.0.0.1, different UDP port) is accepted and its
	 * datagram is forwarded to the target */
	T_CHECK(sendto(client_udp, udp_pkt, sizeof(udp_pkt), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(udp_pkt));
	drive_loop(loop);
	{
		unsigned char buf[32];
		const ssize_t n =
			recv(target_udp, buf, sizeof(buf), MSG_DONTWAIT);
		T_EXPECT(n == 5);
		T_EXPECT(memcmp(buf, "hello", 5) == 0);
	}

	T_CHECK(close(attacker_udp) == 0);
	T_CHECK(close(client_udp) == 0);
	T_CHECK(close(target_udp) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* IPv6 counterpart of socks5_udp_relay_roundtrip. The relay's UDP socket takes
 * the family of the client connection, so the whole chain is IPv6: this
 * exercises udp_parse_addr()'s SOCKS5ADDR_IPV6 branch (client datagram carrying
 * an IPv6 target) and udp_relay_cb()'s AF_INET6 reply-wrap branch. */
T_DECLARE_CASE(socks5_udp_relay_roundtrip_ipv6)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int client_udp = -1;
	int target_udp = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_server_init(&s);

	/* Serve over an IPv6 client connection so the relay UDP socket is
	 * AF_INET6 (serve_payload hardcodes an AF_INET peer, so inline it). */
	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(socket_set_nonblock(sv[0]));
	{
		const struct sockaddr_in6 client_sa = {
			.sin6_family = AF_INET6,
			.sin6_addr = in6addr_loopback,
		};
		socks_serve(
			&s, loop, sv[0], (const struct sockaddr *)&client_sa);
	}
	T_CHECK(write_all(sv[1], req, sizeof(req)) == 0);
	peer_fd = sv[1];
	drive_loop(loop);

	/* Read the relay port from the IPv6 ASSOCIATE reply. After the 2-byte
	 * method-select reply: VER REP RSV ATYP BND.ADDR(16) BND.PORT(2). */
	unsigned char rsp[64];
	const ssize_t nrsp = recv_reply(loop, peer_fd, rsp, sizeof(rsp), 24);
	T_EXPECT(nrsp >= 24);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	T_EXPECT_EQ(rsp[5], SOCKS5ADDR_IPV6);
	in_port_t relay_port;
	memcpy(&relay_port, rsp + 22, sizeof(relay_port));

	/* Create an IPv6 target UDP socket bound to [::1]:0 */
	target_udp = socket(AF_INET6, SOCK_DGRAM, 0);
	T_CHECK(target_udp >= 0);
	{
		const struct sockaddr_in6 target_sa = {
			.sin6_family = AF_INET6,
			.sin6_addr = in6addr_loopback,
		};
		T_CHECK(bind(target_udp, (const struct sockaddr *)&target_sa,
			     sizeof(target_sa)) == 0);
	}
	struct sockaddr_in6 target_bound;
	socklen_t target_bound_len = sizeof(target_bound);
	T_CHECK(getsockname(
			target_udp, (struct sockaddr *)&target_bound,
			&target_bound_len) == 0);

	/* IPv6 client UDP socket bound to [::1]:0 */
	client_udp = socket(AF_INET6, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);
	{
		const struct sockaddr_in6 cli_sa = {
			.sin6_family = AF_INET6,
			.sin6_addr = in6addr_loopback,
		};
		T_CHECK(bind(client_udp, (const struct sockaddr *)&cli_sa,
			     sizeof(cli_sa)) == 0);
	}

	/* SOCKS5 UDP packet: RSV(2)+FRAG(1)+ATYP(1)+IPv6(16)+port(2)+data */
	unsigned char udp_pkt[22 + 5]; /* header + "hello" */
	udp_pkt[0] = 0;
	udp_pkt[1] = 0; /* RSV */
	udp_pkt[2] = 0; /* FRAG */
	udp_pkt[3] = SOCKS5ADDR_IPV6;
	memcpy(udp_pkt + 4, &target_bound.sin6_addr, 16);
	memcpy(udp_pkt + 20, &target_bound.sin6_port, 2);
	memcpy(udp_pkt + 22, "hello", 5);

	const struct sockaddr_in6 relay_sa = {
		.sin6_family = AF_INET6,
		.sin6_addr = in6addr_loopback,
		.sin6_port = relay_port,
	};
	T_CHECK(sendto(client_udp, udp_pkt, sizeof(udp_pkt), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(udp_pkt));

	drive_loop(loop);

	/* Target must receive the raw data "hello" */
	{
		unsigned char buf[32];
		const ssize_t n =
			recv(target_udp, buf, sizeof(buf), MSG_DONTWAIT);
		T_EXPECT(n == 5);
		T_EXPECT(memcmp(buf, "hello", 5) == 0);
	}

	/* Target replies "world"; the relay must wrap it as an IPv6 datagram */
	T_CHECK(sendto(target_udp, "world", 5, 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == 5);

	drive_loop(loop);

	{
		unsigned char buf[64];
		const ssize_t n =
			recv(client_udp, buf, sizeof(buf), MSG_DONTWAIT);
		/* RSV(2)+FRAG(1)+ATYP(1)+IPv6(16)+port(2)+data(5) = 27 */
		T_EXPECT(n == 27);
		T_EXPECT_EQ(buf[0], 0x00);
		T_EXPECT_EQ(buf[1], 0x00);
		T_EXPECT_EQ(buf[2], 0x00);
		T_EXPECT_EQ(buf[3], SOCKS5ADDR_IPV6);
		T_EXPECT(memcmp(buf + 22, "world", 5) == 0);
	}

	T_CHECK(close(client_udp) == 0);
	T_CHECK(close(target_udp) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_udp_tcp_close_teardown)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);

	{
		unsigned char rsp[64];
		const ssize_t n =
			recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
		T_EXPECT(n >= 12);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	}

	/* Closing the TCP control connection should tear down the relay */
	T_CHECK(close(peer_fd) == 0);
	drive_loop(loop);

	/* Verify that the server session counter is back to zero */
	T_EXPECT(s.num_sessions == 0);

	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_udp_frag_two_parts)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int client_udp = -1;
	int target_udp = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	unsigned char rsp[64];
	const ssize_t nrsp = recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
	T_EXPECT(nrsp >= 12);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	in_port_t relay_port;
	memcpy(&relay_port, rsp + 10, sizeof(relay_port));

	/* Bind a target UDP socket */
	target_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(target_udp >= 0);
	{
		struct sockaddr_in target_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(target_udp, (const struct sockaddr *)&target_sa,
			     sizeof(target_sa)) == 0);
	}
	struct sockaddr_in target_bound;
	socklen_t target_bound_len = sizeof(target_bound);
	T_CHECK(getsockname(
			target_udp, (struct sockaddr *)&target_bound,
			&target_bound_len) == 0);

	/* Bind a client UDP socket */
	client_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);
	{
		struct sockaddr_in cli_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(client_udp, (const struct sockaddr *)&cli_sa,
			     sizeof(cli_sa)) == 0);
	}

	const struct sockaddr_in relay_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = relay_port,
	};

	/* Fragment 1 (FRAG=0x01): "Hello " */
	unsigned char frag1[10 + 6];
	frag1[0] = 0;
	frag1[1] = 0; /* RSV */
	frag1[2] = 0x01; /* FRAG: first, more to come */
	frag1[3] = SOCKS5ADDR_IPV4;
	memcpy(frag1 + 4, &target_bound.sin_addr, 4);
	memcpy(frag1 + 8, &target_bound.sin_port, 2);
	memcpy(frag1 + 10, "Hello ", 6);
	T_CHECK(sendto(client_udp, frag1, sizeof(frag1), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(frag1));

	drive_loop(loop);

	/* Target should have received nothing yet */
	{
		T_EXPECT(recv_is_empty(target_udp));
	}

	/* Fragment 2 (FRAG=0x82): "World" — last fragment */
	unsigned char frag2[10 + 5];
	frag2[0] = 0;
	frag2[1] = 0; /* RSV */
	frag2[2] = 0x82; /* FRAG: pos=2, last */
	frag2[3] = SOCKS5ADDR_IPV4;
	memcpy(frag2 + 4, &target_bound.sin_addr, 4);
	memcpy(frag2 + 8, &target_bound.sin_port, 2);
	memcpy(frag2 + 10, "World", 5);
	T_CHECK(sendto(client_udp, frag2, sizeof(frag2), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(frag2));

	drive_loop(loop);

	/* Target must now receive the reassembled payload "Hello World" */
	{
		unsigned char buf[32];
		const ssize_t n =
			recv(target_udp, buf, sizeof(buf), MSG_DONTWAIT);
		T_EXPECT(n == 11);
		T_EXPECT(memcmp(buf, "Hello World", 11) == 0);
	}

	T_CHECK(close(client_udp) == 0);
	T_CHECK(close(target_udp) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* A standalone datagram (FRAG=0) interleaved into a partial reassembly sequence
 * must reinitialize the reassembly queue (RFC 1928 section 7): the standalone
 * payload is forwarded, and a later in-order fragment of the abandoned sequence
 * is then discarded rather than spliced onto the stale prefix. */
T_DECLARE_CASE(socks5_udp_frag_standalone_resets_sequence)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int client_udp = -1;
	int target_udp = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	unsigned char rsp[64];
	const ssize_t nrsp = recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
	T_EXPECT(nrsp >= 12);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	in_port_t relay_port;
	memcpy(&relay_port, rsp + 10, sizeof(relay_port));

	target_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(target_udp >= 0);
	{
		struct sockaddr_in target_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(target_udp, (const struct sockaddr *)&target_sa,
			     sizeof(target_sa)) == 0);
	}
	struct sockaddr_in target_bound;
	socklen_t target_bound_len = sizeof(target_bound);
	T_CHECK(getsockname(
			target_udp, (struct sockaddr *)&target_bound,
			&target_bound_len) == 0);

	client_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);
	{
		struct sockaddr_in cli_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(client_udp, (const struct sockaddr *)&cli_sa,
			     sizeof(cli_sa)) == 0);
	}

	const struct sockaddr_in relay_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = relay_port,
	};

	/* Fragment 1 (FRAG=0x01): begins a sequence but is never completed */
	unsigned char frag1[10 + 6];
	frag1[0] = 0;
	frag1[1] = 0; /* RSV */
	frag1[2] = 0x01; /* FRAG: first, more to come */
	frag1[3] = SOCKS5ADDR_IPV4;
	memcpy(frag1 + 4, &target_bound.sin_addr, 4);
	memcpy(frag1 + 8, &target_bound.sin_port, 2);
	memcpy(frag1 + 10, "Hello ", 6);
	T_CHECK(sendto(client_udp, frag1, sizeof(frag1), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(frag1));
	drive_loop(loop);
	T_EXPECT(recv_is_empty(target_udp));

	/* Standalone datagram (FRAG=0x00): forwarded immediately and resets the
	 * pending sequence */
	unsigned char solo[10 + 4];
	solo[0] = 0;
	solo[1] = 0; /* RSV */
	solo[2] = 0x00; /* FRAG: standalone */
	solo[3] = SOCKS5ADDR_IPV4;
	memcpy(solo + 4, &target_bound.sin_addr, 4);
	memcpy(solo + 8, &target_bound.sin_port, 2);
	memcpy(solo + 10, "solo", 4);
	T_CHECK(sendto(client_udp, solo, sizeof(solo), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(solo));
	drive_loop(loop);
	{
		unsigned char buf[32];
		const ssize_t n =
			recv(target_udp, buf, sizeof(buf), MSG_DONTWAIT);
		T_EXPECT(n == 4);
		T_EXPECT(memcmp(buf, "solo", 4) == 0);
	}

	/* Fragment 2 (FRAG=0x82, last) of the abandoned sequence: with the queue
	 * reset it is now out of order and dropped, not spliced onto "Hello " */
	unsigned char frag2[10 + 5];
	frag2[0] = 0;
	frag2[1] = 0; /* RSV */
	frag2[2] = 0x82; /* FRAG: pos=2, last */
	frag2[3] = SOCKS5ADDR_IPV4;
	memcpy(frag2 + 4, &target_bound.sin_addr, 4);
	memcpy(frag2 + 8, &target_bound.sin_port, 2);
	memcpy(frag2 + 10, "World", 5);
	T_CHECK(sendto(client_udp, frag2, sizeof(frag2), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(frag2));
	drive_loop(loop);
	T_EXPECT(recv_is_empty(target_udp));

	T_CHECK(close(client_udp) == 0);
	T_CHECK(close(target_udp) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* A fragment sequence that stalls mid-reassembly is discarded when the
 * per-association reassembly timer fires (RFC 1928 section 7); a later fragment
 * of the abandoned sequence is then dropped, not spliced onto the stale prefix.
 * Driven under the virtual clock so the timeout is deterministic. */
T_DECLARE_CASE(socks5_udp_frag_reassembly_timeout)
{
	struct server s = { 0 };
	int peer_fd = -1;
	int client_udp = -1;
	int target_udp = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;

	vclock_start();
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	unsigned char rsp[64];
	const ssize_t nrsp = vclock_recv(loop, peer_fd, rsp, sizeof(rsp), 12);
	T_EXPECT(nrsp >= 12);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	in_port_t relay_port;
	memcpy(&relay_port, rsp + 10, sizeof(relay_port));

	target_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(target_udp >= 0);
	{
		struct sockaddr_in target_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(target_udp, (const struct sockaddr *)&target_sa,
			     sizeof(target_sa)) == 0);
	}
	struct sockaddr_in target_bound;
	socklen_t target_bound_len = sizeof(target_bound);
	T_CHECK(getsockname(
			target_udp, (struct sockaddr *)&target_bound,
			&target_bound_len) == 0);

	client_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);
	{
		struct sockaddr_in cli_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(client_udp, (const struct sockaddr *)&cli_sa,
			     sizeof(cli_sa)) == 0);
	}

	const struct sockaddr_in relay_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = relay_port,
	};

	/* Fragment 1 (FRAG=0x01): starts a sequence and arms the timer */
	unsigned char frag1[10 + 6];
	frag1[0] = 0;
	frag1[1] = 0; /* RSV */
	frag1[2] = 0x01; /* FRAG: first, more to come */
	frag1[3] = SOCKS5ADDR_IPV4;
	memcpy(frag1 + 4, &target_bound.sin_addr, 4);
	memcpy(frag1 + 8, &target_bound.sin_port, 2);
	memcpy(frag1 + 10, "Hello ", 6);
	T_CHECK(sendto(client_udp, frag1, sizeof(frag1), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(frag1));
	drive_loop(loop);
	T_EXPECT(recv_is_empty(target_udp));

	/* cross the reassembly deadline; the next pump fires the timer, which
	 * discards the partial sequence */
	vclock_advance(10.0);
	drive_loop(loop);

	/* Fragment 2 (FRAG=0x82, last): the sequence has been timed out, so it
	 * is out of order and dropped -- the reassembled payload must never
	 * reach the target */
	unsigned char frag2[10 + 5];
	frag2[0] = 0;
	frag2[1] = 0; /* RSV */
	frag2[2] = 0x82; /* FRAG: pos=2, last */
	frag2[3] = SOCKS5ADDR_IPV4;
	memcpy(frag2 + 4, &target_bound.sin_addr, 4);
	memcpy(frag2 + 8, &target_bound.sin_port, 2);
	memcpy(frag2 + 10, "World", 5);
	T_CHECK(sendto(client_udp, frag2, sizeof(frag2), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(frag2));
	drive_loop(loop);
	T_EXPECT(recv_is_empty(target_udp));

	T_CHECK(close(client_udp) == 0);
	T_CHECK(close(target_udp) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
	vclock_stop();
}

T_DECLARE_CASE(socks5_udp_frag_discard_out_of_order)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int client_udp = -1;
	int target_udp = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	unsigned char rsp[64];
	const ssize_t nrsp = recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
	T_EXPECT(nrsp >= 12);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	in_port_t relay_port;
	memcpy(&relay_port, rsp + 10, sizeof(relay_port));

	target_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(target_udp >= 0);
	{
		struct sockaddr_in target_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(target_udp, (const struct sockaddr *)&target_sa,
			     sizeof(target_sa)) == 0);
	}
	struct sockaddr_in target_bound;
	socklen_t target_bound_len = sizeof(target_bound);
	T_CHECK(getsockname(
			target_udp, (struct sockaddr *)&target_bound,
			&target_bound_len) == 0);

	client_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);
	{
		struct sockaddr_in cli_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(client_udp, (const struct sockaddr *)&cli_sa,
			     sizeof(cli_sa)) == 0);
	}

	const struct sockaddr_in relay_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = relay_port,
	};

	/* Send FRAG=2 without a preceding FRAG=1: out-of-order, must discard */
	unsigned char frag2[10 + 5];
	frag2[0] = 0;
	frag2[1] = 0; /* RSV */
	frag2[2] = 0x82; /* FRAG: pos=2, last */
	frag2[3] = SOCKS5ADDR_IPV4;
	memcpy(frag2 + 4, &target_bound.sin_addr, 4);
	memcpy(frag2 + 8, &target_bound.sin_port, 2);
	memcpy(frag2 + 10, "oops!", 5);
	T_CHECK(sendto(client_udp, frag2, sizeof(frag2), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(frag2));

	drive_loop(loop);

	/* Target must receive nothing */
	{
		T_EXPECT(recv_is_empty(target_udp));
	}

	T_CHECK(close(client_udp) == 0);
	T_CHECK(close(target_udp) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* An in-progress fragment sequence followed by a new first fragment whose
 * address is malformed exercises the restart path: the relay drops the old
 * sequence before parsing (so a failed parse cannot leave it accumulating
 * toward a zeroed target) and must recover so a fresh sequence reassembles
 * normally. */
T_DECLARE_CASE(socks5_udp_frag_restart_recovers)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int client_udp = -1;
	int target_udp = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	unsigned char rsp[64];
	const ssize_t nrsp = recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
	T_EXPECT(nrsp >= 12);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	in_port_t relay_port;
	memcpy(&relay_port, rsp + 10, sizeof(relay_port));

	/* Bind a target UDP socket */
	target_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(target_udp >= 0);
	{
		struct sockaddr_in target_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(target_udp, (const struct sockaddr *)&target_sa,
			     sizeof(target_sa)) == 0);
	}
	struct sockaddr_in target_bound;
	socklen_t target_bound_len = sizeof(target_bound);
	T_CHECK(getsockname(
			target_udp, (struct sockaddr *)&target_bound,
			&target_bound_len) == 0);

	/* Bind a client UDP socket */
	client_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);
	{
		struct sockaddr_in cli_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(client_udp, (const struct sockaddr *)&cli_sa,
			     sizeof(cli_sa)) == 0);
	}

	const struct sockaddr_in relay_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = relay_port,
	};

	/* Start a fragmented sequence but leave it incomplete. */
	unsigned char frag1[10 + 3];
	frag1[0] = 0;
	frag1[1] = 0; /* RSV */
	frag1[2] = 0x01; /* FRAG: first, more to come */
	frag1[3] = SOCKS5ADDR_IPV4;
	memcpy(frag1 + 4, &target_bound.sin_addr, 4);
	memcpy(frag1 + 8, &target_bound.sin_port, 2);
	memcpy(frag1 + 10, "AAA", 3);
	T_CHECK(sendto(client_udp, frag1, sizeof(frag1), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(frag1));
	drive_loop(loop);

	/* New first fragment with an unsupported ATYP: the restart drops the
	 * in-progress sequence, then udp_parse_addr fails. */
	const unsigned char bad[5] = { 0, 0, 0x01, 0x09, 0x00 };
	T_CHECK(sendto(client_udp, bad, sizeof(bad), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(bad));
	drive_loop(loop);

	/* Nothing has been forwarded to the target yet. */
	{
		T_EXPECT(recv_is_empty(target_udp));
	}

	/* A fresh, complete sequence now reassembles and forwards normally. */
	unsigned char frag_a[10 + 6];
	frag_a[0] = 0;
	frag_a[1] = 0; /* RSV */
	frag_a[2] = 0x01; /* first */
	frag_a[3] = SOCKS5ADDR_IPV4;
	memcpy(frag_a + 4, &target_bound.sin_addr, 4);
	memcpy(frag_a + 8, &target_bound.sin_port, 2);
	memcpy(frag_a + 10, "Hello ", 6);
	T_CHECK(sendto(client_udp, frag_a, sizeof(frag_a), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(frag_a));
	drive_loop(loop);

	unsigned char frag_b[10 + 5];
	frag_b[0] = 0;
	frag_b[1] = 0; /* RSV */
	frag_b[2] = 0x82; /* pos=2, last */
	frag_b[3] = SOCKS5ADDR_IPV4;
	memcpy(frag_b + 4, &target_bound.sin_addr, 4);
	memcpy(frag_b + 8, &target_bound.sin_port, 2);
	memcpy(frag_b + 10, "World", 5);
	T_CHECK(sendto(client_udp, frag_b, sizeof(frag_b), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(frag_b));
	drive_loop(loop);

	{
		unsigned char buf[32];
		const ssize_t n =
			recv(target_udp, buf, sizeof(buf), MSG_DONTWAIT);
		T_EXPECT(n == 11);
		T_EXPECT(memcmp(buf, "Hello World", 11) == 0);
	}

	T_CHECK(close(client_udp) == 0);
	T_CHECK(close(target_udp) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * Characterizes a documented limitation: RFC 1928 section 7 permits
 * ATYP = DOMAINNAME in the UDP request header, but this relay resolves no
 * domain targets, so such datagrams are dropped (now logged at debug level
 * rather than vanishing silently). Pinned here so the behavior is a decision
 * rather than an accident, and to show the drop does not wedge the relay: a
 * following IPv4 datagram still gets through.
 */
T_DECLARE_CASE(socks5_udp_domain_target_discarded)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	int client_udp = -1;
	int target_udp = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, SOCKS5CMD_UDPASSOCIATE,
		0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_conf.socks5_udp = true;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	unsigned char rsp[64];
	const ssize_t nrsp = recv_reply(loop, peer_fd, rsp, sizeof(rsp), 12);
	T_EXPECT(nrsp >= 12);
	T_EXPECT_EQ(rsp[3], SOCKS5RSP_SUCCEEDED);
	in_port_t relay_port;
	memcpy(&relay_port, rsp + 10, sizeof(relay_port));

	target_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(target_udp >= 0);
	{
		struct sockaddr_in target_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(target_udp, (const struct sockaddr *)&target_sa,
			     sizeof(target_sa)) == 0);
	}
	struct sockaddr_in target_bound;
	socklen_t target_bound_len = sizeof(target_bound);
	T_CHECK(getsockname(
			target_udp, (struct sockaddr *)&target_bound,
			&target_bound_len) == 0);

	client_udp = socket(AF_INET, SOCK_DGRAM, 0);
	T_CHECK(client_udp >= 0);
	{
		struct sockaddr_in cli_sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
			.sin_port = 0,
		};
		T_CHECK(bind(client_udp, (const struct sockaddr *)&cli_sa,
			     sizeof(cli_sa)) == 0);
	}

	const struct sockaddr_in relay_sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = relay_port,
	};

	/* RSV(2) FRAG(1) ATYP=DOMAIN len(1) "localhost" port(2) payload */
	unsigned char dom_pkt[4 + 1 + 9 + 2 + 4];
	dom_pkt[0] = dom_pkt[1] = 0x00;
	dom_pkt[2] = 0x00; /* not fragmented */
	dom_pkt[3] = SOCKS5ADDR_DOMAIN;
	dom_pkt[4] = 9;
	memcpy(dom_pkt + 5, "localhost", 9);
	memcpy(dom_pkt + 14, &target_bound.sin_port, 2);
	memcpy(dom_pkt + 16, "nope", 4);
	T_CHECK(sendto(client_udp, dom_pkt, sizeof(dom_pkt), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(dom_pkt));

	drive_loop(loop);

	/* dropped: the domain target is never resolved or forwarded to */
	{
		T_EXPECT(recv_is_empty(target_udp));
	}

	/* the relay survives it: an IPv4 datagram still forwards */
	unsigned char ok_pkt[10 + 5];
	ok_pkt[0] = ok_pkt[1] = 0x00;
	ok_pkt[2] = 0x00;
	ok_pkt[3] = SOCKS5ADDR_IPV4;
	memcpy(ok_pkt + 4, &target_bound.sin_addr, 4);
	memcpy(ok_pkt + 8, &target_bound.sin_port, 2);
	memcpy(ok_pkt + 10, "hello", 5);
	T_CHECK(sendto(client_udp, ok_pkt, sizeof(ok_pkt), 0,
		       (const struct sockaddr *)&relay_sa,
		       sizeof(relay_sa)) == (ssize_t)sizeof(ok_pkt));

	drive_loop(loop);

	{
		unsigned char buf[32];
		const ssize_t n =
			recv(target_udp, buf, sizeof(buf), MSG_DONTWAIT);
		T_EXPECT(n == 5);
		T_EXPECT(memcmp(buf, "hello", 5) == 0);
	}

	T_CHECK(close(client_udp) == 0);
	T_CHECK(close(target_udp) == 0);
	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_dialer_err_resolve_hostunreach)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_RESOLVE;
	STUB.dialer_syserr = 0;

	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	T_CALL_SUBCASE(
		expect_socks5_reply, loop, peer_fd, SOCKS5RSP_HOSTUNREACH);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_dialer_err_system_hostunreach)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_SYSTEM;
	STUB.dialer_syserr = EHOSTUNREACH;

	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	T_CALL_SUBCASE(
		expect_socks5_reply, loop, peer_fd, SOCKS5RSP_HOSTUNREACH);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_dialer_err_proxy_refused_connrefused)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_PROXY_REFUSED;
	STUB.dialer_syserr = 0;

	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	T_CALL_SUBCASE(
		expect_socks5_reply, loop, peer_fd, SOCKS5RSP_CONNREFUSED);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_dialer_err_blocked_noallowed)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_BLOCKED;
	STUB.dialer_syserr = 0;

	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	T_CALL_SUBCASE(expect_socks5_reply, loop, peer_fd, SOCKS5RSP_NOALLOWED);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_unknown_command_cmdnosupport)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* auth + unknown command 0x04 + IPv4 target */
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x04, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	T_CALL_SUBCASE(
		expect_socks5_reply, loop, peer_fd, SOCKS5RSP_CMDNOSUPPORT);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks4_bind_command_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* SOCKS4 BIND request: version=4, command=2, port=80, addr=127.0.0.1 */
	const unsigned char req[] = {
		SOCKS4, 0x02, 0x00, 0x50, 0x7f, 0x00, 0x00, 0x01, 'u', 0x00,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	{
		unsigned char rsp[64];
		const ssize_t n = recv_reply(
			loop, peer_fd, rsp, sizeof(rsp), SOCKS4_RSP_MINLEN);
		T_EXPECT(n >= (ssize_t)SOCKS4_RSP_MINLEN);
		T_EXPECT_EQ(rsp[0], 0x00);
		T_EXPECT_EQ(rsp[1], SOCKS4RSP_REJECTED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * SOCKS4 CONNECT to an IPv4 target that dials successfully must be granted
 * with VN=0x00 and CD=0x5A (SOCKS4RSP_GRANTED), per the SOCKS4 spec.
 */
T_DECLARE_CASE(socks4_connect_success_granted)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		SOCKS4, SOCKS4CMD_CONNECT,
		0x00,	0x50, /* port 80 */
		0x7f,	0x00,
		0x00,	0x01, /* 127.0.0.1 */
		'u',	's',
		'e',	'r',
		0x00,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_SUCCESS;

	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	{
		unsigned char rsp[64];
		const ssize_t n = recv_reply(
			loop, peer_fd, rsp, sizeof(rsp), SOCKS4_RSP_MINLEN);
		T_EXPECT(n >= (ssize_t)SOCKS4_RSP_MINLEN);
		T_EXPECT_EQ(rsp[0], 0x00);
		T_EXPECT_EQ(rsp[1], SOCKS4RSP_GRANTED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * The SOCKS4 USERID field is optional; a request carrying only the NULL
 * terminator must still be accepted and granted on a successful dial.
 */
T_DECLARE_CASE(socks4_empty_userid_connect_success_granted)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		SOCKS4, SOCKS4CMD_CONNECT,
		0x00,	0x50, /* port 80 */
		0x7f,	0x00,
		0x00,	0x01, /* 127.0.0.1 */
		0x00, /* empty USERID */
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_SUCCESS;

	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	{
		unsigned char rsp[64];
		const ssize_t n = recv_reply(
			loop, peer_fd, rsp, sizeof(rsp), SOCKS4_RSP_MINLEN);
		T_EXPECT(n >= (ssize_t)SOCKS4_RSP_MINLEN);
		T_EXPECT_EQ(rsp[0], 0x00);
		T_EXPECT_EQ(rsp[1], SOCKS4RSP_GRANTED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * A SOCKS4 request split across two writes must be reassembled and parsed
 * incrementally, then granted on a successful dial.
 */
T_DECLARE_CASE(socks4_split_request_connect_success_granted)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* split mid-header: VN+CD+port, then DSTIP+USERID+NULL */
	const unsigned char part1[] = {
		SOCKS4,
		SOCKS4CMD_CONNECT,
		0x00,
		0x50,
	};
	const unsigned char part2[] = {
		0x7f, 0x00, 0x00, 0x01, 'u', 's', 'r', 0x00,
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_SUCCESS;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_server_init(&s);

	serve_payload_split(
		loop, &s, part1, sizeof(part1), part2, sizeof(part2), &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_reply(
			loop, peer_fd, rsp, sizeof(rsp), SOCKS4_RSP_MINLEN);
		T_EXPECT(n >= (ssize_t)SOCKS4_RSP_MINLEN);
		T_EXPECT_EQ(rsp[0], 0x00);
		T_EXPECT_EQ(rsp[1], SOCKS4RSP_GRANTED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * Regression: splitting a SOCKS4A request between the userid-terminating
 * NULL and the domain name must not corrupt or misparse the domain. Before
 * the fix, socks4_req() advanced ctx->next past the userid before the first
 * call returned "need more data", so the second call -- re-entered from
 * scratch, as socks_dispatch() has no SOCKS4/4A sub-state -- computed the
 * domain offset/length relative to the wrong base.
 */
T_DECLARE_CASE(socks4a_split_after_userid_connect_success_granted)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* split exactly at the userid NULL / domain name boundary */
	const unsigned char part1[] = {
		SOCKS4, SOCKS4CMD_CONNECT,
		0x01,	0xbb, /* port 443 */
		0x00,	0x00,
		0x00,	0x01, /* 0.0.0.1 -> SOCKS4A marker */
		'u',	0x00, /* USERID "u" + NULL */
	};
	const unsigned char part2[] = {
		'a', '.', 'c', 'o', 'm', 0x00, /* domain + NULL */
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_SUCCESS;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_conf.auth_required = false;
	test_server_init(&s);

	serve_payload_split(
		loop, &s, part1, sizeof(part1), part2, sizeof(part2), &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_reply(
			loop, peer_fd, rsp, sizeof(rsp), SOCKS4_RSP_MINLEN);
		T_EXPECT(n >= (ssize_t)SOCKS4_RSP_MINLEN);
		T_EXPECT_EQ(rsp[0], 0x00);
		T_EXPECT_EQ(rsp[1], SOCKS4RSP_GRANTED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * SOCKS4A: a DSTIP of 0.0.0.x signals that DSTADDR carries a domain name.
 * A successful dial must be granted with VN=0x00 and CD=0x5A.
 */
T_DECLARE_CASE(socks4a_domain_connect_success_granted)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		SOCKS4, SOCKS4CMD_CONNECT,
		0x01,	0xbb, /* port 443 */
		0x00,	0x00,
		0x00,	0x01, /* 0.0.0.1 -> SOCKS4A marker */
		'u',	0x00, /* USERID "u" + NULL */
		'a',	'.',
		'c',	'o',
		'm',	0x00, /* domain + NULL */
	};

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_SUCCESS;

	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));
	drive_loop(loop);

	{
		unsigned char rsp[64];
		const ssize_t n = recv_reply(
			loop, peer_fd, rsp, sizeof(rsp), SOCKS4_RSP_MINLEN);
		T_EXPECT(n >= (ssize_t)SOCKS4_RSP_MINLEN);
		T_EXPECT_EQ(rsp[0], 0x00);
		T_EXPECT_EQ(rsp[1], SOCKS4RSP_GRANTED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/*
 * SOCKS5 CONNECT with ATYP=DOMAIN and a zero-length domain name must be
 * rejected gracefully rather than crashing.
 */
/* A successful CONNECT must send SOCKS5RSP_SUCCEEDED and start exactly one
 * transfer (exercises the previously-dead stub_xfer capture). */
T_DECLARE_CASE(socks5_connect_success_starts_transfer)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const unsigned char req[] = {
		0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x50,
	};

	T_CHECK(loop != NULL);
	s.loop = loop;
	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_SUCCESS;
	test_conf.auth_required = false;
	test_server_init(&s);

	serve_payload(loop, &s, req, sizeof(req), &peer_fd);
	drive_loop(loop);

	T_CALL_SUBCASE(expect_socks5_reply, loop, peer_fd, SOCKS5RSP_SUCCEEDED);
	T_EXPECT_EQ(stub_xfer_ctx_count, 1);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* SOCKS5 CONNECT to a 255-byte (max) domain must parse without overrunning
 * the char[255] domain buffer. */
T_DECLARE_CASE(socks5_domain_max_length_parses)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	unsigned char req[3 + 4 + 1 + 255 + 2];
	size_t off = 0;

	req[off++] = 0x05;
	req[off++] = 0x01;
	req[off++] = 0x00; /* auth: 1 method, NOAUTH */
	req[off++] = SOCKS5;
	req[off++] = 0x01; /* CONNECT */
	req[off++] = 0x00; /* reserved */
	req[off++] = 0x03; /* ATYP domain */
	req[off++] = 0xff; /* domain length 255 */
	memset(req + off, 'a', 255);
	off += 255;
	req[off++] = 0x00;
	req[off++] = 0x50; /* port 80 */

	T_CHECK(loop != NULL);
	s.loop = loop;
	stub_reset();
	STUB.dialer_mode = STUB_DIALER_NONE; /* dialreq_new NULL -> FAIL rsp */
	test_conf.auth_required = false;
	test_server_init(&s);

	serve_payload(loop, &s, req, off, &peer_fd);
	drive_loop(loop);

	T_CALL_SUBCASE(expect_socks5_reply, loop, peer_fd, SOCKS5RSP_FAIL);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* SOCKS4A with an over-255-byte domain must be rejected (not silently
 * dropped) -- exercises socks4a_req's namelen > FQDN_MAX_LENGTH guard. */
T_DECLARE_CASE(socks4a_overlong_domain_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	unsigned char req[8 + 1 + 300 + 1];
	size_t off = 0;

	req[off++] = 0x04;
	req[off++] = 0x01; /* CONNECT */
	req[off++] = 0x00;
	req[off++] = 0x50; /* port 80 */
	req[off++] = 0x00;
	req[off++] = 0x00;
	req[off++] = 0x00;
	req[off++] = 0x01; /* 0.0.0.1 -> SOCKS4A domain follows */
	req[off++] = 0x00; /* empty userid */
	memset(req + off, 'a', 300);
	off += 300;
	req[off++] = 0x00; /* domain terminator */

	T_CHECK(loop != NULL);
	s.loop = loop;
	stub_reset();
	test_conf.auth_required = false;
	test_server_init(&s);

	serve_payload(loop, &s, req, off, &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[64];
		const ssize_t n =
			recv_reply(loop, peer_fd, rsp, sizeof(rsp), 2);
		T_EXPECT(n >= 2);
		T_EXPECT_EQ(rsp[1], SOCKS4RSP_REJECTED);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(socks5_zero_length_domain_parses_then_fails)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* auth neg + CONNECT to zero-length domain:port */
	const unsigned char req[] = {
		0x05, 0x01, 0x00, /* auth negotiation */
		0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50,
	};

	stub_reset();
	T_CHECK(loop != NULL);
	peer_fd = serve_socks5_noauth(loop, &s, req, sizeof(req));

	{
		unsigned char rsp[64];
		const ssize_t n =
			recv_reply(loop, peer_fd, rsp, sizeof(rsp), (2 + 4));
		/* Must at least reply with auth method selection (2 bytes)
		 * plus a CONNECT response header (4+ bytes). */
		T_EXPECT(n >= (ssize_t)(2 + 4));
		/* socks5_req() parses the zero-length domain without error; the
		 * failure is deterministic SOCKS5RSP_FAIL from the default stub
		 * (dialreq_new returns NULL), not a domain-length rejection. */
		T_EXPECT_EQ(rsp[0], SOCKS5);
		T_EXPECT_EQ(rsp[1], SOCKS5AUTH_NOAUTH);
		T_EXPECT_EQ(rsp[2], SOCKS5);
		T_EXPECT_EQ(rsp[3], SOCKS5RSP_FAIL);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(invalid_version_rejected),
	T_CASE(socks5_request_version_rejected),
	T_CASE(socks5_unsupported_command_rsp),
	T_CASE(socks5_unsupported_atyp_rsp),
	T_CASE(socks5_userpass_empty_username_fails),
	T_CASE(socks5_no_acceptable_auth_method),
	T_CASE(socks5_valid_ipv4_request_connect_fail_rsp),
	T_CASE(socks5_userpass_domain_request_connect_fail_rsp),
	T_CASE(socks5_valid_ipv6_request_connect_fail_rsp),
	T_CASE(socks4_long_userid_rejected),
	T_CASE(socks4_valid_connect_rejected_when_dialreq_unavailable),
	T_CASE(socks4a_domain_connect_dialer_fail_rejected),
	T_CASE(socks5_split_payload_connect_fail_rsp),
	T_CASE(socks5_connect_timeout_rsp_ttl_expired),
	T_CASE(socks5_bind_rejected_under_ruleset),
	T_CASE(socks4_connect_timeout_rejected),
	T_CASE(socks5_ruleset_reject_rsp_fail),
	T_CASE(socks5_ruleset_async_then_dialer_fail_noallowed),
	T_CASE(socks5_ruleset_async_cancelled_on_timeout),
	T_CASE(socks5_dialer_system_error_netunreach),
	T_CASE(socks5_udp_domain_target_discarded),
	T_CASE(socks5_dialer_err_resolve_hostunreach),
	T_CASE(socks5_dialer_err_system_hostunreach),
	T_CASE(socks5_dialer_err_proxy_refused_connrefused),
	T_CASE(socks5_dialer_err_blocked_noallowed),
	T_CASE(socks5_unknown_command_cmdnosupport),
	T_CASE(socks4_bind_command_rejected),
	T_CASE(socks4_connect_success_granted),
	T_CASE(socks4_empty_userid_connect_success_granted),
	T_CASE(socks4_split_request_connect_success_granted),
	T_CASE(socks4a_domain_connect_success_granted),
	T_CASE(socks4a_split_after_userid_connect_success_granted),
	T_CASE(socks5_dialer_success_transfer_finished),
	T_CASE(socks5_pipelined_bytes_forwarded_to_upstream),
	T_CASE(socks5_connect_reply_reports_outbound_sockname),
	T_CASE(socks5_dialer_success_connected_transition),
	T_CASE(socks5_bind_disabled_cmdnosupport),
	T_CASE(socks5_udp_disabled_cmdnosupport),
	T_CASE(socks5_bind_first_reply_succeeded),
	T_CASE(socks5_bind_full_flow),
	T_CASE(socks5_bind_pipelined_bytes_forwarded_to_peer),
	T_CASE(socks5_bind_mismatch_allows),
	T_CASE(socks5_bind_timeout_ttlexpired),
	T_CASE(socks5_udp_first_reply_succeeded),
	T_CASE(socks5_udp_associate_advertises_control_addr),
	T_CASE(socks5_udp_relay_roundtrip),
	T_CASE(socks5_udp_relay_filters_unsolicited_source),
	T_CASE(socks5_udp_relay_drops_oversized_datagram),
	T_CASE(socks5_udp_relay_evicts_oldest_target_at_capacity),
	T_CASE(socks5_udp_relay_rejects_off_ip_first_datagram),
	T_CASE(socks5_udp_relay_roundtrip_ipv6),
	T_CASE(socks5_udp_tcp_close_teardown),
	T_CASE(socks5_udp_frag_two_parts),
	T_CASE(socks5_udp_frag_standalone_resets_sequence),
	T_CASE(socks5_udp_frag_reassembly_timeout),
	T_CASE(socks5_udp_frag_discard_out_of_order),
	T_CASE(socks5_udp_frag_restart_recovers),
	T_CASE(socks5_connect_success_starts_transfer),
	T_CASE(socks5_domain_max_length_parses),
	T_CASE(socks4a_overlong_domain_rejected),
	T_CASE(socks5_zero_length_domain_parses_then_fails),
	T_CASE(fuzz_socks),
	T_CASE(fuzz_udp_relay),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	fuzz_seed = read_seed();
	fuzz_iterations = read_iterations();
	(void)fprintf(
		stderr, "fuzz seed=0x%016" PRIx64 " iter=%zu\n", fuzz_seed,
		fuzz_iterations);

	const int ret = testing_main(argc, argv, suite);
	stub_reset();
	return ret;
}
