/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * server_test - white-box unit tests for server.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   server.c         module under test
 *   conf.c           config data
 *   proto/codec.c    leaf
 *   version.c        leaf
 * All stateful collaborators of server.c (socks, http_proxy, forward,
 * api_server, ruleset, dialer) are replaced by the mocks in the mock section
 * below. The transfer engine gets no stub: server.c has no call site for it,
 * the only one being a static inline in server.h that this unit never
 * instantiates.
 */

#include "server.h"

#include "api_server.h"
#include "conf.h"
#include "forward.h"
#include "http_proxy.h"
#if WITH_RULESET
#include "ruleset/ruleset.h"
#endif
#include "socks.h"

#include "meta/arraysize.h"
#include "os/socket.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - collaborator stubs (socks, http_proxy, forward, api_server,
 * ruleset, dialer), the accept() test stub and shared fixtures.
 *
 * Knobs to steer the stubbed dependencies for the reload and accept-error
 * cases. Defaults (all zero/false) preserve the original behaviour used by
 * the other cases.
 * ---------------------------------------------------------------------- */

static struct {
	/* one-shot accept() failure; 0 lets the call through */
	int accept_fail_errno;
	/* keep accept_fail_errno armed instead of consuming it */
	bool accept_fail_sticky;
	/* accept() calls the interposer saw */
	uint_least32_t accept_calls;
	/* one-shot socket-setter failures; 0 lets the call through */
	int cloexec_fail_errno;
	int nonblock_fail_errno;
	bool dialreq_parse_ok;
	int dialreq_replace_calls;
#if WITH_RULESET
	bool ruleset_new_ok;
	bool ruleset_load_ok;
	int ruleset_new_calls;
	bool ruleset_valid;
	int ruleset_setserver_calls;
	int ruleset_setbasereq_calls;
	int ruleset_free_calls;
	int resolver_setnameserver_calls;
#endif /* WITH_RULESET */
} CONTROL;

/* Restore every knob to its default, so a case starts from the behaviour
 * the untouched mocks provide. */
static void control_reset(void)
{
	memset(&CONTROL, 0, sizeof(CONTROL));
}

static int dialreq_dummy_tag;

/* accept() test stub. Fails the next call -- or, while sticky,
 * every call -- with the armed errno so the accept loop's error classification
 * and its backoff can be driven without a real network failure; unarmed calls
 * pass through unchanged. */
int test_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	CONTROL.accept_calls++;
	const int err = CONTROL.accept_fail_errno;
	if (err == 0) {
		return accept(fd, addr, addrlen);
	}
	if (!CONTROL.accept_fail_sticky) {
		CONTROL.accept_fail_errno = 0;
	}
	errno = err;
	return -1;
}

/* The test build redirects server.c's socket setters to these stubs.
 * Fixture and pass-through calls still use the real csnippets functions. They
 * return 0 or an errno and promise nothing about the global errno, so an armed
 * failure returns its own errno and leaves STALE_ERRNO in the global one.
 * Unarmed calls pass through unchanged. */
int test_socket_set_cloexec(int fd);
int test_socket_set_nonblock(int fd);

/* no socket setup can fail this way, so a report of it can only have come from
 * the global errno */
enum { STALE_ERRNO = EDOM };

int test_socket_set_cloexec(const int fd)
{
	const int err = CONTROL.cloexec_fail_errno;
	if (err == 0) {
		return socket_set_cloexec(fd);
	}
	CONTROL.cloexec_fail_errno = 0;
	errno = STALE_ERRNO;
	return err;
}

int test_socket_set_nonblock(const int fd)
{
	const int err = CONTROL.nonblock_fail_errno;
	if (err == 0) {
		return socket_set_nonblock(fd);
	}
	CONTROL.nonblock_fail_errno = 0;
	errno = STALE_ERRNO;
	return err;
}

/* Log capture: the errno a failed socket setup reports reaches no other
 * output, so a writer sink collects the formatted lines for the case to
 * search. */
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

/* Match a captured line's "<what>: (<err>) " prefix, so the assertion turns on
 * the reported number rather than a locale-dependent strerror text. */
static bool logcap_has_errno(const char *restrict what, const int err)
{
	char needle[64];
	(void)snprintf(needle, sizeof(needle), "%s: (%d) ", what, err);
	return strstr(g_logcap.buf, needle) != NULL;
}

/* -------------------------------------------------------------------------
 * virtual clock - deterministic backoff tests without wall-clock waits.
 *
 * The accept backoff is a libev ev_timer inside the listener, so observing how
 * long it actually delays a retry means controlling the clock libev reads.
 * These strong-symbol interposers shadow clock_gettime/gettimeofday: while
 * enabled they return a virtual time the test advances, so a deadline is
 * crossed by advancing the clock and pumping the loop -- no real waiting.
 * Disabled by default (real time), so every other case is unaffected.
 * ---------------------------------------------------------------------- */

static bool g_vclock_on;
static double g_vclock_sec;

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
 * timer the case arms has a virtual-time deadline. */
static void vclock_start(void)
{
	g_vclock_sec = 1000.0;
	g_vclock_on = true;
}

static void vclock_stop(void)
{
	g_vclock_on = false;
}

/* Advance virtual time by @p step and pump the loop once, so libev fires any
 * deadline the advance crossed. A step of 0 observes what the loop does with
 * no time passing at all. */
static void vclock_step(struct ev_loop *loop, const double step)
{
	g_vclock_sec += step;
	ev_run(loop, EVRUN_NOWAIT);
}

/* Step the frozen-clock loop until @p predicate holds, at most @p steps times
 * so a never-satisfied predicate returns false instead of hanging. */
static bool vclock_step_until(
	struct ev_loop *loop, bool (*predicate)(void *), void *data,
	const double step, const int steps)
{
	for (int i = 0; i < steps; i++) {
		if (predicate(data)) {
			return true;
		}
		vclock_step(loop, step);
	}
	return predicate(data);
}

void socket_set_transparent(const int fd, const bool tproxy)
{
	(void)fd;
	(void)tproxy;
}

#if WITH_TCP_KEEPALIVE_PARAMS
void socket_set_keepalive(
	const int fd, const int idle, const int intvl, const int cnt)
{
	(void)fd;
	(void)idle;
	(void)intvl;
	(void)cnt;
}
#endif /* WITH_TCP_KEEPALIVE_PARAMS */

struct dialreq *
dialreq_parse(const char *restrict addr, const char *restrict csv)
{
	(void)addr;
	(void)csv;
	if (!CONTROL.dialreq_parse_ok) {
		return NULL;
	}
	return (struct dialreq *)&dialreq_dummy_tag;
}

void dialreq_free(struct dialreq *req)
{
	(void)req;
}

bool dialreq_replace(
	struct dialreq **restrict req, const char *restrict addr,
	const char *restrict csv)
{
	CONTROL.dialreq_replace_calls++;
	struct dialreq *restrict newreq = dialreq_parse(addr, csv);
	if (newreq == NULL) {
		return false;
	}
	dialreq_free(*req);
	*req = newreq;
	return true;
}

void api_serve(
	struct server *s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	(void)s;
	(void)loop;
	(void)accepted_sa;
	(void)close(accepted_fd);
}

void forward_serve(
	struct server *s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	(void)s;
	(void)loop;
	(void)accepted_sa;
	(void)close(accepted_fd);
}

void http_proxy_serve(
	struct server *s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	(void)s;
	(void)loop;
	(void)accepted_sa;
	(void)close(accepted_fd);
}

void socks_serve(
	struct server *s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	(void)s;
	(void)loop;
	(void)accepted_sa;
	(void)close(accepted_fd);
}

#if WITH_TPROXY
void tproxy_serve(
	struct server *s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	(void)s;
	(void)loop;
	(void)accepted_sa;
	(void)close(accepted_fd);
}
#endif /* WITH_TPROXY */

#if WITH_RULESET
static int ruleset_dummy_tag;

struct ruleset *ruleset_new(
	struct ev_loop *restrict loop, struct config *restrict conf,
	struct resolver *restrict resolver, struct dialreq *restrict basereq)
{
	(void)loop;
	(void)conf;
	(void)resolver;
	(void)basereq;
	CONTROL.ruleset_new_calls++;
	if (!CONTROL.ruleset_new_ok) {
		return NULL;
	}
	return (struct ruleset *)&ruleset_dummy_tag;
}

void ruleset_setserver(struct ruleset *restrict r, struct server *restrict s)
{
	(void)r;
	(void)s;
	CONTROL.ruleset_setserver_calls++;
}

void resolver_setnameserver(
	struct resolver *restrict r, const struct config *restrict conf)
{
	(void)r;
	(void)conf;
	CONTROL.resolver_setnameserver_calls++;
}

void ruleset_setbasereq(
	struct ruleset *restrict r, struct dialreq *restrict basereq)
{
	(void)r;
	(void)basereq;
	CONTROL.ruleset_setbasereq_calls++;
}

void ruleset_free(struct ruleset *restrict r)
{
	(void)r;
	CONTROL.ruleset_free_calls++;
}

bool ruleset_loadfile(struct ruleset *restrict r, const char *restrict filename)
{
	(void)r;
	(void)filename;
	return CONTROL.ruleset_load_ok;
}

bool ruleset_reloadconfig(
	struct ruleset *restrict r, const char *restrict filename)
{
	(void)r;
	(void)filename;
	return CONTROL.ruleset_load_ok;
}

bool ruleset_isvalid(struct ruleset *restrict r)
{
	(void)r;
	return CONTROL.ruleset_valid;
}

const char *
ruleset_geterror(const struct ruleset *restrict r, size_t *restrict len)
{
	(void)r;
	if (len != NULL) {
		*len = 0;
	}
	return "(nil)";
}
#endif /* WITH_RULESET */

static struct config make_conf(const char *listen)
{
	return (struct config){
		.listen = listen,
		.timeout = 1.0,
		.tcp_nodelay = true,
		.tcp_keepalive = true,
	};
}

struct test_watchdog {
	bool fired;
};

static void
watchdog_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	struct test_watchdog *const watchdog = watcher->data;

	(void)revents;
	watchdog->fired = true;
	ev_break(loop, EVBREAK_ONE);
}

static bool test_wait_until(
	struct ev_loop *loop, bool (*predicate)(void *), void *data,
	const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	ev_timer w_timeout;

	ev_timer_init(&w_timeout, watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired) {
		if (predicate(data)) {
			ev_timer_stop(loop, &w_timeout);
			return true;
		}
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_timeout);
	return predicate(data);
}

static uint_fast16_t bound_port(const int fd)
{
	struct sockaddr_in addr = { 0 };
	socklen_t len = sizeof(addr);

	T_CHECK(getsockname(fd, (struct sockaddr *)&addr, &len) == 0);
	return ntohs(addr.sin_port);
}

static int connect_loopback(const uint_fast16_t port)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;

	T_CHECK(fd >= 0);
	addr = (struct sockaddr_in){
		.sin_family = AF_INET,
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
		.sin_port = htons((uint16_t)port),
	};
	T_CHECK(connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0);
	return fd;
}

static bool served_once(void *data)
{
	const struct server *s = data;
	return s->listeners[0].stats.num_serve == 1;
}

static bool accepted_once(void *data)
{
	const struct server *s = data;
	return s->listeners[0].stats.num_accept == 1;
}

static bool listener_backing_off(void *data)
{
	const struct listener *l = data;
	return !ev_is_active(&l->w_accept) && ev_is_active(&l->w_timer);
}

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - listener lifecycle, accept dispatch and reload cases.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(server_start_accept_and_stop)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint_fast16_t port;
	int client_fd = -1;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, served_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 1);
	T_EXPECT(s.stats.started != -1);

	socket_close(client_fd);
	server_stop(&s);
	T_EXPECT_EQ(s.stats.started, -1);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(server_rejects_when_session_limit_exceeded)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint_fast16_t port;
	int client_fd = -1;

	conf.max_sessions = 1;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	s.num_sessions = 2;
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, accepted_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 0);

	socket_close(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * accept_cb must drain the whole backlog in one callback invocation
 * instead of processing a single rejection and returning -- which would
 * leave the rest queued for another event-loop tick each, one connection
 * at a time, during exactly the overload condition the limiter exists to
 * mitigate. All three connections are queued in the kernel accept
 * backlog before the loop ever runs, so a single ev_run(EVRUN_ONCE) call
 * -- one accept_cb invocation -- must drain and reject all three.
 */
T_DECLARE_CASE(server_accept_cb_drains_backlog_in_one_invocation)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint_fast16_t port;
	int client_fd[3] = { -1, -1, -1 };

	conf.max_sessions = 1;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	s.num_sessions = 1;
	port = bound_port(s.listeners[0].w_accept.fd);
	for (size_t i = 0; i < 3; i++) {
		client_fd[i] = connect_loopback(port);
	}

	ev_run(loop, EVRUN_ONCE);
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 3);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 0);

	for (size_t i = 0; i < 3; i++) {
		socket_close(client_fd[i]);
	}
	server_stop(&s);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(server_rejects_when_full_startup_limit_exceeded)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint_fast16_t port;
	int client_fd = -1;

	conf.startup_limit_full = 1;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	s.stats.num_halfopen = 2;
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, accepted_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 0);

	socket_close(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(server_rejects_when_probabilistic_startup_limit_hits)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint_fast16_t port;
	int client_fd = -1;

	conf.startup_limit_start = 1;
	conf.startup_limit_rate = 100;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	s.stats.num_halfopen = 2;
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, accepted_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 0);

	socket_close(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(server_accept_error_restarts_listener)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	struct listener *l;
	uint_fast16_t port;
	int pipefd[2] = { -1, -1 };
	int client_fd = -1;
	int listener_fd;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	l = &s.listeners[0];
	listener_fd = l->w_accept.fd;
	port = bound_port(listener_fd);
	T_CHECK(pipe(pipefd) == 0);

	ev_io_stop(loop, &l->w_accept);
	ev_io_set(&l->w_accept, pipefd[0], EV_READ);
	ev_io_start(loop, &l->w_accept);
	T_CHECK(write(pipefd[1], "x", 1) == 1);

	T_EXPECT(test_wait_until(loop, listener_backing_off, l, 0.5));
	T_EXPECT(!ev_is_active(&l->w_accept));
	T_EXPECT(ev_is_active(&l->w_timer));

	ev_io_set(&l->w_accept, listener_fd, EV_READ);
	socket_close(pipefd[0]);
	socket_close(pipefd[1]);
	client_fd = connect_loopback(port);
	T_EXPECT(test_wait_until(loop, served_once, &s, 1.0));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 1);

	socket_close(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * accept() reports an error already pending on the incoming connection as its
 * own error code, and accept(2) requires the application to retry those like
 * EAGAIN. Taking one for a listener failure would stop the accept watcher and
 * block every other connection until the backoff timer expires. The client is
 * queued before the loop runs, so the single accept_cb invocation must see the
 * armed failure, retry, and still serve it.
 */
T_DECLARE_SUBCASE(server_accept_pending_error_case, const int err)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint_fast16_t port;
	int client_fd = -1;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);
	CONTROL.accept_fail_errno = err;

	ev_run(loop, EVRUN_ONCE);

	/* the armed failure was consumed, so the retry is what served */
	T_EXPECT_EQ(CONTROL.accept_fail_errno, 0);
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 1);
	T_EXPECT(ev_is_active(&s.listeners[0].w_accept));
	T_EXPECT(!ev_is_active(&s.listeners[0].w_timer));

	socket_close(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(server_accept_retries_pending_network_errors)
{
	static const int pending[] = {
		ENETDOWN,    ENETUNREACH, EHOSTUNREACH,
		ENOPROTOOPT, EOPNOTSUPP,  EPROTO,
#ifdef EHOSTDOWN
		EHOSTDOWN,
#endif
#ifdef ENONET
		ENONET,
#endif
	};
	for (size_t i = 0; i < ARRAY_SIZE(pending); i++) {
		T_CALL_SUBCASE(server_accept_pending_error_case, pending[i]);
	}
}

/*
 * The backoff still belongs to the listener's own failures: a descriptor
 * shortage is not a per-connection error, so the watcher stops and waits for
 * the timer instead of spinning on it.
 */
T_DECLARE_CASE(server_accept_listener_error_backs_off)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint_fast16_t port;
	int client_fd = -1;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);
	CONTROL.accept_fail_errno = EMFILE;

	ev_run(loop, EVRUN_ONCE);

	T_EXPECT_EQ(CONTROL.accept_fail_errno, 0);
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 0);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 0);
	T_EXPECT(!ev_is_active(&s.listeners[0].w_accept));
	T_EXPECT(ev_is_active(&s.listeners[0].w_timer));

	socket_close(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * Every retry has to be delayed, not only the first. libev normalises a
 * timer's deadline against the current time when it stops it, so a fired
 * one-shot timer has nothing left to wait and re-arming it with a bare
 * ev_timer_start() schedules it for now: a persistent accept() failure would
 * then spin the listener at full CPU, flooding the log at ERROR level exactly
 * when the daemon can least afford it.
 *
 * The observations are taken before the assertions so a failing one cannot
 * leave the virtual clock installed for the next case.
 */
T_DECLARE_CASE(server_accept_error_backoff_delays_every_retry)
{
	/* the measured window spans BACKOFF_ROUNDS backoff periods, sampled
	 * BACKOFF_STEPS times each: both scale the listener's own interval, so
	 * no count here is a wall-clock guess */
	enum { BACKOFF_ROUNDS = 4, BACKOFF_STEPS = 16 };

	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;

	vclock_start();
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	T_CHECK(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	struct listener *const l = &s.listeners[0];
	const int client_fd = connect_loopback(bound_port(l->w_accept.fd));

	/* the interposed accept() never consumes the pending connection, so the
	 * listener stays readable for as long as the failure is armed */
	CONTROL.accept_fail_errno = EMFILE;
	CONTROL.accept_fail_sticky = true;
	const bool armed = vclock_step_until(
		loop, listener_backing_off, l, 0.0, BACKOFF_STEPS);
	/* the delay the listener promises on its first failure: every later
	 * retry has to honour the same one, so the measured window and its
	 * sampling resolution are both derived from it */
	const ev_tstamp backoff = ev_timer_remaining(loop, &l->w_timer);
	const double step = backoff / BACKOFF_STEPS;

	const uint_least32_t before = CONTROL.accept_calls;
	for (int i = 0; i < BACKOFF_ROUNDS * BACKOFF_STEPS; i++) {
		vclock_step(loop, step);
	}
	const uint_least32_t retries = CONTROL.accept_calls - before;
	const ev_tstamp last_delay = ev_timer_remaining(loop, &l->w_timer);

	/* the shortage clears: the listener must come back on its own */
	CONTROL.accept_fail_sticky = false;
	CONTROL.accept_fail_errno = 0;
	const bool recovered = vclock_step_until(
		loop, served_once, &s, step, 2 * BACKOFF_STEPS);

	socket_close(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
	vclock_stop();

	T_EXPECT(armed);
	T_EXPECT(backoff > 0.0);
	/* one retry per backoff period, plus at most one on a period boundary */
	T_EXPECT(retries >= 1);
	T_EXPECT(retries <= (uint_least32_t)BACKOFF_ROUNDS + 1);
	/* the latest failure is scheduled ahead, not for the current instant */
	T_EXPECT(last_delay >= 0.0);
	T_EXPECT(recovered);
}

/*
 * max_sessions is a hard cap: at exactly max_sessions concurrent sessions,
 * the next connection must be rejected (n >= max_sessions, not n >).
 */
T_DECLARE_CASE(server_rejects_when_at_max_sessions)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint_fast16_t port;
	int client_fd = -1;

	conf.max_sessions = 1;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	/* Exactly at the limit — the next connection must be rejected. */
	s.num_sessions = 1;
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, accepted_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 0);

	socket_close(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * One below max_sessions must still be allowed — guards against
 * overshooting the >= fix into an off-by-one in the other direction.
 */
T_DECLARE_CASE(server_allows_when_below_max_sessions)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint_fast16_t port;
	int client_fd = -1;

	conf.max_sessions = 2;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	s.num_sessions = 1;
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, served_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 1);

	socket_close(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * max_sessions must also count halfopen (accepted, still mid-dial)
 * connections: num_sessions alone is only incremented once a dial commits,
 * so a burst of in-flight dials could otherwise all pass this check and
 * overshoot the cap once they all commit.
 */
T_DECLARE_CASE(server_rejects_when_halfopen_reaches_max_sessions)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint_fast16_t port;
	int client_fd = -1;

	conf.max_sessions = 1;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	/* No committed sessions yet, but one connection is already mid-dial. */
	s.num_sessions = 0;
	s.stats.num_halfopen = 1;
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, accepted_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 0);

	socket_close(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * startup_limit_full is also a hard cap: at exactly the threshold, the
 * next connection must be rejected (>=, not >).
 */
T_DECLARE_CASE(server_rejects_when_at_full_startup_limit)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint_fast16_t port;
	int client_fd = -1;

	conf.startup_limit_full = 1;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	s.stats.num_halfopen = 1;
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, accepted_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 0);

	socket_close(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * startup_limit_start's probabilistic rejection must already be active at
 * exactly the threshold (>=, not >).
 */
T_DECLARE_CASE(server_rejects_when_at_probabilistic_startup_limit)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint_fast16_t port;
	int client_fd = -1;

	conf.startup_limit_start = 1;
	conf.startup_limit_rate = 100;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	s.stats.num_halfopen = 1;
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, accepted_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 0);

	socket_close(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * max_sessions == 0 means unlimited.
 */
T_DECLARE_CASE(server_zero_max_sessions_allows_unlimited)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint_fast16_t port;
	int client_fd = -1;

	/* max_sessions=0: no limit.  Use a large num_sessions to
	 * confirm the guard is not triggered. */
	conf.max_sessions = 0;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	s.num_sessions = (size_t)999999;
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, served_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 1);

	socket_close(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * Two listeners (proxy + http) on the same server must work independently.
 */
T_DECLARE_CASE(server_dual_listener_independent_accepts)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint_fast16_t port_a, port_b;
	int client_fd = -1;

	conf.http_listen = "127.0.0.1:0";
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	/* Two listeners must have been created (proxy + http). */
	T_EXPECT_EQ(s.num_listeners, (size_t)2);

	port_a = bound_port(s.listeners[0].w_accept.fd);
	port_b = bound_port(s.listeners[1].w_accept.fd);
	T_EXPECT(port_a != port_b);

	/* Connect to the first listener. */
	client_fd = connect_loopback(port_a);
	T_EXPECT(test_wait_until(loop, served_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 1);
	T_EXPECT_EQ(s.listeners[1].stats.num_serve, 0);
	socket_close(client_fd);

	/* Connect to the second listener. */
	client_fd = connect_loopback(port_b);
	{
		const size_t num_serve = s.listeners[0].stats.num_serve;
		struct test_watchdog wd = { 0 };
		ev_timer w;
		ev_timer_init(&w, watchdog_cb, 0.5, 0.0);
		w.data = &wd;
		ev_timer_start(loop, &w);
		while (!wd.fired && s.listeners[1].stats.num_serve == 0) {
			ev_run(loop, EVRUN_ONCE);
		}
		ev_timer_stop(loop, &w);
		T_EXPECT_EQ(s.listeners[0].stats.num_serve, num_serve);
		T_EXPECT_EQ(s.listeners[1].stats.num_serve, 1);
	}
	socket_close(client_fd);

	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * Exercise the listener-setup branches of server_init() for the forward,
 * HTTP and REST API modes.
 */
T_DECLARE_CASE(server_init_multi_mode_listeners)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	conf.forward = "127.0.0.1:8080";
	conf.http_listen = "127.0.0.1:0";
	conf.restapi = "127.0.0.1:0";
	struct server s;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	/* proxy (forward) + http + api */
	T_EXPECT_EQ(s.num_listeners, (size_t)3);

	server_stop(&s);
	ev_loop_destroy(loop);
}

/* resolve_addr() rejects malformed listen addresses. */
T_DECLARE_CASE(server_init_rejects_bad_addresses)
{
	{
		struct ev_loop *loop = ev_loop_new(0);
		T_CHECK(loop != NULL);
		control_reset();
		/* longer than FQDN_MAX_LENGTH + ":65535" */
		char addr[600];
		memset(addr, 'a', sizeof(addr) - 1);
		addr[sizeof(addr) - 1] = '\0';
		struct config conf = make_conf(addr);
		struct server s;
		T_EXPECT(!server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
		ev_loop_destroy(loop);
	}
	{
		struct ev_loop *loop = ev_loop_new(0);
		T_CHECK(loop != NULL);
		control_reset();
		struct config conf = make_conf("not a valid address");
		struct server s;
		T_EXPECT(!server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
		ev_loop_destroy(loop);
	}
}

/*
 * server_init() fails on a later listener after an earlier one already
 * succeeded; the partially-initialized server must still tear down cleanly.
 */
T_DECLARE_CASE(server_init_partial_failure_cleanup)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	/* the proxy listener resolves and binds, but the HTTP listener address
	 * is malformed, so server_init() aborts with one listener already up */
	conf.http_listen = "not a valid address";
	struct server s;

	T_EXPECT(!server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	T_EXPECT_EQ(s.num_listeners, (size_t)1);

	/* server_stop() must release the already-opened listener socket; it also
	 * stops the signal watchers, which server_bind() initialized but never
	 * started, so those stops are safe no-ops and nothing leaks on the
	 * partial-init path */
	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * socket_set_cloexec() and socket_set_nonblock() return the errno; the global
 * one is not theirs. A listener whose socket setup fails must report the
 * returned value -- reading the global errno recovers a plausible one only
 * while the setters are implemented over fcntl(), and would otherwise blame an
 * unrelated error for a bind that never happened.
 */
T_DECLARE_CASE(server_listener_setup_failure_reports_setter_errno)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;

	logcap_start(LOG_LEVEL_ERROR);
	CONTROL.cloexec_fail_errno = EMFILE;
	const bool ok = server_init(&s, loop, &conf, NULL, NULL, NULL, NULL);
	logcap_stop();

	T_EXPECT(!ok);
	/* the armed failure was consumed, so the listener is what tripped it */
	T_EXPECT_EQ(CONTROL.cloexec_fail_errno, 0);
	T_EXPECT_EQ(s.num_listeners, (size_t)0);
	T_EXPECT(logcap_has_errno("socket setup", EMFILE));
	T_EXPECT(!logcap_has_errno("socket setup", STALE_ERRNO));

	server_stop(&s);
	ev_loop_destroy(loop);
}

/* The same for an accepted connection, whose setup runs the second setter:
 * the connection is dropped and the returned errno reported. */
T_DECLARE_CASE(server_accepted_setup_failure_reports_setter_errno)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint_fast16_t port;
	int client_fd = -1;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);
	logcap_start(LOG_LEVEL_ERROR);
	CONTROL.nonblock_fail_errno = ENFILE;

	ev_run(loop, EVRUN_ONCE);
	logcap_stop();

	T_EXPECT_EQ(CONTROL.nonblock_fail_errno, 0);
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 0);
	T_EXPECT(logcap_has_errno("socket setup", ENFILE));
	T_EXPECT(!logcap_has_errno("socket setup", STALE_ERRNO));

	socket_close(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

/* server_stats() aggregates per-listener accept/serve counters. */
T_DECLARE_CASE(server_stats_aggregates_listeners)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	conf.http_listen = "127.0.0.1:0";
	struct server s;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	T_EXPECT_EQ(s.num_listeners, (size_t)2);
	s.listeners[0].stats.num_accept = 3;
	s.listeners[0].stats.num_serve = 2;
	s.listeners[1].stats.num_accept = 5;
	s.listeners[1].stats.num_serve = 4;
	/* the authoritative num_sessions/byt_up/byt_down live in the top-level
	 * atomic fields; server_stats must copy those into out (the identically
	 * named s->stats members stay zero) */
	s.num_sessions = 7;
	s.byt_up = 1111;
	s.byt_down = 2222;

	struct server_stats out;
	server_stats(&s, &out);
	T_EXPECT_EQ(out.num_accept, (uint_least64_t)8);
	T_EXPECT_EQ(out.num_serve, (uint_least64_t)6);
	T_EXPECT_EQ(out.num_sessions, (size_t)7);
	T_EXPECT_EQ(out.byt_up, (uint_least64_t)1111);
	T_EXPECT_EQ(out.byt_down, (uint_least64_t)2222);

	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * server_bind() binds the listener sockets (the privileged phase) but must not
 * register the accept watcher yet; server_start() registers it afterwards. This
 * split lets main() bind a privileged port while still privileged, then drop
 * and spawn the I/O thread, then server_start() after the fork.
 */
T_DECLARE_CASE(server_bind_defers_accept_watcher_until_start)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;

	T_EXPECT(server_bind(&s, loop, &conf, NULL, NULL, NULL));
	T_EXPECT_EQ(s.num_listeners, (size_t)1);
	/* bound and listening, but the accept watcher is not registered yet */
	T_EXPECT(!ev_is_active(&s.listeners[0].w_accept));

	server_start(&s, NULL);
	T_EXPECT(ev_is_active(&s.listeners[0].w_accept));

	server_stop(&s);
	ev_loop_destroy(loop);
}

#if WITH_RULESET
/*
 * SIGHUP drives ruleset reload: a failed engine creation leaves the ruleset
 * unset; a successful reload installs it.
 */
T_DECLARE_CASE(server_signal_reload_ruleset)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	conf.ruleset = "ruleset.lua";
	struct server s;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));

	/* engine creation fails -> reload aborts, ruleset stays unset */
	CONTROL.ruleset_new_ok = false;
	ev_feed_event(loop, &s.w_sighup, EV_SIGNAL);
	ev_run(loop, EVRUN_NOWAIT);
	T_EXPECT(s.ruleset == NULL);

	/* engine creation + load succeed -> ruleset installed */
	CONTROL.ruleset_new_ok = true;
	CONTROL.ruleset_load_ok = true;
	CONTROL.ruleset_valid = true;
	ev_feed_event(loop, &s.w_sighup, EV_SIGNAL);
	ev_run(loop, EVRUN_NOWAIT);
	T_EXPECT(s.ruleset != NULL);
	T_EXPECT_EQ(CONTROL.ruleset_setserver_calls, 1);

	server_stop(&s);
	/* the server owns the reload-created ruleset: server_stop frees it
	 * exactly once. It was previously leaked -- main's local stayed NULL
	 * across the reload, so shutdown never freed s->ruleset. */
	T_EXPECT_EQ(CONTROL.ruleset_free_calls, 1);
	ev_loop_destroy(loop);
}

/*
 * The server owns the ruleset installed at server_init (main no longer frees
 * its local copy): server_stop must free it exactly once. A split where main
 * also freed it double-freed after a reload replaced s->ruleset.
 */
T_DECLARE_CASE(server_stop_frees_ruleset_installed_at_init)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;

	T_EXPECT(server_init(
		&s, loop, &conf, NULL, NULL, NULL,
		(struct ruleset *)&ruleset_dummy_tag));
	T_EXPECT(s.ruleset == (struct ruleset *)&ruleset_dummy_tag);

	server_stop(&s);
	T_EXPECT_EQ(CONTROL.ruleset_free_calls, 1);
	T_EXPECT(s.ruleset == NULL);

	ev_loop_destroy(loop);
}

/*
 * SIGHUP with a boot config also reloads the base dial request and pushes it
 * into the live ruleset.
 */
T_DECLARE_CASE(server_signal_reload_boot_basereq)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	conf.boot = "boot.lua";
	struct server s;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));

	CONTROL.ruleset_new_ok = true;
	CONTROL.ruleset_load_ok = true;
	CONTROL.ruleset_valid = true;
	CONTROL.dialreq_parse_ok = true;
	ev_feed_event(loop, &s.w_sighup, EV_SIGNAL);
	ev_run(loop, EVRUN_NOWAIT);

	T_EXPECT(s.ruleset != NULL);
	/* the boot config path rebuilds and re-applies the base request */
	T_EXPECT_EQ(CONTROL.ruleset_setbasereq_calls, 1);
	/* a boot config may change the nameserver, so it is re-applied too */
	T_EXPECT_EQ(CONTROL.resolver_setnameserver_calls, 1);

	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * A boot config that fails to reparse forward/proxy must not push a stale
 * base request into the ruleset: the reload should fail open, keeping the
 * previous request and skipping ruleset_setbasereq.
 */
T_DECLARE_CASE(server_signal_reload_boot_basereq_parse_failure)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	conf.boot = "boot.lua";
	struct server s;
	struct dialreq *const original = (struct dialreq *)&dialreq_dummy_tag;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, original, NULL));

	CONTROL.ruleset_new_ok = true;
	CONTROL.ruleset_load_ok = true;
	CONTROL.ruleset_valid = true;
	CONTROL.dialreq_parse_ok = false;
	ev_feed_event(loop, &s.w_sighup, EV_SIGNAL);
	ev_run(loop, EVRUN_NOWAIT);

	T_EXPECT(s.ruleset != NULL);
	T_EXPECT_EQ(CONTROL.ruleset_setbasereq_calls, 0);
	T_EXPECT_EQ(s.basereq, original);

	server_stop(&s);
	ev_loop_destroy(loop);
}

/* Deliver `w`'s signal to the server and run the handler. */
static void feed_signal(struct ev_loop *loop, ev_signal *w)
{
	ev_feed_event(loop, w, EV_SIGNAL);
	ev_run(loop, EVRUN_NOWAIT);
}

/*
 * A reload whose load fails keeps the previous state: an engine created for
 * it is freed rather than leaked or installed, and an installed ruleset is
 * neither freed, replaced nor attached to the server again.
 */
T_DECLARE_CASE(server_signal_reload_load_failure_keeps_previous)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	conf.ruleset = "ruleset.lua";
	struct server s;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	CONTROL.ruleset_new_ok = true;
	CONTROL.ruleset_load_ok = false;
	CONTROL.ruleset_valid = true;
	feed_signal(loop, &s.w_sighup);
	T_EXPECT_EQ(CONTROL.ruleset_new_calls, 1);
	T_EXPECT_EQ(CONTROL.ruleset_free_calls, 1);
	T_EXPECT_EQ(CONTROL.ruleset_setserver_calls, 0);
	T_EXPECT(s.ruleset == NULL);
	server_stop(&s);

	control_reset();
	struct ruleset *const installed = (struct ruleset *)&ruleset_dummy_tag;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, installed));
	CONTROL.ruleset_new_ok = true;
	CONTROL.ruleset_load_ok = false;
	CONTROL.ruleset_valid = true;
	feed_signal(loop, &s.w_sighup);
	T_EXPECT_EQ(CONTROL.ruleset_new_calls, 0);
	T_EXPECT_EQ(CONTROL.ruleset_free_calls, 0);
	T_EXPECT_EQ(CONTROL.ruleset_setserver_calls, 0);
	T_EXPECT(s.ruleset == installed);
	server_stop(&s);

	ev_loop_destroy(loop);
}

/*
 * A load that succeeds but leaves no ruleset installed drops the engine,
 * whether the reload created it or it was already installed.
 */
T_DECLARE_CASE(server_signal_reload_without_ruleset_drops_engine)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	conf.ruleset = "ruleset.lua";
	struct server s;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	CONTROL.ruleset_new_ok = true;
	CONTROL.ruleset_load_ok = true;
	CONTROL.ruleset_valid = false;
	feed_signal(loop, &s.w_sighup);
	T_EXPECT_EQ(CONTROL.ruleset_free_calls, 1);
	T_EXPECT_EQ(CONTROL.ruleset_setserver_calls, 0);
	T_EXPECT(s.ruleset == NULL);
	server_stop(&s);

	control_reset();
	T_EXPECT(server_init(
		&s, loop, &conf, NULL, NULL, NULL,
		(struct ruleset *)&ruleset_dummy_tag));
	CONTROL.ruleset_load_ok = true;
	CONTROL.ruleset_valid = false;
	feed_signal(loop, &s.w_sighup);
	T_EXPECT_EQ(CONTROL.ruleset_new_calls, 0);
	T_EXPECT_EQ(CONTROL.ruleset_free_calls, 1);
	T_EXPECT(s.ruleset == NULL);
	server_stop(&s);
	/* server_stop does not free the dropped engine a second time */
	T_EXPECT_EQ(CONTROL.ruleset_free_calls, 1);

	ev_loop_destroy(loop);
}

/*
 * A successful reload of an installed ruleset updates it in place: no new
 * engine is created, and the one attached to the server is not attached
 * again.
 */
T_DECLARE_CASE(server_signal_reload_in_place)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	conf.ruleset = "ruleset.lua";
	struct server s;
	struct ruleset *const installed = (struct ruleset *)&ruleset_dummy_tag;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, installed));
	CONTROL.ruleset_new_ok = true;
	CONTROL.ruleset_load_ok = true;
	CONTROL.ruleset_valid = true;
	feed_signal(loop, &s.w_sighup);
	feed_signal(loop, &s.w_sighup);
	T_EXPECT_EQ(CONTROL.ruleset_new_calls, 0);
	T_EXPECT_EQ(CONTROL.ruleset_setserver_calls, 0);
	T_EXPECT_EQ(CONTROL.ruleset_free_calls, 0);
	T_EXPECT(s.ruleset == installed);

	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * A boot config that fails to reload is not applied at all: the base request,
 * the log level and the nameserver keep what the previous config set.
 */
T_DECLARE_CASE(server_signal_reload_boot_failure_skips_reapply)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	conf.boot = "boot.lua";
	conf.loglevel = LOG_LEVEL_VERBOSE;
	struct server s;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	CONTROL.ruleset_new_ok = true;
	CONTROL.ruleset_load_ok = false;
	CONTROL.ruleset_valid = true;
	CONTROL.dialreq_parse_ok = true;
	slog_setlevel(LOG_LEVEL_SILENCE);
	feed_signal(loop, &s.w_sighup);
	const bool level_applied = LOGLEVEL(FATAL);
	slog_setlevel(LOG_LEVEL_SILENCE);
	T_EXPECT(!level_applied);
	T_EXPECT_EQ(CONTROL.dialreq_replace_calls, 0);
	T_EXPECT_EQ(CONTROL.ruleset_setbasereq_calls, 0);
	T_EXPECT_EQ(CONTROL.resolver_setnameserver_calls, 0);
	T_EXPECT(s.ruleset == NULL);

	server_stop(&s);
	ev_loop_destroy(loop);
}

/* SIGHUP with neither a boot config nor a ruleset file reloads nothing. */
T_DECLARE_CASE(server_signal_reload_nothing_reloadable)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	control_reset();
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	CONTROL.ruleset_new_ok = true;
	CONTROL.ruleset_load_ok = true;
	CONTROL.ruleset_valid = true;
	CONTROL.dialreq_parse_ok = true;
	feed_signal(loop, &s.w_sighup);
	T_EXPECT_EQ(CONTROL.ruleset_new_calls, 0);
	T_EXPECT_EQ(CONTROL.dialreq_replace_calls, 0);
	T_EXPECT_EQ(CONTROL.resolver_setnameserver_calls, 0);
	T_EXPECT(s.ruleset == NULL);

	server_stop(&s);
	ev_loop_destroy(loop);
}
#endif /* WITH_RULESET */

/*
 * SIGINT and SIGTERM stop the event loop: with a listener still active the
 * loop would otherwise run on until the watchdog fires.
 */
T_DECLARE_CASE(server_signal_int_term_break_loop)
{
	for (int i = 0; i < 2; i++) {
		struct ev_loop *loop = ev_loop_new(0);
		T_CHECK(loop != NULL);
		control_reset();
		struct config conf = make_conf("127.0.0.1:0");
		struct server s;

		T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
		struct test_watchdog watchdog = { 0 };
		ev_timer w_timeout;
		ev_timer_init(&w_timeout, watchdog_cb, 5.0, 0.0);
		w_timeout.data = &watchdog;
		ev_timer_start(loop, &w_timeout);

		ev_feed_event(
			loop, (i == 0) ? &s.w_sigint : &s.w_sigterm, EV_SIGNAL);
		ev_run(loop, 0);
		T_EXPECT(!watchdog.fired);

		ev_timer_stop(loop, &w_timeout);
		server_stop(&s);
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
	T_CASE(server_start_accept_and_stop),
	T_CASE(server_rejects_when_session_limit_exceeded),
	T_CASE(server_accept_cb_drains_backlog_in_one_invocation),
	T_CASE(server_rejects_when_at_max_sessions),
	T_CASE(server_allows_when_below_max_sessions),
	T_CASE(server_rejects_when_halfopen_reaches_max_sessions),
	T_CASE(server_zero_max_sessions_allows_unlimited),
	T_CASE(server_rejects_when_full_startup_limit_exceeded),
	T_CASE(server_rejects_when_at_full_startup_limit),
	T_CASE(server_rejects_when_probabilistic_startup_limit_hits),
	T_CASE(server_rejects_when_at_probabilistic_startup_limit),
	T_CASE(server_accept_error_restarts_listener),
	T_CASE(server_accept_retries_pending_network_errors),
	T_CASE(server_accept_listener_error_backs_off),
	T_CASE(server_accept_error_backoff_delays_every_retry),
	T_CASE(server_dual_listener_independent_accepts),
	T_CASE(server_init_multi_mode_listeners),
	T_CASE(server_init_rejects_bad_addresses),
	T_CASE(server_init_partial_failure_cleanup),
	T_CASE(server_listener_setup_failure_reports_setter_errno),
	T_CASE(server_accepted_setup_failure_reports_setter_errno),
	T_CASE(server_stats_aggregates_listeners),
	T_CASE(server_bind_defers_accept_watcher_until_start),
#if WITH_RULESET
	T_CASE(server_signal_reload_ruleset),
	T_CASE(server_stop_frees_ruleset_installed_at_init),
	T_CASE(server_signal_reload_boot_basereq),
	T_CASE(server_signal_reload_boot_basereq_parse_failure),
	T_CASE(server_signal_reload_load_failure_keeps_previous),
	T_CASE(server_signal_reload_without_ruleset_drops_engine),
	T_CASE(server_signal_reload_in_place),
	T_CASE(server_signal_reload_boot_failure_skips_reapply),
	T_CASE(server_signal_reload_nothing_reloadable),
#endif /* WITH_RULESET */
	T_CASE(server_signal_int_term_break_loop),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
