/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Integration tests: real socks/http_proxy/server/dialer over loopback;
 * mocked: ruleset host and forward/api/tproxy entry points. */

#include "api_server.h"
#include "conf.h"
#include "dialer.h"
#include "forward.h"
#include "proto/codec.h"
#include "proto/http.h"
#include "resolver.h"
#if WITH_RULESET
#include "ruleset/ruleset.h"
#endif
#include "server.h"
#include "socks.h"
#include "transfer.h"

#include "io/memory.h"
#include "io/stream.h"
#include "utils/buffer.h"
#include "utils/gc.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <fcntl.h>
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
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - the ruleset host and the server's forward/api/tproxy entry points are
 * stubbed; everything else is the real module. Shared fixtures live here too.
 * ---------------------------------------------------------------------- */

/* The client dialer's configuration. The dialer arms no deadline of its own,
 * so conf.timeout is not read from here; each case's own wait is bounded by
 * TEST_WAIT_SEC instead. */
static const struct config test_conf = { 0 };

/* Read-only fixture template: start_proxy mutates the config it is given (its
 * .listen/.http_listen), so callers copy this into a local first -- const here
 * makes that copy-before-use compiler-enforced.
 *
 * .timeout is the proxy's own handshake-and-connect deadline. No case expects
 * it to expire -- a healthy session stops it once relaying starts -- so it too
 * is sized as a failsafe rather than a tight bound: it must outlive a refused
 * connect, so the connrefused cases get the proxy's error reply (loopback
 * ECONNREFUSED takes ~2s on MSYS2/Cygwin emulation), and a healthy dial under
 * load; and it must stay below TEST_WAIT_SEC, so a proxy-side stall surfaces as
 * the proxy's error rather than as the case's own watchdog expiring. */
static const struct config proxy_conf = { .timeout = 5.0 };

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

/* Failsafe watchdog for every wait below -- a dial completing, an accept, the
 * multi-session relay, the sessions draining. Each wait returns the instant its
 * predicate holds, so a correct build never reaches this deadline; it exists
 * only to fail a genuine hang in bounded time instead of blocking CI. It is
 * therefore sized to the project-standard T_TIMEOUT_SECONDS rather than a tight
 * bound: a real-proxy case runs a loopback connect, the SOCKS/HTTP handshake,
 * the proxy's own dial and the reply, possibly on a worker thread, and
 * scheduling delay alone can stretch that past a sub-second watchdog on a
 * loaded runner (ctest -j, a sanitizer build) and fail a healthy case. */
static const ev_tstamp TEST_WAIT_SEC = (ev_tstamp)T_TIMEOUT_SECONDS;
/* Re-check period while draining. Under WITH_THREADS a worker clears the session
 * counter on its own thread without waking the main loop, so a plain
 * ev_run(EVRUN_ONCE) would block on the watchdog instead of observing the drop;
 * a short repeating timer wakes the loop so the predicate is re-polled. */
static const ev_tstamp TEST_POLL_INTERVAL_SEC = 0.001;

struct dialer_result {
	bool called;
	int fd;
};

struct test_watchdog {
	bool fired;
};

static void close_if_open(int *restrict fd)
{
	if (*fd >= 0) {
		T_CHECK(close(*fd) == 0);
		*fd = -1;
	}
}

static bool fd_set_nonblock(const int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		return false;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool write_all(const int fd, const void *restrict buf, size_t len)
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

static void dialer_finish_cb(struct ev_loop *loop, void *data, const int fd)
{
	struct dialer_result *const result = data;
	(void)loop;
	result->called = true;
	result->fd = fd;
}

static void
test_watchdog_cb(struct ev_loop *loop, struct ev_timer *w, const int revents)
{
	struct test_watchdog *const watchdog = w->data;
	(void)revents;
	watchdog->fired = true;
	ev_break(loop, EVBREAK_ONE);
}

static void
test_poll_cb(struct ev_loop *loop, struct ev_timer *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
	/* No-op: the timer exists only to wake ev_run(EVRUN_ONCE) so the wait
	 * loop re-checks its predicate; see drain_sessions(). */
}

static bool test_wait_until(
	struct ev_loop *loop, bool (*predicate)(void *), void *predicate_data,
	const ev_tstamp timeout_sec, bool (*step)(void *), void *step_data)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;
	bool ok = true;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired && !predicate(predicate_data) && ok) {
		ev_run(loop, EVRUN_ONCE);
		if (step != NULL) {
			ok = step(step_data);
		}
	}
	ev_timer_stop(loop, &w_timeout);
	return ok && predicate(predicate_data);
}

static bool dialer_called_predicate(void *data)
{
	const struct dialer_result *const result = data;
	return result->called;
}

static int accept_nowait(const int listener_fd)
{
	for (;;) {
		const int fd = accept(listener_fd, NULL, NULL);
		if (fd < 0 && errno == EINTR) {
			continue;
		}
		if (fd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return -1;
		}
		return fd;
	}
}

/* Accept-queue depth for the loopback listeners: deep enough for every dial of
 * the multi-session case to be queued at once. */
#define TEST_LISTEN_BACKLOG 16

static int make_listener(uint_fast16_t *restrict port)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	const int enable = 1;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
		.sin_port = 0,
	};
	struct sockaddr_in bound_addr = { 0 };
	socklen_t len = sizeof(bound_addr);

	T_CHECK(fd >= 0);
	T_CHECK(setsockopt(
			fd, SOL_SOCKET, SO_REUSEADDR, &enable,
			sizeof(enable)) == 0);
	T_CHECK(bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0);
	T_CHECK(listen(fd, TEST_LISTEN_BACKLOG) == 0);
	T_CHECK(fd_set_nonblock(fd));
	T_CHECK(getsockname(fd, (struct sockaddr *)&bound_addr, &len) == 0);
	*port = ntohs(bound_addr.sin_port);
	return fd;
}

static int make_listener6(uint_fast16_t *restrict port)
{
	const int fd = socket(AF_INET6, SOCK_STREAM, 0);
	const int enable = 1;
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = in6addr_loopback,
		.sin6_port = 0,
	};
	struct sockaddr_in6 bound_addr = { 0 };
	socklen_t len = sizeof(bound_addr);

	T_CHECK(fd >= 0);
	T_CHECK(setsockopt(
			fd, SOL_SOCKET, SO_REUSEADDR, &enable,
			sizeof(enable)) == 0);
	T_CHECK(bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0);
	T_CHECK(listen(fd, TEST_LISTEN_BACKLOG) == 0);
	T_CHECK(fd_set_nonblock(fd));
	T_CHECK(getsockname(fd, (struct sockaddr *)&bound_addr, &len) == 0);
	*port = ntohs(bound_addr.sin6_port);
	return fd;
}

static int wait_for_accept(
	struct ev_loop *loop, const int listener_fd,
	const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	for (;;) {
		const int fd = accept_nowait(listener_fd);
		if (fd >= 0 || watchdog.fired) {
			ev_timer_stop(loop, &w_timeout);
			return fd;
		}
		ev_run(loop, EVRUN_ONCE);
	}
}

/* -------------------------------------------------------------------------
 * regression - end-to-end CONNECT through the real socks/http proxy handlers
 * (single-hop and chained). The dialer's own unit and raw-peer cases live in
 * dialer_test.c.
 * ---------------------------------------------------------------------- */

/* mock (cont.) - ruleset host stubs and the real-proxy fixtures below. */
#if WITH_RULESET
void ruleset_cancel(struct ev_loop *loop, struct ruleset_state *restrict state)
{
	(void)loop;
	(void)state;
}

/* ruleset_new() returns NULL here, so no request ever completes and w_finish
 * never goes pending: the window this handles cannot arise. Assert that premise
 * rather than keep a second copy of the production body, which ruleset_test
 * covers directly. */
void ruleset_request_cancel(
	struct ev_loop *loop, struct ruleset_callback *restrict cb)
{
	(void)loop;
	T_CHECK(!ev_is_pending(&cb->w_finish));
}

bool ruleset_resolve(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request,
	const struct ruleset_credentials *restrict creds,
	struct ruleset_callback *callback)
{
	(void)r;
	(void)state;
	(void)request;
	(void)creds;
	(void)callback;
	return false;
}

bool ruleset_dispatch(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const int atype,
	const struct ruleset_credentials *restrict creds,
	struct ruleset_callback *callback)
{
	(void)r;
	(void)state;
	(void)request;
	(void)atype;
	(void)creds;
	(void)callback;
	return false;
}

struct ruleset *ruleset_new(
	struct ev_loop *restrict loop, struct config *restrict conf,
	struct resolver *restrict resolver, struct dialreq *restrict basereq)
{
	(void)loop;
	(void)conf;
	(void)resolver;
	(void)basereq;
	return NULL;
}

void ruleset_setserver(struct ruleset *restrict r, struct server *restrict s)
{
	(void)r;
	(void)s;
}

void ruleset_setbasereq(
	struct ruleset *restrict r, struct dialreq *restrict basereq)
{
	(void)r;
	(void)basereq;
}

void ruleset_free(struct ruleset *restrict r)
{
	(void)r;
}

bool ruleset_loadfile(struct ruleset *restrict r, const char *restrict filename)
{
	(void)r;
	(void)filename;
	return false;
}

bool ruleset_reloadconfig(
	struct ruleset *restrict r, const char *restrict filename)
{
	(void)r;
	(void)filename;
	return false;
}

bool ruleset_isvalid(struct ruleset *restrict r)
{
	(void)r;
	return false;
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

/* Start a proxy server on an ephemeral loopback port and return that port.
 * Sets conf->listen or conf->http_listen to "127.0.0.1:0" depending on
 * use_http; conf must outlive the server. Relayed payload is spread over
 * @p nworkers I/O worker threads, as --workers does in main(). */
static uint_fast16_t start_proxy_ex(
	struct server *restrict s, struct ev_loop *restrict loop,
	const bool use_http, struct config *restrict conf,
	struct resolver *restrict resolver, const unsigned int nworkers)
{
	if (use_http) {
		conf->listen = NULL;
		conf->http_listen = "127.0.0.1:0";
	} else {
		conf->listen = "127.0.0.1:0";
		conf->http_listen = NULL;
	}
	struct sockaddr_in bound_addr = { 0 };
	socklen_t len = sizeof(bound_addr);

	struct transfer *restrict xfer = transfer_create(loop, nworkers);
	T_CHECK(xfer != NULL);
	T_CHECK(server_init(s, loop, conf, resolver, xfer, NULL, NULL));
	T_CHECK(getsockname(
			s->listeners[0].w_accept.fd,
			(struct sockaddr *)&bound_addr, &len) == 0);
	return ntohs(bound_addr.sin_port);
}

static uint_fast16_t start_proxy(
	struct server *restrict s, struct ev_loop *restrict loop,
	const bool use_http, struct config *restrict conf)
{
	return start_proxy_ex(s, loop, use_http, conf, NULL, 1);
}

static void stop_proxy(struct server *restrict s)
{
	server_stop(s);
	gc_finalizeall();
	transfer_join(s->xfer);
	s->xfer = NULL;
}

static size_t server_sessions(struct server *restrict s)
{
#if WITH_THREADS
	return atomic_load_explicit(&s->num_sessions, memory_order_relaxed);
#else
	return s->num_sessions;
#endif
}

struct sessions_drained_ctx {
	struct server *a, *b; /* b may be NULL */
};

static bool sessions_drained_predicate(void *data)
{
	const struct sessions_drained_ctx *const ctx = data;
	return server_sessions(ctx->a) == 0 &&
	       (ctx->b == NULL || server_sessions(ctx->b) == 0);
}

/* Pump the loop until the given proxies' sessions have torn down, so a caller
 * can stop them cleanly. Returns as soon as they drain instead of blocking for
 * a fixed duration; a false return means the timeout was hit, which is a
 * failure rather than the expected outcome. Pass b = NULL for a single proxy.
 *
 * The result must be captured and asserted *after* the case's teardown rather
 * than through an inline T_EXPECT: a T_EXPECT failure longjmps out of the case,
 * and skipping teardown would leak the loop and, under WITH_THREADS, leave the
 * worker threads unjoined and still writing the by-then-dead num_sessions slot. */
static bool drain_sessions(
	struct ev_loop *restrict loop, struct server *restrict a,
	struct server *restrict b)
{
	struct sessions_drained_ctx ctx = { .a = a, .b = b };
	struct ev_timer w_poll;
	ev_timer_init(
		&w_poll, test_poll_cb, TEST_POLL_INTERVAL_SEC,
		TEST_POLL_INTERVAL_SEC);
	ev_timer_start(loop, &w_poll);
	const bool drained = test_wait_until(
		loop, sessions_drained_predicate, &ctx, TEST_WAIT_SEC, NULL,
		NULL);
	ev_timer_stop(loop, &w_poll);
	return drained;
}

/* Reserve an ephemeral loopback port that refuses connections: bind a socket but
 * never listen() (so connects get RST/ECONNREFUSED) and keep it open (so no
 * other process, e.g. under `ctest -j`, can grab the port and accept the connect
 * that the test expects to be refused). No SO_REUSEADDR, to keep the reservation
 * exclusive. The caller closes the returned fd once the dial has completed. */
static int make_refused_port(uint_fast16_t *restrict port)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
		.sin_port = 0,
	};
	socklen_t len = sizeof(addr);

	T_CHECK(fd >= 0);
	T_CHECK(bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0);
	T_CHECK(getsockname(fd, (struct sockaddr *)&addr, &len) == 0);
	*port = ntohs(addr.sin_port);
	return fd;
}

T_DECLARE_CASE(socks5_connect_success_via_real_proxy)
{
	uint_fast16_t proxy_port, final_port;
	int final_fd = make_listener(&final_port);
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64], target_addr[32];
	bool completed;
	int accepted_fd;
	int client_fd;
	bool has_accepted;
	bool has_client_fd;
	enum dialer_error err;

	T_CHECK(loop != NULL);
	struct config pconf = proxy_conf;
	proxy_port = start_proxy(&proxy_s, loop, false, &pconf);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "127.0.0.1:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	client_fd = result.fd;
	has_client_fd = client_fd >= 0;
	err = d.err;
	dialer_cancel(&d, loop);
	accepted_fd = accept_nowait(final_fd);
	has_accepted = accepted_fd >= 0;
	close_if_open(&accepted_fd);
	close_if_open(&client_fd);
	dialreq_free(req);
	const bool drained = drain_sessions(loop, &proxy_s, NULL);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);

	T_EXPECT(drained);
	T_EXPECT(completed);
	T_EXPECT(has_client_fd);
	T_EXPECT(has_accepted);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(socks5_connrefused_proxied_correctly)
{
	uint_fast16_t proxy_port;
	uint_fast16_t closed_port;
	const int refused_fd = make_refused_port(&closed_port);
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64], target_addr[32];
	bool completed;
	enum dialer_error err;

	T_CHECK(loop != NULL);
	struct config pconf = proxy_conf;
	proxy_port = start_proxy(&proxy_s, loop, false, &pconf);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "127.0.0.1:%u",
			(unsigned)closed_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	err = d.err;
	dialer_cancel(&d, loop);
	dialreq_free(req);
	const bool drained = drain_sessions(loop, &proxy_s, NULL);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	(void)close(refused_fd);

	T_EXPECT(drained);
	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_REFUSED);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(socks5_noauth_rejected_when_auth_required)
{
	struct config auth_conf = proxy_conf;
	uint_fast16_t proxy_port;
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];
	bool completed;
	enum dialer_error err;

	auth_conf.auth_required = true;
	T_CHECK(loop != NULL);
	proxy_port = start_proxy(&proxy_s, loop, false, &auth_conf);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	/* Dial without credentials; proxy requires authentication */
	req = dialreq_parse("127.0.0.1:1", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	err = d.err;
	dialer_cancel(&d, loop);
	dialreq_free(req);
	const bool drained = drain_sessions(loop, &proxy_s, NULL);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);

	T_EXPECT(drained);
	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_AUTH);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(socks5_credentials_accepted_when_auth_required)
{
	struct config auth_conf = proxy_conf;
	uint_fast16_t proxy_port, final_port;
	int final_fd = make_listener(&final_port);
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[128], target_addr[32];
	bool completed;
	int accepted_fd;
	int client_fd;
	bool has_accepted;
	bool has_client_fd;
	enum dialer_error err;

	auth_conf.auth_required = true;
	T_CHECK(loop != NULL);
	proxy_port = start_proxy(&proxy_s, loop, false, &auth_conf);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "127.0.0.1:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri),
			"socks5://user:pass@127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	client_fd = result.fd;
	has_client_fd = client_fd >= 0;
	err = d.err;
	dialer_cancel(&d, loop);
	accepted_fd = accept_nowait(final_fd);
	has_accepted = accepted_fd >= 0;
	close_if_open(&accepted_fd);
	close_if_open(&client_fd);
	dialreq_free(req);
	const bool drained = drain_sessions(loop, &proxy_s, NULL);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);

	T_EXPECT(drained);
	T_EXPECT(completed);
	T_EXPECT(has_client_fd);
	T_EXPECT(has_accepted);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(socks4a_connect_success_via_real_proxy)
{
	uint_fast16_t proxy_port, final_port;
	int final_fd = make_listener(&final_port);
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64], target_addr[32];
	bool completed;
	int accepted_fd;
	int client_fd;
	bool has_accepted;
	bool has_client_fd;
	enum dialer_error err;

	T_CHECK(loop != NULL);
	struct config pconf = proxy_conf;
	proxy_port = start_proxy(&proxy_s, loop, false, &pconf);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "127.0.0.1:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks4a://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	client_fd = result.fd;
	has_client_fd = client_fd >= 0;
	err = d.err;
	dialer_cancel(&d, loop);
	accepted_fd = accept_nowait(final_fd);
	has_accepted = accepted_fd >= 0;
	close_if_open(&accepted_fd);
	close_if_open(&client_fd);
	dialreq_free(req);
	const bool drained = drain_sessions(loop, &proxy_s, NULL);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);

	T_EXPECT(drained);
	T_EXPECT(completed);
	T_EXPECT(has_client_fd);
	T_EXPECT(has_accepted);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(http_proxy_connect_success_via_real_proxy)
{
	uint_fast16_t proxy_port, final_port;
	int final_fd = make_listener(&final_port);
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64], target_addr[32];
	bool completed;
	int accepted_fd;
	int client_fd;
	bool has_accepted;
	bool has_client_fd;
	enum dialer_error err;

	T_CHECK(loop != NULL);
	struct config pconf = proxy_conf;
	proxy_port = start_proxy(&proxy_s, loop, true, &pconf);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "127.0.0.1:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	client_fd = result.fd;
	has_client_fd = client_fd >= 0;
	err = d.err;
	dialer_cancel(&d, loop);
	accepted_fd = accept_nowait(final_fd);
	has_accepted = accepted_fd >= 0;
	close_if_open(&accepted_fd);
	close_if_open(&client_fd);
	dialreq_free(req);
	const bool drained = drain_sessions(loop, &proxy_s, NULL);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);

	T_EXPECT(drained);
	T_EXPECT(completed);
	T_EXPECT(has_client_fd);
	T_EXPECT(has_accepted);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(http_proxy_connrefused_proxied_correctly)
{
	uint_fast16_t proxy_port;
	uint_fast16_t closed_port;
	const int refused_fd = make_refused_port(&closed_port);
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64], target_addr[32];
	bool completed;
	enum dialer_error err;

	T_CHECK(loop != NULL);
	struct config pconf = proxy_conf;
	proxy_port = start_proxy(&proxy_s, loop, true, &pconf);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "127.0.0.1:%u",
			(unsigned)closed_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	err = d.err;
	dialer_cancel(&d, loop);
	dialreq_free(req);
	const bool drained = drain_sessions(loop, &proxy_s, NULL);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	(void)close(refused_fd);

	T_EXPECT(drained);
	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_REFUSED);
	T_EXPECT_EQ(d.syserr, 0);
}

/* Outcome of a dial-success attempt, recorded by expect_dial_success and
 * asserted by the caller after teardown (see below). */
struct dial_success_result {
	bool completed;
	bool has_client_fd;
	bool has_accepted;
	enum dialer_error err;
	int syserr;
};

T_DECLARE_SUBCASE(
	assert_dial_success, const struct dial_success_result *restrict r)
{
	T_EXPECT(r->completed);
	T_EXPECT(r->has_client_fd);
	T_EXPECT(r->has_accepted);
	T_EXPECT_EQ(r->err, DIALER_OK);
	T_EXPECT_EQ(r->syserr, 0);
}

/* Drive the dialer with @p req until completion, recording into *out whether a
 * successful CONNECT whose final hop is accepted on @p final_fd occurred. The
 * client uses @p conf (with optional @p resolver for domain targets). Both
 * produced fds are closed before returning.
 *
 * Records rather than asserts: the caller must assert (assert_dial_success)
 * *after* its own teardown, because an inline T_EXPECT here would longjmp out
 * of the case before drain_sessions/stop_proxy/ev_loop_destroy run -- leaking
 * the loop and, under WITH_THREADS, leaving worker threads unjoined and still
 * writing the by-then-dead num_sessions slot. */
static void expect_dial_success(
	struct ev_loop *restrict loop, struct dialreq *restrict req,
	const struct config *restrict conf, struct resolver *restrict resolver,
	const int final_fd, struct dial_success_result *restrict out)
{
	struct dialer_result result = { .fd = -1 };
	struct dialer d;

	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, conf, resolver, NULL);
	out->completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SEC, NULL,
		NULL);
	int client_fd = result.fd;
	out->has_client_fd = client_fd >= 0;
	out->err = d.err;
	out->syserr = d.syserr;
	/* A dial still in flight when the watchdog expired must not outlive d:
	 * the caller runs the loop again (drain_sessions), which would fire its
	 * watchers into this dead frame. A no-op once the dial has completed. */
	dialer_cancel(&d, loop);
	int accepted_fd = wait_for_accept(loop, final_fd, TEST_WAIT_SEC);
	out->has_accepted = accepted_fd >= 0;
	close_if_open(&accepted_fd);
	close_if_open(&client_fd);
}

T_DECLARE_CASE(socks5_connect_ipv6_target_via_real_proxy)
{
	uint_fast16_t proxy_port, final_port;
	int final_fd = make_listener6(&final_port);
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialreq *req;
	char proxy_uri[64], target_addr[48];

	T_CHECK(loop != NULL);
	struct config pconf = proxy_conf;
	proxy_port = start_proxy(&proxy_s, loop, false, &pconf);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "[::1]:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	struct dial_success_result r;
	expect_dial_success(loop, req, &test_conf, NULL, final_fd, &r);
	dialreq_free(req);
	const bool drained = drain_sessions(loop, &proxy_s, NULL);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
	T_EXPECT(drained);
	T_CALL_SUBCASE(assert_dial_success, &r);
}

T_DECLARE_CASE(http_proxy_connect_ipv6_target_via_real_proxy)
{
	uint_fast16_t proxy_port, final_port;
	int final_fd = make_listener6(&final_port);
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialreq *req;
	char proxy_uri[64], target_addr[48];

	T_CHECK(loop != NULL);
	struct config pconf = proxy_conf;
	proxy_port = start_proxy(&proxy_s, loop, true, &pconf);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "[::1]:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	struct dial_success_result r;
	expect_dial_success(loop, req, &test_conf, NULL, final_fd, &r);
	dialreq_free(req);
	const bool drained = drain_sessions(loop, &proxy_s, NULL);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
	T_EXPECT(drained);
	T_CALL_SUBCASE(assert_dial_success, &r);
}

T_DECLARE_CASE(http_proxy_connect_with_credentials_via_real_proxy)
{
	uint_fast16_t proxy_port, final_port;
	int final_fd = make_listener(&final_port);
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialreq *req;
	char proxy_uri[128], target_addr[32];

	T_CHECK(loop != NULL);
	struct config pconf = proxy_conf;
	proxy_port = start_proxy(&proxy_s, loop, true, &pconf);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "127.0.0.1:%u",
			(unsigned)final_port) > 0);
	/* The client formats a Proxy-Authorization header; a proxy that does
	 * not require auth accepts and ignores it. */
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri),
			"http://user:pass@127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	struct dial_success_result r;
	expect_dial_success(loop, req, &test_conf, NULL, final_fd, &r);
	dialreq_free(req);
	const bool drained = drain_sessions(loop, &proxy_s, NULL);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
	T_EXPECT(drained);
	T_CALL_SUBCASE(assert_dial_success, &r);
}

/* Chain two real proxies of the given protocols and assert an end-to-end
 * CONNECT to a final loopback listener succeeds. This exercises the dialer's
 * multi-hop traversal against real server handshakes. */
T_DECLARE_SUBCASE(
	run_chain_success, const bool first_http, const bool second_http)
{
	uint_fast16_t port1, port2, final_port;
	int final_fd = make_listener(&final_port);
	struct server proxy1, proxy2;
	struct config conf1 = proxy_conf, conf2 = proxy_conf;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialreq *req;
	char proxy_uri[128], target_addr[32];

	T_CHECK(loop != NULL);
	port1 = start_proxy(&proxy1, loop, first_http, &conf1);
	port2 = start_proxy(&proxy2, loop, second_http, &conf2);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "127.0.0.1:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri),
			"%s://127.0.0.1:%u,%s://127.0.0.1:%u",
			first_http ? "http" : "socks5", (unsigned)port1,
			second_http ? "http" : "socks5", (unsigned)port2) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	struct dial_success_result r;
	expect_dial_success(loop, req, &test_conf, NULL, final_fd, &r);
	dialreq_free(req);
	const bool drained = drain_sessions(loop, &proxy2, &proxy1);
	stop_proxy(&proxy2);
	stop_proxy(&proxy1);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
	T_EXPECT(drained);
	T_CALL_SUBCASE(assert_dial_success, &r);
}

T_DECLARE_CASE(chain_socks5_to_http_connect_success)
{
	T_CALL_SUBCASE(run_chain_success, false, true);
}

T_DECLARE_CASE(chain_http_to_socks5_connect_success)
{
	T_CALL_SUBCASE(run_chain_success, true, false);
}

T_DECLARE_CASE(chain_socks5_to_socks5_connect_success)
{
	T_CALL_SUBCASE(run_chain_success, false, false);
}

/* Concurrent sessions relayed through one multi-worker proxy. Sized so
 * transfer_serve's round-robin lands at least one session on every worker. */
enum { MULTI_WORKERS = 4, MULTI_SESSIONS = 8 };

/* One proxied client: the dial that produced it, the tag byte it sent and the
 * byte the far end echoed back through the relay. */
struct multi_client {
	struct dialer d;
	struct dialer_result result;
	int fd;
	unsigned char echo;
	bool got_echo;
};

/* The far end of one session, accepted on the final listener. Which client it
 * belongs to is unknown here; the tag byte carries that. */
struct multi_relay {
	int fd;
	bool echoed;
};

struct multi_ctx {
	struct multi_client clients[MULTI_SESSIONS];
	struct multi_relay relays[MULTI_SESSIONS];
	size_t nrelays;
	int listener_fd;
};

/* Accept whatever the final listener has queued, so a proxy dial never waits on
 * a full accept queue. */
static bool multi_accept_step(void *data)
{
	struct multi_ctx *const ctx = data;

	while (ctx->nrelays < MULTI_SESSIONS) {
		const int fd = accept_nowait(ctx->listener_fd);
		if (fd < 0) {
			break;
		}
		if (!fd_set_nonblock(fd)) {
			return false;
		}
		ctx->relays[ctx->nrelays++] = (struct multi_relay){
			.fd = fd,
			.echoed = false,
		};
	}
	return true;
}

static bool multi_dialed_predicate(void *data)
{
	const struct multi_ctx *const ctx = data;

	if (ctx->nrelays < MULTI_SESSIONS) {
		return false;
	}
	for (size_t i = 0; i < MULTI_SESSIONS; i++) {
		if (!ctx->clients[i].result.called) {
			return false;
		}
	}
	return true;
}

/* Bounce each tag byte back at the far end, then collect the bounce at the
 * client end; both directions cross the relay. */
static bool multi_relay_step(void *data)
{
	struct multi_ctx *const ctx = data;

	for (size_t i = 0; i < ctx->nrelays; i++) {
		struct multi_relay *const relay = &ctx->relays[i];
		if (relay->echoed) {
			continue;
		}
		unsigned char tag;
		if (recv_nowait(relay->fd, &tag, sizeof(tag)) !=
		    (ssize_t)sizeof(tag)) {
			continue;
		}
		if (!write_all(relay->fd, &tag, sizeof(tag))) {
			return false;
		}
		relay->echoed = true;
	}
	for (size_t i = 0; i < MULTI_SESSIONS; i++) {
		struct multi_client *const client = &ctx->clients[i];
		if (client->got_echo || client->fd < 0) {
			continue;
		}
		if (recv_nowait(
			    client->fd, &client->echo, sizeof(client->echo)) !=
		    (ssize_t)sizeof(client->echo)) {
			continue;
		}
		client->got_echo = true;
	}
	return true;
}

static bool multi_echoed_predicate(void *data)
{
	const struct multi_ctx *const ctx = data;

	for (size_t i = 0; i < MULTI_SESSIONS; i++) {
		if (!ctx->clients[i].got_echo) {
			return false;
		}
	}
	return true;
}

/*
 * Several real SOCKS5 sessions relayed at once by a proxy whose transfer engine
 * runs MULTI_WORKERS I/O threads -- the configuration --workers creates, which
 * no other case builds: handshakes accepted on the main loop, payload pumped on
 * the worker loops, num_sessions accounted across threads and torn down through
 * server_stop -> gc_finalizeall -> transfer_join. Each client sends its own tag
 * byte and must read that same byte back, so a session crossed both relay
 * directions and stayed paired with its own far end. Without WITH_THREADS the
 * engine ignores the worker count and the case still covers the concurrent
 * sessions.
 */
T_DECLARE_CASE(multi_worker_relays_concurrent_sessions)
{
	uint_fast16_t proxy_port, final_port;
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialreq *req;
	char proxy_uri[64], target_addr[32];
	/* static: a dialer carries an 8 KiB read buffer, MULTI_SESSIONS of
	 * them do not belong on the case's stack */
	static struct multi_ctx ctx;

	T_CHECK(loop != NULL);
	/* The client and far-end sockets are not watched by this loop -- under
	 * WITH_THREADS the relay runs on a worker thread that never wakes it --
	 * so a short repeating timer drives the step callbacks below. */
	struct ev_timer w_poll;
	ev_timer_init(
		&w_poll, test_poll_cb, TEST_POLL_INTERVAL_SEC,
		TEST_POLL_INTERVAL_SEC);
	ev_timer_start(loop, &w_poll);
	ctx = (struct multi_ctx){ .listener_fd = make_listener(&final_port) };
	struct config pconf = proxy_conf;
	proxy_port = start_proxy_ex(
		&proxy_s, loop, false, &pconf, NULL, MULTI_WORKERS);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "127.0.0.1:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);

	for (size_t i = 0; i < MULTI_SESSIONS; i++) {
		struct multi_client *const client = &ctx.clients[i];
		client->fd = -1;
		client->result.fd = -1;
		dialer_init(
			&client->d,
			&(struct dialer_cb){
				.func = dialer_finish_cb,
				.data = &client->result,
			},
			NULL, NULL);
		dialer_do(&client->d, loop, req, &test_conf, NULL, NULL);
	}
	const bool dialed = test_wait_until(
		loop, multi_dialed_predicate, &ctx, TEST_WAIT_SEC,
		multi_accept_step, &ctx);

	bool wrote = true;
	for (size_t i = 0; i < MULTI_SESSIONS; i++) {
		struct multi_client *const client = &ctx.clients[i];
		dialer_cancel(&client->d, loop);
		const unsigned char tag = (unsigned char)i;
		client->fd = client->result.fd;
		if (client->fd < 0) {
			wrote = false;
			continue;
		}
		wrote = write_all(client->fd, &tag, sizeof(tag)) && wrote;
	}
	const bool echoed = test_wait_until(
		loop, multi_echoed_predicate, &ctx, TEST_WAIT_SEC,
		multi_relay_step, &ctx);

	bool paired = true;
	for (size_t i = 0; i < MULTI_SESSIONS; i++) {
		paired = paired && ctx.clients[i].got_echo &&
			 ctx.clients[i].echo == (unsigned char)i;
		close_if_open(&ctx.clients[i].fd);
	}
	for (size_t i = 0; i < ctx.nrelays; i++) {
		close_if_open(&ctx.relays[i].fd);
	}
	const size_t nrelays = ctx.nrelays;
	dialreq_free(req);
	ev_timer_stop(loop, &w_poll);
	const bool drained = drain_sessions(loop, &proxy_s, NULL);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(ctx.listener_fd) == 0);

	T_EXPECT(dialed);
	T_EXPECT_EQ(nrelays, (size_t)MULTI_SESSIONS);
	T_EXPECT(wrote);
	T_EXPECT(echoed);
	T_EXPECT(paired);
	T_EXPECT(drained);
}

T_DECLARE_CASE(socks5_connect_domain_target_via_real_proxy)
{
	struct config server_conf = proxy_conf;
	uint_fast16_t proxy_port, final_port;
	int final_fd = make_listener(&final_port);
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct resolver *resolver;
	struct dialreq *req;
	char proxy_uri[64], target_addr[32];

	T_CHECK(loop != NULL);
	server_conf.resolve_pf = PF_INET;
	resolver = resolver_new(loop, &server_conf);
	T_CHECK(resolver != NULL);
	proxy_port = start_proxy_ex(
		&proxy_s, loop, false, &server_conf, resolver, 1);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "localhost:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	struct dial_success_result r;
	expect_dial_success(loop, req, &test_conf, NULL, final_fd, &r);
	dialreq_free(req);
	const bool drained = drain_sessions(loop, &proxy_s, NULL);
	stop_proxy(&proxy_s);
	resolver_free(resolver);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
	T_EXPECT(drained);
	T_CALL_SUBCASE(assert_dial_success, &r);
}

/* SOCKS4a has no native IPv6: the client encodes an IPv6 target as a textual
 * hostname ("::1"). The proxy parses it as a domain and resolves it. */
T_DECLARE_CASE(socks4a_connect_ipv6_target_via_real_proxy)
{
	struct config server_conf = proxy_conf;
	uint_fast16_t proxy_port, final_port;
	int final_fd = make_listener6(&final_port);
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct resolver *resolver;
	struct dialreq *req;
	char proxy_uri[64], target_addr[48];

	T_CHECK(loop != NULL);
	server_conf.resolve_pf = PF_INET6;
	resolver = resolver_new(loop, &server_conf);
	T_CHECK(resolver != NULL);
	proxy_port = start_proxy_ex(
		&proxy_s, loop, false, &server_conf, resolver, 1);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "[::1]:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks4a://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	struct dial_success_result r;
	expect_dial_success(loop, req, &test_conf, NULL, final_fd, &r);
	dialreq_free(req);
	const bool drained = drain_sessions(loop, &proxy_s, NULL);
	stop_proxy(&proxy_s);
	resolver_free(resolver);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
	T_EXPECT(drained);
	T_CALL_SUBCASE(assert_dial_success, &r);
}

T_DECLARE_CASE(socks4a_connect_domain_target_via_real_proxy)
{
	struct config server_conf = proxy_conf;
	uint_fast16_t proxy_port, final_port;
	int final_fd = make_listener(&final_port);
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct resolver *resolver;
	struct dialreq *req;
	char proxy_uri[64], target_addr[32];

	T_CHECK(loop != NULL);
	server_conf.resolve_pf = PF_INET;
	resolver = resolver_new(loop, &server_conf);
	T_CHECK(resolver != NULL);
	proxy_port = start_proxy_ex(
		&proxy_s, loop, false, &server_conf, resolver, 1);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "localhost:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks4a://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	struct dial_success_result r;
	expect_dial_success(loop, req, &test_conf, NULL, final_fd, &r);
	dialreq_free(req);
	const bool drained = drain_sessions(loop, &proxy_s, NULL);
	stop_proxy(&proxy_s);
	resolver_free(resolver);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
	T_EXPECT(drained);
	T_CALL_SUBCASE(assert_dial_success, &r);
}

/* -------------------------------------------------------------------------
 * fuzz - randomized codec and HTTP parser inputs. The socks parser fuzzer
 * lives in socks_test, which stubs the network boundary; against the real
 * dialer/transfer here it is not safe to run. Tunable via FUZZ_SEED/FUZZ_ITER.
 * ---------------------------------------------------------------------- */

#define FUZZ_DEFAULT_ITERATIONS 1000
#define FUZZ_MAX_CODEC_INPUT 512
#define FUZZ_MAX_HEADER_VALUE 256
#define FUZZ_MAX_HTTP_INPUT 1024
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

/* Retry on transient EMFILE/ENFILE/ENOBUFS under `ctest -j` load. */
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

static void drain_stream(struct io_stream *restrict s)
{
	size_t total = 0;
	for (;;) {
		unsigned char out[1024];
		size_t len = sizeof(out);
		const int err = io_stream_read(s, out, &len);
		if (err != 0 || len == 0) {
			break;
		}
		total += len;
		if (total >= FUZZ_MAX_STREAM_OUTPUT) {
			break;
		}
	}
}

typedef struct io_stream *(*codec_reader_fn)(struct io_stream *base);

static void
fuzz_codec_reader(struct prng *restrict p, codec_reader_fn new_reader)
{
	unsigned char input[FUZZ_MAX_CODEC_INPUT];
	const size_t len = prng_size(p, 0, sizeof(input));
	prng_fill(p, input, len);

	struct io_stream *const base = io_memreader(input, len);
	T_CHECK(base != NULL);
	struct io_stream *const reader = new_reader(base);
	if (reader == NULL) {
		return;
	}
	drain_stream(reader);
	/* Malformed fuzz inputs may be rejected during close-time validation. */
	(void)io_stream_close(reader);
}

static void
fuzz_ascii_string(struct prng *restrict p, char *restrict buf, const size_t len)
{
	for (size_t i = 0; i < len; i++) {
		buf[i] = (char)(0x20 + (prng_next(p) % 0x5f));
		if (buf[i] == '\0') {
			buf[i] = 'x';
		}
	}
	buf[len] = '\0';
}

struct header_cb_ctx {
	struct http_conn *conn;
};

static bool parse_header_cb(void *ctx, const char *key, char *value)
{
	struct header_cb_ctx *const c = ctx;
	if (strcasecmp(key, "Transfer-Encoding") == 0) {
		return parsehdr_transfer_encoding(c->conn, value);
	}
	if (strcasecmp(key, "Accept-Encoding") == 0) {
		return parsehdr_accept_encoding(c->conn, value);
	}
	if (strcasecmp(key, "Content-Length") == 0) {
		return parsehdr_content_length(c->conn, value);
	}
	if (strcasecmp(key, "Content-Encoding") == 0) {
		return parsehdr_content_encoding(c->conn, value);
	}
	if (strcasecmp(key, "Expect") == 0) {
		return parsehdr_expect(c->conn, value);
	}
	if (strcasecmp(key, "Connection") == 0) {
		return parsehdr_connection(c->conn, value);
	}
	return true;
}

static void
fuzz_http_conn(struct prng *restrict p, const enum http_conn_state mode)
{
	int sv[2] = { -1, -1 };
	struct http_conn conn = { 0 };
	struct header_cb_ctx cbctx = { .conn = &conn };
	const struct http_parsehdr_cb cb = {
		.func = parse_header_cb,
		.ctx = &cbctx,
	};
	unsigned char input[FUZZ_MAX_HTTP_INPUT];
	const size_t len = prng_size(p, 0, sizeof(input));
	prng_fill(p, input, len);

	make_socketpair(sv);
	T_CHECK(write_all(sv[1], input, len));
	T_CHECK(shutdown(sv[1], SHUT_WR) == 0);
	http_conn_init(&conn, sv[0], mode, cb, NULL, NULL);

	for (size_t i = 0; i < 8; i++) {
		const int ret = http_conn_recv(&conn);
		if (ret != 1) {
			break;
		}
	}

	VBUF_FREE(conn.cbuf);
	close_if_open(&sv[0]);
	close_if_open(&sv[1]);
}

static void fuzz_parsehdr_value(
	struct prng *restrict p, char *restrict value, const size_t len)
{
	fuzz_ascii_string(p, value, len);
	if (len > 0 && prng_bool(p)) {
		value[prng_size(p, 0, len - 1)] = ',';
	}
	if (len > 0 && prng_bool(p)) {
		value[prng_size(p, 0, len - 1)] = ';';
	}
}

static void fuzz_connection_tokens(const char *restrict value)
{
	const char *cursor = value;
	for (size_t i = 0; i <= FUZZ_MAX_HEADER_VALUE; i++) {
		const char *tok;
		size_t toklen;
		const char *const next =
			parsehdr_connection_token(cursor, &tok, &toklen);
		if (next == NULL || *next == '\0') {
			break;
		}
		if (next == cursor) {
			break;
		}
		cursor = next;
	}
}

static void fuzz_http_headers_once(struct prng *restrict p)
{
	char value[FUZZ_MAX_HEADER_VALUE + 1];
	char copy[FUZZ_MAX_HEADER_VALUE + 1];
	const size_t len = prng_size(p, 0, FUZZ_MAX_HEADER_VALUE);
	fuzz_parsehdr_value(p, value, len);

	struct http_conn conn = { 0 };
	http_conn_init(
		&conn, -1, STATE_PARSE_REQUEST, (struct http_parsehdr_cb){ 0 },
		NULL, NULL);
	conn.msg.req.method = "";
	conn.msg.req.version = "HTTP/1.1";

#define CALL_PARSEHDR(fn)                                                      \
	do {                                                                   \
		(void)memcpy(copy, value, len + 1);                            \
		(void)fn(&conn, copy);                                         \
	} while (0)
	CALL_PARSEHDR(parsehdr_transfer_encoding);
	CALL_PARSEHDR(parsehdr_accept_encoding);
	CALL_PARSEHDR(parsehdr_content_length);
	CALL_PARSEHDR(parsehdr_content_encoding);
	CALL_PARSEHDR(parsehdr_expect);
	CALL_PARSEHDR(parsehdr_connection);
#undef CALL_PARSEHDR
	fuzz_connection_tokens(value);
}
T_DECLARE_CASE(fuzz_inflate)
{
	(void)_t_;

	struct prng p;
	prng_seed(&p, fuzz_case_seed(1));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_codec_reader(&p, codec_inflate_reader);
	}
}

T_DECLARE_CASE(fuzz_zlib)
{
	(void)_t_;

	struct prng p;
	prng_seed(&p, fuzz_case_seed(2));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_codec_reader(&p, codec_zlib_reader);
	}
}

T_DECLARE_CASE(fuzz_gzip)
{
	(void)_t_;

	struct prng p;
	prng_seed(&p, fuzz_case_seed(3));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_codec_reader(&p, codec_gzip_reader);
	}
}

T_DECLARE_CASE(fuzz_http_req)
{
	(void)_t_;

	struct prng p;
	prng_seed(&p, fuzz_case_seed(4));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_http_conn(&p, STATE_PARSE_REQUEST);
	}
}

T_DECLARE_CASE(fuzz_http_resp)
{
	(void)_t_;

	struct prng p;
	prng_seed(&p, fuzz_case_seed(5));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_http_conn(&p, STATE_PARSE_RESPONSE);
	}
}

T_DECLARE_CASE(fuzz_parsehdr)
{
	(void)_t_;

	struct prng p;
	prng_seed(&p, fuzz_case_seed(6));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_http_headers_once(&p);
	}
}
/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(socks5_connect_success_via_real_proxy),
	T_CASE(socks5_connrefused_proxied_correctly),
	T_CASE(socks5_noauth_rejected_when_auth_required),
	T_CASE(socks5_credentials_accepted_when_auth_required),
	T_CASE(socks4a_connect_success_via_real_proxy),
	T_CASE(http_proxy_connect_success_via_real_proxy),
	T_CASE(http_proxy_connrefused_proxied_correctly),
	T_CASE(socks5_connect_ipv6_target_via_real_proxy),
	T_CASE(http_proxy_connect_ipv6_target_via_real_proxy),
	T_CASE(http_proxy_connect_with_credentials_via_real_proxy),
	T_CASE(chain_socks5_to_http_connect_success),
	T_CASE(chain_http_to_socks5_connect_success),
	T_CASE(chain_socks5_to_socks5_connect_success),
	T_CASE(multi_worker_relays_concurrent_sessions),
	T_CASE(socks5_connect_domain_target_via_real_proxy),
	T_CASE(socks4a_connect_ipv6_target_via_real_proxy),
	T_CASE(socks4a_connect_domain_target_via_real_proxy),
	/* fuzz cases */
	T_CASE(fuzz_inflate),
	T_CASE(fuzz_zlib),
	T_CASE(fuzz_gzip),
	T_CASE(fuzz_http_req),
	T_CASE(fuzz_http_resp),
	T_CASE(fuzz_parsehdr),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	fuzz_seed = read_seed();
	fuzz_iterations = read_iterations();
	(void)fprintf(
		stderr, "fuzz seed=0x%016" PRIx64 " iter=%zu\n", fuzz_seed,
		fuzz_iterations);

	resolver_init();
	const int ret = testing_main(argc, argv, suite);
	resolver_cleanup();
	return ret;
}
