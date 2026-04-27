/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "forward.h"

#include "conf.h"
#include "dialer.h"
#include "ruleset.h"
#include "server.h"
#include "transfer.h"
#include "util.h"

#include "utils/testing.h"

#include <arpa/inet.h>
#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * These tests isolate the state machine in forward.c. Dialer, transfer, and
 * ruleset dependencies are stubbed so connection accounting and callback
 * sequencing can be asserted without real network activity.
 */

static struct config test_conf = {
	.timeout = 1.0,
};

static const ev_tstamp TEST_WAIT_SHORT_SEC = 0.032;
static const ev_tstamp TEST_WAIT_TIMEOUT_SEC = 0.128;

const char *proxy_protocol_str[PROTO_MAX] = {
	[PROTO_HTTP] = "http",
	[PROTO_SOCKS4A] = "socks4a",
	[PROTO_SOCKS5] = "socks5",
};

enum stub_dialer_mode {
	STUB_DIALER_NONE,
	STUB_DIALER_FAIL,
	STUB_DIALER_SUCCESS,
};

#if WITH_RULESET
enum stub_ruleset_mode {
	STUB_RULESET_FAIL,
	STUB_RULESET_ASYNC_OK,
};
#endif

static struct {
	bool dialreq_available;
	bool dialaddr_set_ok;
	int dialaddr_set_calls;
	int dialreq_free_calls;

	enum stub_dialer_mode dialer_mode;
	enum dialer_error dialer_err;
	int dialer_syserr;
	int dialer_result_fd;
	int dialer_do_calls;
	int dialer_cancel_calls;

	struct stub_xfer_ctx *xfer_ctxs[2];
	int xfer_count;

#if WITH_RULESET
	enum stub_ruleset_mode ruleset_mode;
	struct ruleset_callback *ruleset_pending_cb;
	int ruleset_resolve_calls;
	int ruleset_route_calls;
	int ruleset_route6_calls;
	int ruleset_cancel_calls;
#endif
} STUB = {
	.dialreq_available = false,
	.dialaddr_set_ok = false,
	.dialaddr_set_calls = 0,
	.dialreq_free_calls = 0,
	.dialer_mode = STUB_DIALER_NONE,
	.dialer_err = DIALER_ERR_CONNECT,
	.dialer_syserr = ECONNREFUSED,
	.dialer_result_fd = -1,
	.dialer_do_calls = 0,
	.dialer_cancel_calls = 0,
	.xfer_ctxs = { NULL, NULL },
	.xfer_count = 0,
#if WITH_RULESET
	.ruleset_mode = STUB_RULESET_FAIL,
	.ruleset_pending_cb = NULL,
	.ruleset_resolve_calls = 0,
	.ruleset_route_calls = 0,
	.ruleset_route6_calls = 0,
	.ruleset_cancel_calls = 0,
#endif
};

#if WITH_RULESET
static int stub_ruleset_state_tag = 0;
#endif

static void stub_reset(void)
{
	STUB.dialreq_available = false;
	STUB.dialaddr_set_ok = false;
	STUB.dialaddr_set_calls = 0;
	STUB.dialreq_free_calls = 0;
	STUB.dialer_mode = STUB_DIALER_NONE;
	STUB.dialer_err = DIALER_ERR_CONNECT;
	STUB.dialer_syserr = ECONNREFUSED;
	STUB.dialer_result_fd = -1;
	STUB.dialer_do_calls = 0;
	STUB.dialer_cancel_calls = 0;
	for (int i = 0; i < STUB.xfer_count; i++) {
		free(STUB.xfer_ctxs[i]);
		STUB.xfer_ctxs[i] = NULL;
	}
	STUB.xfer_count = 0;
#if WITH_RULESET
	STUB.ruleset_mode = STUB_RULESET_FAIL;
	STUB.ruleset_pending_cb = NULL;
	STUB.ruleset_resolve_calls = 0;
	STUB.ruleset_route_calls = 0;
	STUB.ruleset_route6_calls = 0;
	STUB.ruleset_cancel_calls = 0;
#endif
	test_conf.timeout = 1.0;
}

static void test_server_init(struct server *restrict s)
{
	s->conf = &test_conf;
	s->resolver = NULL;
	s->xfer = transfer_new(s->loop);
	s->basereq = NULL;
#if WITH_RULESET
	s->ruleset = NULL;
#endif
}

struct test_watchdog {
	bool fired;
};

static void
test_watchdog_cb(struct ev_loop *loop, struct ev_timer *w, const int revents)
{
	struct test_watchdog *const watchdog = w->data;
	UNUSED(revents);
	watchdog->fired = true;
	ev_break(loop, EVBREAK_ONE);
}

static void test_run_for(struct ev_loop *loop, const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired) {
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_timeout);
}

#if WITH_RULESET
static void test_drive_once(struct ev_loop *loop, const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	ev_run(loop, EVRUN_ONCE);
	ev_timer_stop(loop, &w_timeout);
}
#endif

static void make_socketpair(int *restrict left_fd, int *restrict right_fd)
{
	int sv[2] = { -1, -1 };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	*left_fd = sv[0];
	*right_fd = sv[1];
}

#if WITH_TPROXY
static int make_bound_ipv4_socket(void)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
		.sin_port = 0,
	};

	T_CHECK(fd >= 0);
	T_CHECK(bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0);
	return fd;
}
#endif

static void set_ipv4_addr(struct dialaddr *restrict addr, const uint16_t port)
{
	memset(addr, 0, sizeof(*addr));
	addr->type = ATYP_INET;
	addr->port = port;
	addr->in.s_addr = htonl(INADDR_LOOPBACK);
}

#if WITH_RULESET
static void set_domain_addr(
	struct dialaddr *restrict addr, const char *restrict name,
	const uint16_t port)
{
	const size_t len = strlen(name);

	memset(addr, 0, sizeof(*addr));
	addr->type = ATYP_DOMAIN;
	addr->port = port;
	addr->domain.len = len;
	(void)memcpy(addr->domain.name, name, len);
}
#endif

const char *dialer_strerror(const enum dialer_error err)
{
	UNUSED(err);
	return "stub";
}

struct dialreq *dialreq_new(const struct dialreq *base, const size_t num_proxy)
{
	struct dialreq *req;
	const size_t size = sizeof(*req) + num_proxy * sizeof(req->proxy[0]);

	UNUSED(base);
	if (!STUB.dialreq_available) {
		return NULL;
	}
	req = calloc(1, size);
	if (req == NULL) {
		return NULL;
	}
	req->num_proxy = num_proxy;
	return req;
}

bool dialreq_addproxy(
	struct dialreq *restrict req, const char *restrict proxy_uri,
	const size_t urilen)
{
	UNUSED(req);
	UNUSED(proxy_uri);
	UNUSED(urilen);
	return false;
}

struct dialreq *
dialreq_parse(const char *restrict addr, const char *restrict csv)
{
	UNUSED(addr);
	UNUSED(csv);
	return NULL;
}

int dialreq_format(
	char *restrict s, const size_t maxlen, const struct dialreq *restrict r)
{
	UNUSED(s);
	UNUSED(maxlen);
	UNUSED(r);
	return -1;
}

void dialreq_free(struct dialreq *req)
{
	STUB.dialreq_free_calls++;
	free(req);
}

bool dialaddr_parse(
	struct dialaddr *restrict addr, const char *restrict s,
	const size_t len)
{
	UNUSED(addr);
	UNUSED(s);
	UNUSED(len);
	return false;
}

bool dialaddr_set(
	struct dialaddr *restrict addr, const struct sockaddr *restrict sa,
	const socklen_t len)
{
	UNUSED(len);
	STUB.dialaddr_set_calls++;
	if (!STUB.dialaddr_set_ok) {
		return false;
	}
	switch (sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *const in =
			(const struct sockaddr_in *)sa;
		addr->type = ATYP_INET;
		addr->port = ntohs(in->sin_port);
		addr->in = in->sin_addr;
		return true;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *const in6 =
			(const struct sockaddr_in6 *)sa;
		addr->type = ATYP_INET6;
		addr->port = ntohs(in6->sin6_port);
		addr->in6 = in6->sin6_addr;
		return true;
	}
	default:
		return false;
	}
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

void dialer_init(struct dialer *restrict d, const struct dialer_cb *callback)
{
	d->finish_cb = *callback;
	d->err = DIALER_OK;
	d->syserr = 0;
}

void dialer_do(
	struct dialer *d, struct ev_loop *loop, const struct dialreq *req,
	const struct config *conf, struct resolver *resolver)
{
	UNUSED(req);
	UNUSED(conf);
	UNUSED(resolver);
	STUB.dialer_do_calls++;

	switch (STUB.dialer_mode) {
	case STUB_DIALER_NONE:
		return;
	case STUB_DIALER_FAIL:
		d->err = STUB.dialer_err;
		d->syserr = STUB.dialer_syserr;
		d->finish_cb.func(loop, d->finish_cb.data, -1);
		return;
	case STUB_DIALER_SUCCESS:
		d->err = DIALER_OK;
		d->syserr = 0;
		d->finish_cb.func(
			loop, d->finish_cb.data, STUB.dialer_result_fd);
		return;
	default:
		return;
	}
}

void dialer_cancel(struct dialer *restrict d, struct ev_loop *restrict loop)
{
	UNUSED(d);
	UNUSED(loop);
	STUB.dialer_cancel_calls++;
}

struct stub_xfer_ctx {
#if WITH_THREADS
	atomic_size_t *num_sessions;
#else
	size_t *num_sessions;
#endif
};

struct transfer *transfer_new(struct ev_loop *restrict loop)
{
	UNUSED(loop);
	static int token;
	return (struct transfer *)&token;
}

void transfer_free(struct transfer *restrict xfer)
{
	UNUSED(xfer);
}

bool transfer_serve(
	struct transfer *restrict xfer, const int acc_fd, const int dial_fd,
	const struct transfer_opts *restrict opts)
{
	UNUSED(xfer);
	UNUSED(acc_fd);
	UNUSED(dial_fd);
	T_CHECK(STUB.xfer_count <
		(int)(sizeof(STUB.xfer_ctxs) / sizeof(STUB.xfer_ctxs[0])));
	struct stub_xfer_ctx *restrict xctx = malloc(sizeof(*xctx));
	if (xctx == NULL) {
		return false;
	}
	xctx->num_sessions = opts->num_sessions;
	STUB.xfer_ctxs[STUB.xfer_count++] = xctx;
	return true;
}

static void stub_fire_all_xfer_finished(struct ev_loop *loop)
{
	UNUSED(loop);
	for (int i = 0; i < STUB.xfer_count; i++) {
		struct stub_xfer_ctx *restrict xctx = STUB.xfer_ctxs[i];
#if WITH_THREADS
		atomic_fetch_sub_explicit(
			xctx->num_sessions, 1, memory_order_relaxed);
#else
		(*xctx->num_sessions)--;
#endif
	}
}

#if WITH_RULESET
void ruleset_cancel(struct ev_loop *loop, struct ruleset_state *restrict state)
{
	UNUSED(loop);
	UNUSED(state);
	STUB.ruleset_cancel_calls++;
}

static bool ruleset_stub_start(
	struct ruleset_state **state, struct ruleset_callback *callback)
{
	if (STUB.ruleset_mode != STUB_RULESET_ASYNC_OK) {
		return false;
	}
	callback->request.req = dialreq_new(NULL, 0);
	if (callback->request.req == NULL) {
		return false;
	}
	set_ipv4_addr(&callback->request.req->addr, 443);
	*state = (struct ruleset_state *)&stub_ruleset_state_tag;
	STUB.ruleset_pending_cb = callback;
	return true;
}

bool ruleset_resolve(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	UNUSED(r);
	UNUSED(request);
	UNUSED(username);
	UNUSED(password);
	STUB.ruleset_resolve_calls++;
	return ruleset_stub_start(state, callback);
}

bool ruleset_route(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	UNUSED(r);
	UNUSED(request);
	UNUSED(username);
	UNUSED(password);
	STUB.ruleset_route_calls++;
	return ruleset_stub_start(state, callback);
}

bool ruleset_route6(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	UNUSED(r);
	UNUSED(request);
	UNUSED(username);
	UNUSED(password);
	STUB.ruleset_route6_calls++;
	return ruleset_stub_start(state, callback);
}

static void complete_pending_ruleset(struct ev_loop *loop)
{
	T_CHECK(STUB.ruleset_pending_cb != NULL);
	ev_feed_event(loop, &STUB.ruleset_pending_cb->w_finish, EV_CUSTOM);
	STUB.ruleset_pending_cb = NULL;
	test_drive_once(loop, TEST_WAIT_SHORT_SEC);
}
#endif

T_DECLARE_CASE(forward_dialer_fail_updates_stats)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = {
		.sin_family = AF_INET,
	};
	struct dialreq base_req = { 0 };
	int accepted_fd = -1;
	int peer_fd = -1;

	stub_reset();
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.dialer_err = DIALER_ERR_CONNECT;
	STUB.dialer_syserr = ENETUNREACH;
	set_ipv4_addr(&base_req.addr, 80);

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	s.basereq = &base_req;
	make_socketpair(&accepted_fd, &peer_fd);

	forward_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);

	T_EXPECT_EQ(STUB.dialer_do_calls, 1);
	T_EXPECT_EQ(STUB.dialer_cancel_calls, 1);
	T_EXPECT_EQ(s.stats.num_request, 1);
	T_EXPECT_EQ(s.stats.num_success, 0);
	T_EXPECT_EQ(s.stats.num_halfopen, 0);
	T_EXPECT_EQ(s.num_sessions, 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(forward_timeout_cancels_pending_dialer)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = {
		.sin_family = AF_INET,
	};
	struct dialreq base_req = { 0 };
	int accepted_fd = -1;
	int peer_fd = -1;

	stub_reset();
	test_conf.timeout = TEST_WAIT_SHORT_SEC;
	set_ipv4_addr(&base_req.addr, 80);

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	s.basereq = &base_req;
	make_socketpair(&accepted_fd, &peer_fd);

	forward_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);
	test_run_for(loop, TEST_WAIT_TIMEOUT_SEC);

	T_EXPECT_EQ(STUB.dialer_do_calls, 1);
	T_EXPECT_EQ(STUB.dialer_cancel_calls, 1);
	T_EXPECT_EQ(s.stats.num_request, 1);
	T_EXPECT_EQ(s.stats.num_success, 0);
	T_EXPECT_EQ(s.stats.num_halfopen, 0);
	T_EXPECT_EQ(s.num_sessions, 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(forward_bidir_timeout_connected_then_finished)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = {
		.sin_family = AF_INET,
	};
	struct dialreq base_req = { 0 };
	int accepted_fd = -1;
	int accepted_peer_fd = -1;
	int dialed_fd = -1;
	int dialed_peer_fd = -1;

	stub_reset();
	STUB.dialer_mode = STUB_DIALER_SUCCESS;
	set_ipv4_addr(&base_req.addr, 443);

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	s.basereq = &base_req;
	make_socketpair(&accepted_fd, &accepted_peer_fd);
	make_socketpair(&dialed_fd, &dialed_peer_fd);
	STUB.dialer_result_fd = dialed_fd;

	forward_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);

	/* After serve: ctx is already unref'd; transfer is running. */
	T_EXPECT_EQ(STUB.xfer_count, 1);
	T_EXPECT_EQ(s.stats.num_request, 1);
	T_EXPECT_EQ(s.stats.num_success, 1);
	T_EXPECT_EQ(s.stats.num_halfopen, 0);
	T_EXPECT_EQ(s.num_sessions, (size_t)1);

	/* Simulate transfer finishing on the xfer thread. */
	stub_fire_all_xfer_finished(loop);

	T_EXPECT_EQ(s.stats.num_success, 1);
	T_EXPECT_EQ(s.stats.num_halfopen, 0);
	T_EXPECT_EQ(s.num_sessions, (size_t)0);

	T_CHECK(close(accepted_peer_fd) == 0);
	T_CHECK(close(dialed_peer_fd) == 0);
	ev_loop_destroy(loop);
}

#if WITH_RULESET
T_DECLARE_CASE(forward_ruleset_async_then_dialer_fail)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = {
		.sin_family = AF_INET,
	};
	struct dialreq base_req = { 0 };
	int accepted_fd = -1;
	int peer_fd = -1;

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.ruleset_mode = STUB_RULESET_ASYNC_OK;
	set_domain_addr(&base_req.addr, "example.org", 443);

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	s.basereq = &base_req;
	s.ruleset = (struct ruleset *)&s;
	make_socketpair(&accepted_fd, &peer_fd);

	forward_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);
	test_drive_once(loop, TEST_WAIT_SHORT_SEC);

	T_EXPECT_EQ(STUB.ruleset_resolve_calls, 1);
	T_EXPECT(STUB.ruleset_pending_cb != NULL);
	T_EXPECT_EQ(s.stats.num_request, 0);

	complete_pending_ruleset(loop);

	T_EXPECT_EQ(STUB.ruleset_resolve_calls, 1);
	T_EXPECT_EQ(STUB.ruleset_cancel_calls, 0);
	T_EXPECT_EQ(STUB.dialer_cancel_calls, 1);
	T_EXPECT_EQ(STUB.dialreq_free_calls, 1);
	T_EXPECT_EQ(s.stats.num_request, 1);
	T_EXPECT_EQ(s.stats.num_success, 0);
	T_EXPECT_EQ(s.stats.num_halfopen, 0);
	T_EXPECT_EQ(s.num_sessions, 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}
#endif

#if WITH_TPROXY
T_DECLARE_CASE(tproxy_dialer_fail_uses_socket_destination)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = {
		.sin_family = AF_INET,
	};
	int accepted_fd = -1;

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialaddr_set_ok = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	accepted_fd = make_bound_ipv4_socket();

	tproxy_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);

	T_EXPECT_EQ(STUB.dialaddr_set_calls, 1);
	T_EXPECT_EQ(STUB.dialreq_free_calls, 1);
	T_EXPECT_EQ(STUB.dialer_cancel_calls, 1);
	T_EXPECT_EQ(s.stats.num_request, 1);
	T_EXPECT_EQ(s.stats.num_success, 0);
	T_EXPECT_EQ(s.stats.num_halfopen, 0);
	T_EXPECT_EQ(s.num_sessions, 0);

	ev_loop_destroy(loop);
}
#endif

#define FORWARD_TESTS(X)                                                       \
	X(forward_dialer_fail_updates_stats);                                  \
	X(forward_timeout_cancels_pending_dialer);                             \
	X(forward_bidir_timeout_connected_then_finished)

#if WITH_RULESET
#define FORWARD_RULESET_TESTS(X) X(forward_ruleset_async_then_dialer_fail)
#else
#define FORWARD_RULESET_TESTS(X)
#endif

#if WITH_TPROXY
#define FORWARD_TPROXY_TESTS(X) X(tproxy_dialer_fail_uses_socket_destination)
#else
#define FORWARD_TPROXY_TESTS(X)
#endif

int main(void)
{
	T_DECLARE_CTX(t);

#define RUN_TEST(name) T_RUN_CASE(t, name)
	FORWARD_TESTS(RUN_TEST);
	FORWARD_RULESET_TESTS(RUN_TEST);
	FORWARD_TPROXY_TESTS(RUN_TEST);
#undef RUN_TEST

	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
