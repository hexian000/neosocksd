/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for forward.c; mocked: dialer, transfer, ruleset. */

#include "forward.h"

#include "conf.h"
#include "dialer.h"
#include "ruleset.h"
#include "server.h"
#include "transfer.h"
#include "util.h"

#include "utils/arraysize.h"
#include "utils/testing.h"

#include <ev.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - collaborator stubs (dialer, transfer, ruleset) and shared fixtures.
 * ---------------------------------------------------------------------- */

static struct config test_conf = {
	.timeout = 1.0,
};

static const ev_tstamp TEST_WAIT_SHORT_SEC = 0.032;
static const ev_tstamp TEST_WAIT_TIMEOUT_SEC = 0.128;

char *const proxy_protocol_str[PROTO_MAX] = {
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
	/* completes asynchronously with no dialreq (a policy rejection) */
	STUB_RULESET_ASYNC_REJECT,
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
	s->xfer = transfer_create(s->loop, 1);
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
	(void)revents;
	watchdog->fired = true;
	ev_break(loop, EVBREAK_ONE);
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
#endif /* WITH_RULESET */

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
#endif /* WITH_TPROXY */

static void
set_ipv4_addr(struct dialaddr *restrict addr, const uint_fast16_t port)
{
	memset(addr, 0, sizeof(*addr));
	addr->type = ATYP_INET;
	addr->port = port;
	addr->in.s_addr = htonl(INADDR_LOOPBACK);
}
#if WITH_RULESET
static void
set_ipv6_addr(struct dialaddr *restrict addr, const uint_fast16_t port)
{
	memset(addr, 0, sizeof(*addr));
	addr->type = ATYP_INET6;
	addr->port = port;
	addr->in6 = in6addr_loopback;
}

static void set_domain_addr(
	struct dialaddr *restrict addr, const char *restrict name,
	const uint_fast16_t port)
{
	const size_t len = strlen(name);

	memset(addr, 0, sizeof(*addr));
	addr->type = ATYP_DOMAIN;
	addr->port = port;
	addr->domain.len = len;
	(void)memcpy(addr->domain.name, name, len);
}
#endif /* WITH_RULESET */

const char *dialer_strerror(const enum dialer_error err)
{
	(void)err;
	return "stub";
}

struct dialreq *dialreq_new(const struct dialreq *base, const size_t num_proxy)
{
	struct dialreq *req;
	const size_t size = sizeof(*req) + num_proxy * sizeof(req->proxy[0]);

	(void)base;
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
	STUB.dialreq_free_calls++;
	free(req);
}

bool dialaddr_parse(
	struct dialaddr *restrict addr, const char *restrict s,
	const size_t len)
{
	(void)addr;
	(void)s;
	(void)len;
	return false;
}

bool dialaddr_set(
	struct dialaddr *restrict addr, const struct sockaddr *restrict sa,
	const socklen_t len)
{
	(void)len;
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
	(void)d;
	(void)loop;
	STUB.dialer_cancel_calls++;
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
	T_CHECK(STUB.xfer_count < (int)ARRAY_SIZE(STUB.xfer_ctxs));
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
	(void)loop;
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
	(void)loop;
	(void)state;
	STUB.ruleset_cancel_calls++;
}

static bool ruleset_stub_start(
	struct ruleset_state **state, struct ruleset_callback *callback)
{
	if (STUB.ruleset_mode == STUB_RULESET_ASYNC_REJECT) {
		/* simulate a ruleset that completes without a dialreq */
		callback->request.req = NULL;
		*state = (struct ruleset_state *)&stub_ruleset_state_tag;
		STUB.ruleset_pending_cb = callback;
		return true;
	}
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
	(void)r;
	(void)request;
	(void)username;
	(void)password;
	STUB.ruleset_resolve_calls++;
	return ruleset_stub_start(state, callback);
}

bool ruleset_route(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	(void)r;
	(void)request;
	(void)username;
	(void)password;
	STUB.ruleset_route_calls++;
	return ruleset_stub_start(state, callback);
}

bool ruleset_route6(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback)
{
	(void)r;
	(void)request;
	(void)username;
	(void)password;
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
#endif /* WITH_RULESET */

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - dialer/ruleset outcomes and connection accounting.
 * ---------------------------------------------------------------------- */

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

	/* Wait for timeout to clean up — exit when num_halfopen hits zero. */
	{
		struct test_watchdog watchdog = { 0 };
		struct ev_timer w;
		ev_timer_init(&w, test_watchdog_cb, TEST_WAIT_TIMEOUT_SEC, 0.0);
		w.data = &watchdog;
		ev_timer_start(loop, &w);
		while (!watchdog.fired && s.stats.num_halfopen != 0) {
			ev_run(loop, EVRUN_ONCE);
		}
		ev_timer_stop(loop, &w);
	}

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
	/* num_request is counted at request receipt (in forward_serve) */
	T_EXPECT_EQ(s.stats.num_request, 1);

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

/* IPv4 base → ruleset_route(); IPv6 base → ruleset_route6(). */
T_DECLARE_SUBCASE(forward_ruleset_route_case, const bool ipv6)
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
	if (ipv6) {
		set_ipv6_addr(&base_req.addr, 443);
	} else {
		set_ipv4_addr(&base_req.addr, 443);
	}

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	s.basereq = &base_req;
	s.ruleset = (struct ruleset *)&s;
	make_socketpair(&accepted_fd, &peer_fd);

	forward_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);
	test_drive_once(loop, TEST_WAIT_SHORT_SEC);

	T_EXPECT_EQ(STUB.ruleset_resolve_calls, 0);
	if (ipv6) {
		T_EXPECT_EQ(STUB.ruleset_route_calls, 0);
		T_EXPECT_EQ(STUB.ruleset_route6_calls, 1);
	} else {
		T_EXPECT_EQ(STUB.ruleset_route_calls, 1);
		T_EXPECT_EQ(STUB.ruleset_route6_calls, 0);
	}

	complete_pending_ruleset(loop);

	/* the ruleset-supplied request is dialed; the dialer then fails */
	T_EXPECT_EQ(STUB.dialer_cancel_calls, 1);
	T_EXPECT_EQ(s.stats.num_request, 1);
	T_EXPECT_EQ(s.stats.num_success, 0);
	T_EXPECT_EQ(s.stats.num_halfopen, 0);
	T_EXPECT_EQ(s.num_sessions, 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(forward_ruleset_route_ipv4)
{
	T_CALL_SUBCASE(forward_ruleset_route_case, false);
}

T_DECLARE_CASE(forward_ruleset_route_ipv6)
{
	T_CALL_SUBCASE(forward_ruleset_route_case, true);
}

/* Ruleset callback with no dialreq = policy rejection. */
T_DECLARE_CASE(forward_ruleset_reject)
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
	STUB.ruleset_mode = STUB_RULESET_ASYNC_REJECT;
	set_ipv4_addr(&base_req.addr, 80);

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	s.basereq = &base_req;
	s.ruleset = (struct ruleset *)&s;
	make_socketpair(&accepted_fd, &peer_fd);

	forward_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);
	test_drive_once(loop, TEST_WAIT_SHORT_SEC);
	T_EXPECT_EQ(STUB.ruleset_route_calls, 1);

	complete_pending_ruleset(loop);

	/* rejection: no dial attempt, the connection is dropped */
	T_EXPECT_EQ(STUB.dialer_do_calls, 0);
	T_EXPECT_EQ(s.stats.num_reject_ruleset, (uint_least64_t)1);
	T_EXPECT_EQ(s.stats.num_reject_upstream, (uint_least64_t)0);
	T_EXPECT_EQ(s.stats.num_halfopen, 0);
	T_EXPECT_EQ(s.num_sessions, 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}
#endif /* WITH_RULESET */

/* SIGHUP may clear s->ruleset between forward_serve and forward_process_cb. */
#if WITH_RULESET
T_DECLARE_CASE(forward_ruleset_null_after_sighup)
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
	/* Use a short timeout so that after the idle watcher fires and
	 * falls back to direct-dial, the timer cleans up quickly. */
	test_conf.timeout = TEST_WAIT_SHORT_SEC;
	STUB.dialer_mode = STUB_DIALER_NONE;
	set_ipv4_addr(&base_req.addr, 80);

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	s.basereq = &base_req;
	s.ruleset = (struct ruleset *)&s;
	make_socketpair(&accepted_fd, &peer_fd);

	forward_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);
	/* Simulate SIGHUP: clear ruleset before the idle watcher fires. */
	s.ruleset = NULL;

	/* Run until the forward timeout fires; idle cb falls back to direct
	 * dial, then num_halfopen hits zero. */
	{
		struct test_watchdog watchdog = { 0 };
		struct ev_timer w;
		ev_timer_init(&w, test_watchdog_cb, TEST_WAIT_TIMEOUT_SEC, 0.0);
		w.data = &watchdog;
		ev_timer_start(loop, &w);
		while (!watchdog.fired && s.stats.num_halfopen != 0) {
			ev_run(loop, EVRUN_ONCE);
		}
		ev_timer_stop(loop, &w);
	}

	/* forward_process_cb fell back to direct dial; dialer_do called once. */
	T_EXPECT_EQ(STUB.dialer_do_calls, 1);
	T_EXPECT_EQ(STUB.dialer_cancel_calls, 1);
	T_EXPECT_EQ(s.stats.num_halfopen, (size_t)0);
	T_EXPECT_EQ(s.num_sessions, (size_t)0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}
#endif /* WITH_RULESET */

/* num_halfopen must not underflow on repeated creation/cancellation. */
T_DECLARE_CASE(forward_num_halfopen_no_underflow)
{
	static const int ITERATIONS = 50;
	const ev_tstamp max_wait = TEST_WAIT_TIMEOUT_SEC;

	for (int i = 0; i < ITERATIONS; i++) {
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
		STUB.dialer_mode = STUB_DIALER_NONE;
		set_ipv4_addr(&base_req.addr, 80);

		T_CHECK(loop != NULL);
		s.loop = loop;
		test_server_init(&s);
		s.basereq = &base_req;
		make_socketpair(&accepted_fd, &peer_fd);

		forward_serve(
			&s, loop, accepted_fd,
			(const struct sockaddr *)&accepted_sa);
		T_EXPECT_EQ(s.stats.num_halfopen, (size_t)1);

		/* Wait for timeout to clean up — exit when num_halfopen hits zero. */
		{
			struct test_watchdog watchdog = { 0 };
			struct ev_timer w;
			ev_timer_init(&w, test_watchdog_cb, max_wait, 0.0);
			w.data = &watchdog;
			ev_timer_start(loop, &w);
			while (!watchdog.fired && s.stats.num_halfopen != 0) {
				ev_run(loop, EVRUN_ONCE);
			}
			ev_timer_stop(loop, &w);
		}

		T_EXPECT_EQ(s.stats.num_halfopen, (size_t)0);
		T_EXPECT_EQ(s.num_sessions, (size_t)0);

		T_CHECK(close(peer_fd) == 0);
		ev_loop_destroy(loop);
	}
}

/* Timeout with dialer pending: dialer_cancel must be called exactly once. */
T_DECLARE_CASE(forward_timeout_stops_pending_dialer_once)
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
	STUB.dialer_mode = STUB_DIALER_NONE;
	set_ipv4_addr(&base_req.addr, 80);

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	s.basereq = &base_req;
	make_socketpair(&accepted_fd, &peer_fd);

	forward_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);

	/* Wait for timeout to clean up — exit when num_halfopen hits zero. */
	{
		struct test_watchdog watchdog = { 0 };
		struct ev_timer w;
		ev_timer_init(&w, test_watchdog_cb, TEST_WAIT_TIMEOUT_SEC, 0.0);
		w.data = &watchdog;
		ev_timer_start(loop, &w);
		while (!watchdog.fired && s.stats.num_halfopen != 0) {
			ev_run(loop, EVRUN_ONCE);
		}
		ev_timer_stop(loop, &w);
	}

	/* No ruleset: one direct dial attempt, cancelled exactly once by timeout. */
	T_EXPECT_EQ(STUB.dialer_do_calls, 1);
	T_EXPECT_EQ(STUB.dialer_cancel_calls, 1);
	T_EXPECT_EQ(s.stats.num_reject_timeout, (uint_least64_t)1);
	T_EXPECT_EQ(s.stats.num_halfopen, (size_t)0);
	T_EXPECT_EQ(s.num_sessions, (size_t)0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

#if WITH_TPROXY && WITH_RULESET
/* tproxy: getsockname() → ruleset_route() for IPv4. */
T_DECLARE_CASE(tproxy_ruleset_route_ipv4)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = {
		.sin_family = AF_INET,
	};
	int accepted_fd = -1;

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;
	STUB.ruleset_mode = STUB_RULESET_ASYNC_OK;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	accepted_fd = make_bound_ipv4_socket();
	s.ruleset = (struct ruleset *)&s;

	tproxy_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);
	test_drive_once(loop, TEST_WAIT_SHORT_SEC);

	/* the bound IPv4 destination is routed via ruleset_route() */
	T_EXPECT_EQ(STUB.ruleset_route_calls, 1);
	T_EXPECT_EQ(STUB.ruleset_route6_calls, 0);
	T_EXPECT(STUB.ruleset_pending_cb != NULL);

	complete_pending_ruleset(loop);

	T_EXPECT_EQ(STUB.dialer_cancel_calls, 1);
	T_EXPECT_EQ(s.stats.num_request, 1);
	T_EXPECT_EQ(s.stats.num_halfopen, 0);
	T_EXPECT_EQ(s.num_sessions, 0);

	ev_loop_destroy(loop);
}

/* SIGHUP may clear s->ruleset between forward_serve and tproxy_process_cb. */
T_DECLARE_CASE(tproxy_ruleset_null_after_sighup)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = {
		.sin_family = AF_INET,
	};
	int accepted_fd = -1;

	stub_reset();
	STUB.dialaddr_set_ok = true;
	STUB.dialer_mode = STUB_DIALER_NONE;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	accepted_fd = make_bound_ipv4_socket();
	s.ruleset = (struct ruleset *)&s;

	tproxy_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);

	/* Simulate SIGHUP clearing ruleset before idle watcher fires. */
	s.ruleset = NULL;
	ev_run(loop, EVRUN_NOWAIT);

	/* tproxy_process_cb must reject (num_reject_ruleset++) rather than crash. */
	T_EXPECT_EQ(s.stats.num_reject_ruleset, (uint_least64_t)1);
	T_EXPECT_EQ(s.stats.num_halfopen, (size_t)0);
	T_EXPECT_EQ(s.num_sessions, (size_t)0);

	ev_loop_destroy(loop);
}
#endif /* WITH_TPROXY && WITH_RULESET */

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
#endif /* WITH_TPROXY */

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(forward_dialer_fail_updates_stats),
	T_CASE(forward_timeout_cancels_pending_dialer),
	T_CASE(forward_bidir_timeout_connected_then_finished),
	T_CASE(forward_num_halfopen_no_underflow),
	T_CASE(forward_timeout_stops_pending_dialer_once),
#if WITH_RULESET
	T_CASE(forward_ruleset_async_then_dialer_fail),
	T_CASE(forward_ruleset_route_ipv4),
	T_CASE(forward_ruleset_route_ipv6),
	T_CASE(forward_ruleset_reject),
	T_CASE(forward_ruleset_null_after_sighup),
#endif /* WITH_RULESET */
#if WITH_TPROXY
	T_CASE(tproxy_dialer_fail_uses_socket_destination),
#endif
#if WITH_TPROXY && WITH_RULESET
	T_CASE(tproxy_ruleset_route_ipv4),
	T_CASE(tproxy_ruleset_null_after_sighup),
#endif
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	const int ret = testing_main(argc, argv, suite);
	stub_reset();
	return ret;
}
