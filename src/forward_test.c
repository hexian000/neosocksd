/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for forward.c; mocked: dialer, transfer, ruleset. */

#include "forward.h"

#include "conf.h"
#include "dialer.h"
#include "ruleset/ruleset.h"
#include "server.h"
#include "transfer.h"

#include "meta/arraysize.h"
#if WITH_RULESET
#include "utils/gc.h"
#endif
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <arpa/inet.h>
#include <errno.h>
#if WITH_TPROXY
#include <fcntl.h>
#endif
#include <netinet/in.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
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

const char *const proxy_protocol_str[PROTO_MAX] = {
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
	bool hold_timeout;
	struct ev_timer *held_timeout;
	bool dialreq_available;
	bool dialaddr_set_ok;
	int_least32_t dialaddr_set_calls;
	int_least32_t dialreq_free_calls;

	enum stub_dialer_mode dialer_mode;
	enum dialer_error dialer_err;
	int dialer_syserr;
	int dialer_result_fd;
	int_least32_t dialer_do_calls;
	int_least32_t dialer_cancel_calls;

	struct stub_xfer_ctx *xfer_ctxs[2];
	int_least32_t xfer_count;
	bool xfer_serve_fail;

#if WITH_RULESET
	enum stub_ruleset_mode ruleset_mode;
	struct ruleset_callback *ruleset_pending_cb;
	/* the caller's ruleset_state, detached at completion as the real
	 * state_complete() does */
	struct ruleset_state **ruleset_selfptr;
	int_least32_t ruleset_resolve_calls;
	int_least32_t ruleset_route_calls;
	int_least32_t ruleset_route6_calls;
	int_least32_t ruleset_cancel_calls;
#endif /* WITH_RULESET */
} STUB = {
	.dialreq_available = true,
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
	.xfer_serve_fail = false,
#if WITH_RULESET
	.ruleset_mode = STUB_RULESET_FAIL,
	.ruleset_pending_cb = NULL,
	.ruleset_selfptr = NULL,
	.ruleset_resolve_calls = 0,
	.ruleset_route_calls = 0,
	.ruleset_route6_calls = 0,
	.ruleset_cancel_calls = 0,
#endif
};

#if WITH_RULESET
static int stub_ruleset_state_tag = 0;
#endif

/* log capture - the fd-correlation prefix has no output other than the log, so
 * the case reads back the lines production emitted. */
static struct {
	char buf[8192];
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

/* Copy the whole captured line containing @p needle into @p out. A substring
 * search cannot tell "[fd:9] addr: closing" from "addr: closing"; the line
 * boundaries can. */
static bool logcap_line(
	const char *restrict needle, char *restrict out, const size_t maxlen)
{
	const char *const hit = strstr(g_logcap.buf, needle);
	if (hit == NULL) {
		return false;
	}
	const char *begin = hit;
	while (begin > g_logcap.buf && begin[-1] != '\n') {
		begin--;
	}
	const char *end = strchr(hit, '\n');
	if (end == NULL) {
		end = g_logcap.buf + g_logcap.len;
	}
	const size_t len = (size_t)(end - begin);
	if (len >= maxlen) {
		return false;
	}
	(void)memcpy(out, begin, len);
	out[len] = '\0';
	return true;
}

static void stub_reset(void)
{
	logcap_stop();
	STUB.hold_timeout = false;
	STUB.held_timeout = NULL;
	STUB.dialreq_available = true;
	STUB.dialaddr_set_ok = false;
	STUB.dialaddr_set_calls = 0;
	STUB.dialreq_free_calls = 0;
	STUB.dialer_mode = STUB_DIALER_NONE;
	STUB.dialer_err = DIALER_ERR_CONNECT;
	STUB.dialer_syserr = ECONNREFUSED;
	STUB.dialer_result_fd = -1;
	STUB.dialer_do_calls = 0;
	STUB.dialer_cancel_calls = 0;
	for (int_fast32_t i = 0; i < STUB.xfer_count; i++) {
		free(STUB.xfer_ctxs[i]);
		STUB.xfer_ctxs[i] = NULL;
	}
	STUB.xfer_count = 0;
	STUB.xfer_serve_fail = false;
#if WITH_RULESET
	STUB.ruleset_mode = STUB_RULESET_FAIL;
	STUB.ruleset_pending_cb = NULL;
	STUB.ruleset_selfptr = NULL;
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

/* Only forward.c redirects ev_timer_start here. Timeout cases hold the
 * initialized production watcher until the dialer/ruleset state is observable;
 * no amount of setup or scheduler delay can expire it prematurely. */
void test_ev_timer_start(struct ev_loop *loop, ev_timer *watcher);

void test_ev_timer_start(struct ev_loop *loop, ev_timer *watcher)
{
	if (STUB.hold_timeout) {
		T_CHECK(STUB.held_timeout == NULL);
		STUB.held_timeout = watcher;
		return;
	}
	ev_timer_start(loop, watcher);
}

/* Arm the held watcher at the current loop time, then let libev dispatch
 * its production callback. Clear the borrowed pointer before teardown frees it. */
static void fire_timeout(struct ev_loop *loop)
{
	struct ev_timer *const watcher = STUB.held_timeout;
	T_CHECK(watcher != NULL);
	STUB.held_timeout = NULL;
	ev_timer_set(watcher, 0.0, 0.0);
	ev_timer_start(loop, watcher);
	ev_run(loop, EVRUN_NOWAIT);
}

#if WITH_RULESET
static void test_drive_once(struct ev_loop *loop)
{
	ev_run(loop, EVRUN_NOWAIT);
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
	addr->domain.len = (uint_least8_t)len;
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
	/* Count only the frees that release a request. dialreq_free(NULL) is a
	 * legal no-op, and counting it would make a context that merely borrowed
	 * its request (leaving ctx->dialreq NULL) reach the same count as one
	 * that owns a copy -- exactly the distinction the callers assert on. */
	if (req != NULL) {
		STUB.dialreq_free_calls++;
	}
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
	xfer_session_counter *num_sessions;
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
	if (STUB.xfer_serve_fail) {
		return false;
	}
	T_CHECK(STUB.xfer_count < (int_fast32_t)ARRAY_SIZE(STUB.xfer_ctxs));
	struct stub_xfer_ctx *restrict xctx = malloc(sizeof(*xctx));
	if (xctx == NULL) {
		return false;
	}
	xctx->num_sessions = opts->num_sessions;
	STUB.xfer_ctxs[STUB.xfer_count++] = xctx;
	/* the real transfer_serve takes ownership of both fds on success and
	 * closes them in release_ctx; emulate that so they do not leak */
	(void)close(acc_fd);
	(void)close(dial_fd);
	return true;
}

static void stub_fire_all_xfer_finished(struct ev_loop *loop)
{
	(void)loop;
	for (int_fast32_t i = 0; i < STUB.xfer_count; i++) {
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

static bool ruleset_stub_start(
	struct ruleset_state **state, struct ruleset_callback *callback)
{
	if (STUB.ruleset_mode != STUB_RULESET_ASYNC_OK &&
	    STUB.ruleset_mode != STUB_RULESET_ASYNC_REJECT) {
		return false;
	}
	/* The real ruleset delivers request.req only at completion (in
	 * request_finish, alongside feeding w_finish); complete_pending_ruleset
	 * mirrors that. Setting it here would leak the dialreq on a teardown that
	 * cancels before completion. */
	(void)callback;
	*state = (struct ruleset_state *)&stub_ruleset_state_tag;
	STUB.ruleset_selfptr = state;
	STUB.ruleset_pending_cb = callback;
	return true;
}

bool ruleset_dispatch(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const int atype,
	const struct ruleset_credentials *restrict creds,
	struct ruleset_callback *callback)
{
	(void)r;
	(void)request;
	(void)creds;
	switch (atype) {
	case ATYP_INET:
		STUB.ruleset_route_calls++;
		break;
	case ATYP_INET6:
		STUB.ruleset_route6_calls++;
		break;
	case ATYP_DOMAIN:
		STUB.ruleset_resolve_calls++;
		break;
	default:
		return false;
	}
	return ruleset_stub_start(state, callback);
}

/* Complete the pending request as request_finish + state_complete would,
 * leaving the fed event for a later loop sweep. */
static struct ruleset_callback *deliver_pending_ruleset(struct ev_loop *loop)
{
	T_CHECK(STUB.ruleset_pending_cb != NULL);
	struct ruleset_callback *restrict cb = STUB.ruleset_pending_cb;
	/* deliver the request (or NULL for a reject) as request_finish would,
	 * just before feeding the completion event */
	if (STUB.ruleset_mode == STUB_RULESET_ASYNC_OK) {
		cb->request.req = dialreq_new(NULL, 0);
		T_CHECK(cb->request.req != NULL);
		set_ipv4_addr(&cb->request.req->addr, 443);
	} else {
		cb->request.req = NULL;
	}
	ev_feed_event(loop, &cb->w_finish, EV_CUSTOM);
	/* a completed operation is detached, so ruleset_cancel no longer
	 * reaches it */
	*STUB.ruleset_selfptr = NULL;
	STUB.ruleset_selfptr = NULL;
	STUB.ruleset_pending_cb = NULL;
	return cb;
}

static void complete_pending_ruleset(struct ev_loop *loop)
{
	(void)deliver_pending_ruleset(loop);
	test_drive_once(loop);
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
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
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
	/* the counter this path uniquely updates */
	T_EXPECT_EQ(s.stats.num_reject_upstream, (uint_least64_t)1);
	T_EXPECT_EQ(s.num_sessions, 0);
	/* the direct dial must own a copy of basereq (not borrow it, which a
	 * SIGHUP reload would free mid-dial): teardown frees exactly that copy */
	T_EXPECT_EQ(STUB.dialreq_free_calls, 1);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(forward_timeout_cancels_pending_dialer)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
	struct dialreq base_req = { 0 };
	int accepted_fd = -1;
	int peer_fd = -1;

	stub_reset();
	STUB.hold_timeout = true;
	set_ipv4_addr(&base_req.addr, 80);

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	s.basereq = &base_req;
	make_socketpair(&accepted_fd, &peer_fd);

	forward_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);

	T_CHECK(STUB.dialer_do_calls == 1);
	T_CHECK(s.stats.num_halfopen == 1);
	fire_timeout(loop);

	/* No ruleset: one direct dial attempt, cancelled exactly once by the
	 * timeout, which also records the timeout rejection. */
	T_EXPECT_EQ(STUB.dialer_do_calls, 1);
	T_EXPECT_EQ(STUB.dialer_cancel_calls, 1);
	T_EXPECT_EQ(s.stats.num_request, 1);
	T_EXPECT_EQ(s.stats.num_success, 0);
	T_EXPECT_EQ(s.stats.num_reject_timeout, (uint_least64_t)1);
	T_EXPECT_EQ(s.stats.num_halfopen, 0);
	T_EXPECT_EQ(s.num_sessions, 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(forward_bidir_timeout_connected_then_finished)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
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

/* The context finalizes after the hand-off moved its descriptor out, so the
 * closing line has none to name. It must print no fd field at all: [fd:-1]
 * names nothing, and the remembered number may already belong to another
 * connection. Lines emitted while the context still owns the descriptor keep
 * naming it. */
T_DECLARE_CASE(forward_close_log_omits_handed_off_fd)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
	struct dialreq base_req = { 0 };
	int accepted_fd = -1;
	int accepted_peer_fd = -1;
	int dialed_fd = -1;
	int dialed_peer_fd = -1;
	char line[256];
	char want[128];

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

	logcap_start(LOG_LEVEL_VERBOSE);
	forward_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);
	logcap_stop();
	T_EXPECT_EQ(STUB.xfer_count, 1);

	T_EXPECT(logcap_line("closing, state=", line, sizeof(line)));
	T_EXPECT(strstr(line, "[fd:") == NULL);
	/* the same session named its descriptor while it still owned one */
	(void)snprintf(want, sizeof(want), "[fd:%d] ", accepted_fd);
	T_EXPECT(logcap_line(": connect\n", line, sizeof(line)));
	T_EXPECT(strstr(line, want) != NULL);

	T_CHECK(close(accepted_peer_fd) == 0);
	T_CHECK(close(dialed_peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* forward_commit's transfer_serve()-failure recovery: undo the session
 * increment, close both fds, and drop the context. */
T_DECLARE_CASE(forward_commit_xfer_serve_failure_recovers)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
	struct dialreq base_req = { 0 };
	int accepted_fd = -1;
	int accepted_peer_fd = -1;
	int dialed_fd = -1;
	int dialed_peer_fd = -1;

	stub_reset();
	STUB.dialer_mode = STUB_DIALER_SUCCESS;
	STUB.xfer_serve_fail = true;
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

	/* transfer_serve failed: no active transfer, session count unwound. */
	T_EXPECT_EQ(STUB.xfer_count, 0);
	T_EXPECT_EQ(s.stats.num_request, 1);
	T_EXPECT_EQ(s.stats.num_success, 0);
	T_EXPECT_EQ(s.stats.num_halfopen, 0);
	T_EXPECT_EQ(s.num_sessions, (size_t)0);

	/* accepted_fd and dialed_fd were closed by the recovery path. */
	T_CHECK(close(accepted_peer_fd) == 0);
	T_CHECK(close(dialed_peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* forward_ctx_start_direct cannot copy basereq: the connection is dropped
 * before any dial, closing the accepted fd and unwinding the half-open count. */
T_DECLARE_CASE(forward_direct_dialreq_oom_closes_accepted)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
	struct dialreq base_req = { 0 };
	int accepted_fd = -1;
	int peer_fd = -1;
	unsigned char byte;

	stub_reset();
	STUB.dialreq_available = false;
	set_ipv4_addr(&base_req.addr, 80);

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	s.basereq = &base_req;
	make_socketpair(&accepted_fd, &peer_fd);

	forward_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);

	T_EXPECT_EQ(STUB.dialer_do_calls, 0);
	T_EXPECT_EQ(STUB.dialreq_free_calls, 0);
	T_EXPECT_EQ(s.stats.num_request, 1);
	T_EXPECT_EQ(s.stats.num_success, 0);
	T_EXPECT_EQ(s.stats.num_halfopen, 0);
	T_EXPECT_EQ(s.num_sessions, 0);
	/* the peer sees EOF: the accepted end was closed */
	T_EXPECT_EQ(recv(peer_fd, &byte, sizeof(byte), MSG_DONTWAIT), 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

#if WITH_RULESET
/* An await.forward() route hands the context an already-connected fd through
 * the ruleset_callback's forward hook while the context is still in
 * STATE_PROCESS: it commits straight to the transfer, with no dial, and the
 * detached ruleset operation is not cancelled on the way out. */
T_DECLARE_CASE(forward_ruleset_forward_hook_commits)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
	struct dialreq base_req = { 0 };
	int accepted_fd = -1;
	int accepted_peer_fd = -1;
	int dialed_fd = -1;
	int dialed_peer_fd = -1;

	stub_reset();
	STUB.ruleset_mode = STUB_RULESET_ASYNC_OK;
	set_ipv4_addr(&base_req.addr, 443);

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	s.basereq = &base_req;
	s.ruleset = (struct ruleset *)&s;
	make_socketpair(&accepted_fd, &accepted_peer_fd);
	make_socketpair(&dialed_fd, &dialed_peer_fd);

	forward_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);
	test_drive_once(loop);
	T_CHECK(STUB.ruleset_pending_cb != NULL);
	T_EXPECT_EQ(s.stats.num_halfopen, 1);

	/* await_forward_k: the routine connected the fd itself */
	struct ruleset_callback *restrict cb = STUB.ruleset_pending_cb;
	STUB.ruleset_pending_cb = NULL;
	STUB.ruleset_selfptr = NULL;
	T_CHECK(cb->forward != NULL);
	cb->forward(loop, cb, dialed_fd);

	T_EXPECT_EQ(STUB.dialer_do_calls, 0);
	T_EXPECT_EQ(STUB.xfer_count, 1);
	T_EXPECT_EQ(STUB.ruleset_cancel_calls, 0);
	T_EXPECT_EQ(STUB.dialreq_free_calls, 0);
	T_EXPECT_EQ(s.stats.num_request, 1);
	T_EXPECT_EQ(s.stats.num_success, 1);
	T_EXPECT_EQ(s.stats.num_halfopen, 0);
	T_EXPECT_EQ(s.num_sessions, (size_t)1);

	stub_fire_all_xfer_finished(loop);
	T_EXPECT_EQ(s.num_sessions, (size_t)0);

	T_CHECK(close(accepted_peer_fd) == 0);
	T_CHECK(close(dialed_peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(forward_ruleset_async_then_dialer_fail)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
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
	test_drive_once(loop);

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
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
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
	test_drive_once(loop);

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
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
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
	test_drive_once(loop);
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

/* Synchronous ruleset-dispatch failure (STUB_RULESET_FAIL) must still count a
 * rejection, keeping num_success + num_reject_* == num_request. */
T_DECLARE_CASE(forward_ruleset_sync_dispatch_fail_counts_reject)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
	struct dialreq base_req = { 0 };
	int accepted_fd = -1;
	int peer_fd = -1;

	stub_reset();
	/* STUB_RULESET_FAIL is the default: ruleset_route returns false
	 * synchronously. */
	set_ipv4_addr(&base_req.addr, 80);

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	s.basereq = &base_req;
	s.ruleset = (struct ruleset *)&s;
	make_socketpair(&accepted_fd, &peer_fd);

	forward_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);
	test_drive_once(loop);

	T_EXPECT_EQ(STUB.ruleset_route_calls, 1);
	T_EXPECT_EQ(STUB.dialer_do_calls, 0);
	T_EXPECT_EQ(s.stats.num_request, (uint_least64_t)1);
	T_EXPECT_EQ(s.stats.num_reject_ruleset, (uint_least64_t)1);
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
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
	struct dialreq base_req = { 0 };
	int accepted_fd = -1;
	int peer_fd = -1;

	stub_reset();
	/* Hold the deadline until the idle watcher has fallen back to dial. */
	STUB.hold_timeout = true;
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

	/* Reach the fallback dial before firing its deadline. */
	test_drive_once(loop);
	T_CHECK(STUB.dialer_do_calls == 1);
	T_CHECK(s.stats.num_halfopen == 1);
	fire_timeout(loop);

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
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct dialreq base_req = { 0 };

	T_CHECK(loop != NULL);
	stub_reset();
	STUB.hold_timeout = true;
	STUB.dialer_mode = STUB_DIALER_NONE;
	set_ipv4_addr(&base_req.addr, 80);
	s.loop = loop;
	test_server_init(&s);
	s.basereq = &base_req;

	/* Repeated accept/timeout cycles share one num_halfopen counter, so a
	 * cross-cycle double-decrement would underflow the unsigned counter to a
	 * huge value here -- which a fresh-server-per-iteration loop could never
	 * observe. A few cycles suffice; no magic large repeat count. */
	for (int cycle = 0; cycle < 3; cycle++) {
		struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
		int accepted_fd = -1, peer_fd = -1;
		make_socketpair(&accepted_fd, &peer_fd);

		forward_serve(
			&s, loop, accepted_fd,
			(const struct sockaddr *)&accepted_sa);
		T_CHECK(STUB.dialer_do_calls == cycle + 1);
		T_EXPECT_EQ(s.stats.num_halfopen, (size_t)1);

		fire_timeout(loop);

		T_EXPECT_EQ(s.stats.num_halfopen, (size_t)0);
		T_EXPECT_EQ(s.num_sessions, (size_t)0);

		T_CHECK(close(peer_fd) == 0);
	}

	ev_loop_destroy(loop);
}

#if WITH_RULESET
/* Tearing a context down while an async ruleset dispatch is still outstanding
 * must cancel the ruleset state (forward_ctx_stop STATE_PROCESS). */
T_DECLARE_CASE(forward_ruleset_async_timeout_cancels_ruleset)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
	struct dialreq base_req = { 0 };
	int accepted_fd = -1;
	int peer_fd = -1;

	stub_reset();
	STUB.hold_timeout = true;
	STUB.dialer_mode = STUB_DIALER_NONE;
	STUB.ruleset_mode = STUB_RULESET_ASYNC_OK;
	set_ipv4_addr(&base_req.addr, 80);

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	s.basereq = &base_req;
	s.ruleset = (struct ruleset *)&s;
	make_socketpair(&accepted_fd, &peer_fd);

	forward_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);
	test_drive_once(loop);
	T_CHECK(STUB.ruleset_pending_cb != NULL);

	/* Fire only after the async dispatch has become observable. */
	T_CHECK(STUB.ruleset_route_calls == 1);
	T_CHECK(s.stats.num_halfopen == 1);
	fire_timeout(loop);

	T_EXPECT_EQ(STUB.ruleset_cancel_calls, 1);
	T_EXPECT_EQ(STUB.dialer_do_calls, 0);
	T_EXPECT_EQ(s.stats.num_reject_timeout, (uint_least64_t)1);
	T_EXPECT_EQ(s.stats.num_halfopen, (size_t)0);
	T_EXPECT_EQ(s.num_sessions, (size_t)0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* The opposite teardown window: the ruleset completed in this same loop sweep,
 * so w_finish is pending with a delivered dialreq that ruleset_cb has not taken
 * ownership of yet. forward_ctx_stop must drop that event, releasing the
 * request and keeping it from firing into the freed context. */
T_DECLARE_CASE(forward_ruleset_completed_teardown_cancels_request)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
	struct dialreq base_req = { 0 };
	int accepted_fd = -1;
	int peer_fd = -1;

	stub_reset();
	STUB.dialer_mode = STUB_DIALER_NONE;
	STUB.ruleset_mode = STUB_RULESET_ASYNC_OK;
	set_ipv4_addr(&base_req.addr, 80);

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	s.basereq = &base_req;
	s.ruleset = (struct ruleset *)&s;
	make_socketpair(&accepted_fd, &peer_fd);

	forward_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);
	test_drive_once(loop);
	T_CHECK(STUB.ruleset_pending_cb != NULL);

	/* complete the request, but leave the event for the next loop sweep --
	 * which the teardown below preempts */
	struct ruleset_callback *restrict cb = deliver_pending_ruleset(loop);
	T_CHECK(ev_is_pending(&cb->w_finish));

	T_EXPECT_EQ(gc_finalizeall(), (size_t)1);

	/* the cleared event must not reach the freed context */
	test_drive_once(loop);
	/* the delivered request was released, and by ruleset_request_cancel
	 * alone: a completed operation is already detached from ruleset_cancel */
	T_EXPECT_EQ(STUB.dialreq_free_calls, 1);
	T_EXPECT_EQ(STUB.ruleset_cancel_calls, 0);
	T_EXPECT_EQ(STUB.dialer_do_calls, 0);
	T_EXPECT_EQ(s.stats.num_halfopen, (size_t)0);
	T_EXPECT_EQ(s.num_sessions, (size_t)0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}
#endif /* WITH_RULESET */

#if WITH_TPROXY && WITH_RULESET
/* tproxy: getsockname() → ruleset_route() for IPv4. */
T_DECLARE_CASE(tproxy_ruleset_route_ipv4)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
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
	test_drive_once(loop);

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

/* SIGHUP may clear s->ruleset between tproxy_serve and tproxy_process_cb. The
 * connection is then served as the reloaded no-ruleset configuration serves a
 * new one: dialed directly to its original destination, not rejected. */
T_DECLARE_CASE(tproxy_ruleset_null_after_sighup)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
	int accepted_fd = -1;

	stub_reset();
	STUB.dialaddr_set_ok = true;
	STUB.dialer_mode = STUB_DIALER_FAIL;

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

	/* the socket destination was dialed directly, not rejected by policy */
	T_EXPECT_EQ(STUB.ruleset_route_calls, 0);
	T_EXPECT_EQ(STUB.dialaddr_set_calls, 1);
	T_EXPECT_EQ(STUB.dialer_do_calls, 1);
	T_EXPECT_EQ(STUB.dialreq_free_calls, 1);
	T_EXPECT_EQ(s.stats.num_reject_ruleset, (uint_least64_t)0);
	T_EXPECT_EQ(s.stats.num_reject_upstream, (uint_least64_t)1);
	T_EXPECT_EQ(s.stats.num_halfopen, (size_t)0);
	T_EXPECT_EQ(s.num_sessions, (size_t)0);

	ev_loop_destroy(loop);
}

/* tproxy_process_cb's default: branch: an accepted fd whose getsockname family
 * is neither AF_INET nor AF_INET6 (here AF_UNIX) is rejected without dialing. */
T_DECLARE_CASE(tproxy_unsupported_af_rejects)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
	int accepted_fd = -1;
	int peer_fd = -1;

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	/* an AF_UNIX socket: getsockname reports AF_UNIX */
	make_socketpair(&accepted_fd, &peer_fd);
	s.ruleset = (struct ruleset *)&s;

	tproxy_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);
	ev_run(loop, EVRUN_NOWAIT);

	T_EXPECT_EQ(STUB.dialer_do_calls, 0);
	T_EXPECT_EQ(STUB.ruleset_route_calls, 0);
	T_EXPECT_EQ(s.stats.num_halfopen, (size_t)0);
	T_EXPECT_EQ(s.num_sessions, (size_t)0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* tproxy_getdest's failure branch: getsockname fails on a non-socket accepted
 * fd (a pipe end, ENOTSOCK), so the connection is rejected without dialing. */
T_DECLARE_CASE(tproxy_getdest_failure_rejects)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
	int pipefd[2] = { -1, -1 };

	stub_reset();
	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	T_CHECK(pipe(pipefd) == 0);
	s.ruleset = (struct ruleset *)&s;

	/* the read end is handed in as the accepted fd; getsockname will fail */
	tproxy_serve(
		&s, loop, pipefd[0], (const struct sockaddr *)&accepted_sa);
	ev_run(loop, EVRUN_NOWAIT);

	T_EXPECT_EQ(STUB.dialer_do_calls, 0);
	T_EXPECT_EQ(s.stats.num_halfopen, (size_t)0);
	T_EXPECT_EQ(s.num_sessions, (size_t)0);

	T_CHECK(close(pipefd[1]) == 0);
	ev_loop_destroy(loop);
}
#endif /* WITH_TPROXY && WITH_RULESET */

#if WITH_TPROXY
T_DECLARE_CASE(tproxy_dialer_fail_uses_socket_destination)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
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
	/* the counter this path uniquely updates */
	T_EXPECT_EQ(s.stats.num_reject_upstream, (uint_least64_t)1);
	T_EXPECT_EQ(s.num_sessions, 0);

	ev_loop_destroy(loop);
}

/* No-ruleset tproxy path where tproxy_makereq() fails (dialaddr_set rejects
 * the destination): the req == NULL cleanup branch must unwind cleanly. */
T_DECLARE_CASE(tproxy_makereq_failure_cleans_up)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
	int accepted_fd = -1;

	stub_reset();
	STUB.dialreq_available = true;
	STUB.dialaddr_set_ok = false;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	accepted_fd = make_bound_ipv4_socket();

	tproxy_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);

	T_EXPECT_EQ(STUB.dialaddr_set_calls, 1);
	T_EXPECT_EQ(STUB.dialer_do_calls, 0);
	T_EXPECT_EQ(s.stats.num_request, 1);
	T_EXPECT_EQ(s.stats.num_success, 0);
	T_EXPECT_EQ(s.stats.num_halfopen, 0);
	T_EXPECT_EQ(s.num_sessions, 0);

	ev_loop_destroy(loop);
}

/* No-ruleset tproxy path where tproxy_makereq() cannot allocate the request:
 * the connection is dropped before dialaddr_set or any dial, and the accepted
 * fd is closed. */
T_DECLARE_CASE(tproxy_makereq_oom_closes_accepted)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	struct sockaddr_in accepted_sa = { .sin_family = AF_INET };
	int accepted_fd = -1;

	stub_reset();
	STUB.dialreq_available = false;
	STUB.dialaddr_set_ok = true;

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);
	accepted_fd = make_bound_ipv4_socket();

	tproxy_serve(
		&s, loop, accepted_fd, (const struct sockaddr *)&accepted_sa);

	T_EXPECT_EQ(STUB.dialaddr_set_calls, 0);
	T_EXPECT_EQ(STUB.dialer_do_calls, 0);
	T_EXPECT_EQ(STUB.dialreq_free_calls, 0);
	T_EXPECT_EQ(s.stats.num_request, 1);
	T_EXPECT_EQ(s.stats.num_success, 0);
	T_EXPECT_EQ(s.stats.num_halfopen, 0);
	T_EXPECT_EQ(s.num_sessions, 0);
	/* nothing opened a descriptor since, so a closed fd is still EBADF */
	errno = 0;
	T_EXPECT_EQ(fcntl(accepted_fd, F_GETFD), -1);
	T_EXPECT_EQ(errno, EBADF);

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
	T_CASE(forward_close_log_omits_handed_off_fd),
	T_CASE(forward_commit_xfer_serve_failure_recovers),
	T_CASE(forward_direct_dialreq_oom_closes_accepted),
	T_CASE(forward_num_halfopen_no_underflow),
#if WITH_RULESET
	T_CASE(forward_ruleset_async_timeout_cancels_ruleset),
	T_CASE(forward_ruleset_completed_teardown_cancels_request),
	T_CASE(forward_ruleset_forward_hook_commits),
	T_CASE(forward_ruleset_async_then_dialer_fail),
	T_CASE(forward_ruleset_route_ipv4),
	T_CASE(forward_ruleset_route_ipv6),
	T_CASE(forward_ruleset_reject),
	T_CASE(forward_ruleset_sync_dispatch_fail_counts_reject),
	T_CASE(forward_ruleset_null_after_sighup),
#endif /* WITH_RULESET */
#if WITH_TPROXY
	T_CASE(tproxy_dialer_fail_uses_socket_destination),
	T_CASE(tproxy_makereq_failure_cleans_up),
	T_CASE(tproxy_makereq_oom_closes_accepted),
#endif
#if WITH_TPROXY && WITH_RULESET
	T_CASE(tproxy_ruleset_route_ipv4),
	T_CASE(tproxy_ruleset_null_after_sighup),
	T_CASE(tproxy_unsupported_af_rejects),
	T_CASE(tproxy_getdest_failure_rejects),
#endif
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	const int ret = testing_main(argc, argv, suite);
	stub_reset();
	return ret;
}
