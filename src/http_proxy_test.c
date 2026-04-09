/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http_proxy.h"

#include "conf.h"
#include "dialer.h"
#include "proto/http.h"
#include "ruleset.h"
#include "server.h"
#include "transfer.h"
#include "util.h"

#include "os/socket.h"
#include "utils/testing.h"

#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * These tests focus on HTTP parser/proxy request handling in http_proxy.c.
 * Dialer, transfer and ruleset are stubbed so the tests can isolate protocol
 * parsing and error response paths.
 */

/**
 * Test-only definition of struct globals (removed from util.h during refactoring).
 * Used to stub G.conf and G.ruleset for test initialization.
 */
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
	.bidir_timeout = false,
	.conn_cache = false,
};

static const ev_tstamp TEST_WAIT_SHORT_SEC = 0.064;
static const ev_tstamp TEST_WAIT_RECV_SEC = 0.256;
static const ev_tstamp TEST_WAIT_TIMEOUT_SEC = 1.0;

const char *proxy_protocol_str[PROTO_MAX] = {
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
	bool transfer_auto_finish;
	bool ruleset_resolve_ok;
	bool ruleset_reply_with_req;
	bool ruleset_finish_now;
	bool ruleset_state_nonnull;
	struct ev_loop *ruleset_loop;
	struct ruleset_state *ruleset_state_ptr;
	int_least32_t ruleset_cancel_calls;
	int_least32_t dialer_cancel_calls;
	int conn_cache_fd;
	int_least32_t conn_cache_get_calls;
	int_least32_t conn_cache_put_calls;
};

static struct stub_state S = {
	.dialreq_new_ok = false,
	.dialaddr_parse_ok = false,
	.dialer_invoke_now = true,
	.dialer_result_fd = -1,
	.dialer_err = DIALER_ERR_CONNECT,
	.dialer_syserr = ECONNREFUSED,
	.transfer_auto_finish = true,
	.ruleset_resolve_ok = false,
	.ruleset_reply_with_req = false,
	.ruleset_finish_now = false,
	.ruleset_state_nonnull = false,
	.ruleset_loop = NULL,
	.ruleset_state_ptr = NULL,
	.ruleset_cancel_calls = 0,
	.dialer_cancel_calls = 0,
	.conn_cache_fd = -1,
	.conn_cache_get_calls = 0,
	.conn_cache_put_calls = 0,
};

static int_least32_t ruleset_state_token = 0;
static struct dialreq *dialreq_allocations[32];
static size_t num_dialreq_allocations = 0;

static void reset_dialreq_allocations(void)
{
	num_dialreq_allocations = 0;
	memset(dialreq_allocations, 0, sizeof(dialreq_allocations));
}

static void track_dialreq_allocation(struct dialreq *restrict req)
{
	T_CHECK(num_dialreq_allocations <
		(sizeof(dialreq_allocations) / sizeof(dialreq_allocations[0])));
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

/**
 * Initialize server struct for testing.
 * Sets minimal required fields so production code can access conf/resolver/etc.
 */
static void test_server_init(struct server *restrict s)
{
	s->conf = &test_conf;
	s->resolver = NULL;
	s->ruleset = G.ruleset;
	s->basereq = NULL;
}

static void reset_stub_state(void)
{
	if (S.conn_cache_fd != -1) {
		close(S.conn_cache_fd);
	}
	S.dialreq_new_ok = false;
	S.dialaddr_parse_ok = false;
	S.dialer_invoke_now = true;
	S.dialer_result_fd = -1;
	S.dialer_err = DIALER_ERR_CONNECT;
	S.dialer_syserr = ECONNREFUSED;
	S.dialreq_free_calls = 0;
	S.dialreq_invalid_free_calls = 0;
	S.transfer_auto_finish = true;
	S.ruleset_resolve_ok = false;
	S.ruleset_reply_with_req = false;
	S.ruleset_finish_now = false;
	S.ruleset_state_nonnull = false;
	S.ruleset_loop = NULL;
	S.ruleset_state_ptr = NULL;
	S.ruleset_cancel_calls = 0;
	S.dialer_cancel_calls = 0;
	S.conn_cache_fd = -1;
	S.conn_cache_get_calls = 0;
	S.conn_cache_put_calls = 0;
	reset_dialreq_allocations();
	test_conf.timeout = 1.0;
	test_conf.auth_required = false;
	test_conf.bidir_timeout = false;
	test_conf.conn_cache = false;
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
	d->req = req;
	(void)loop;
	(void)conf;
	(void)resolver;
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

void transfer_init(
	struct transfer *restrict t, const struct transfer_state_cb *callback,
	const int src_fd, const int dst_fd, uintmax_t *byt_transferred,
	const bool is_uplink, const bool use_splice)
{
	memset(t, 0xA5, sizeof(*t));
	t->state = XFER_INIT;
	t->src_fd = src_fd;
	t->dst_fd = dst_fd;
	t->state_cb = *callback;
	t->byt_transferred = byt_transferred;
	(void)is_uplink;
	(void)use_splice;
}

void transfer_start(struct ev_loop *restrict loop, struct transfer *restrict t)
{
	t->state = XFER_CONNECTED;
	t->state_cb.func(loop, t->state_cb.data);
	if (!S.transfer_auto_finish) {
		return;
	}
	t->state = XFER_FINISHED;
	t->state_cb.func(loop, t->state_cb.data);
}

void transfer_stop(struct ev_loop *loop, struct transfer *restrict t)
{
	(void)loop;
	t->state = XFER_FINISHED;
}

void ruleset_cancel(struct ev_loop *loop, struct ruleset_state *restrict state)
{
	(void)loop;
	(void)state;
	S.ruleset_cancel_calls++;
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

void conn_cache_put(
	struct ev_loop *loop, const int fd,
	const struct dialreq *restrict dialreq)
{
	(void)loop;
	(void)dialreq;
	S.conn_cache_put_calls++;
	if (S.conn_cache_fd != -1 && S.conn_cache_fd != fd) {
		close(S.conn_cache_fd);
	}
	S.conn_cache_fd = fd;
}

int conn_cache_get(struct ev_loop *loop, const struct dialreq *restrict req)
{
	(void)loop;
	(void)req;
	S.conn_cache_get_calls++;
	if (S.conn_cache_fd == -1) {
		return -1;
	}
	const int fd = S.conn_cache_fd;
	S.conn_cache_fd = -1;
	return fd;
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

static void drive_loop(struct ev_loop *loop)
{
	test_run_for(loop, TEST_WAIT_SHORT_SEC);
}

static ssize_t recv_all_with_timeout(
	struct ev_loop *loop, const int fd, unsigned char *restrict buf,
	const size_t cap)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;
	size_t off = 0;

	ev_timer_init(&w_timeout, test_watchdog_cb, TEST_WAIT_RECV_SEC, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired && off < cap) {
		const ssize_t n = recv(fd, buf + off, cap - off, MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				ev_run(loop, EVRUN_ONCE);
				continue;
			}
			ev_timer_stop(loop, &w_timeout);
			return -1;
		}
		if (n == 0) {
			break;
		}
		off += (size_t)n;
	}
	ev_timer_stop(loop, &w_timeout);
	return (ssize_t)off;
}

static void serve_payload(
	struct ev_loop *loop, struct server *restrict s,
	const char *restrict req, int *restrict peer_fd)
{
	int sv[2] = { -1, -1 };
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
	};

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(socket_set_nonblock(sv[0]));
	T_CHECK(socket_set_nonblock(sv[1]));
	S.ruleset_loop = loop;
	http_proxy_serve(s, loop, sv[0], (const struct sockaddr *)&sa);
	T_CHECK(write_all(sv[1], req, strlen(req)) == 0);

	*peer_fd = sv[1];
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

struct collect_body_ctx {
	unsigned char *buf;
	size_t cap;
	size_t len;
};

static bool collect_body_cb(
	void *restrict data, const unsigned char *restrict chunk,
	const size_t len)
{
	struct collect_body_ctx *restrict ctx = data;
	if (ctx->cap - ctx->len < len) {
		return false;
	}
	memcpy(ctx->buf + ctx->len, chunk, len);
	ctx->len += len;
	return true;
}

static bool decode_chunked_response_body(
	const unsigned char *restrict rsp, const size_t rsp_len,
	unsigned char *restrict out, const size_t out_cap,
	size_t *restrict out_len)
{
	const unsigned char *hdr_end =
		memmem(rsp, rsp_len, "\r\n\r\n", CONSTSTRLEN("\r\n\r\n"));
	if (hdr_end == NULL) {
		return false;
	}
	const unsigned char *body = hdr_end + CONSTSTRLEN("\r\n\r\n");
	const size_t body_len = rsp_len - (size_t)(body - rsp);

	struct collect_body_ctx ctx = {
		.buf = out,
		.cap = out_cap,
		.len = 0,
	};
	const struct http_body_data_cb cb = {
		.func = collect_body_cb,
		.ctx = &ctx,
	};
	struct http_body d;
	http_body_init(&d, HTTP_BODY_CHUNKED, 0);
	if (!http_body_consume(&d, body, body_len, cb)) {
		return false;
	}
	if (!http_body_finish(&d)) {
		return false;
	}
	*out_len = ctx.len;
	return true;
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
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
	};

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(socket_set_nonblock(sv[0]));
	T_CHECK(socket_set_nonblock(sv[1]));
	S.ruleset_loop = loop;
	http_proxy_serve(s, loop, sv[0], (const struct sockaddr *)&sa);
	*peer_fd = sv[1];
}

static bool assert_response_status(
	struct ev_loop *loop, const int peer_fd, const char *restrict status)
{
	unsigned char rsp[1024];
	const ssize_t n =
		recv_all_with_timeout(loop, peer_fd, rsp, sizeof(rsp));
	if (n <= 0) {
		return false;
	}
	return has_http_status(rsp, (size_t)n, status);
}

static void make_fd_pair(int *restrict a, int *restrict b)
{
	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	T_CHECK(socket_set_nonblock(sv[0]));
	T_CHECK(socket_set_nonblock(sv[1]));
	*a = sv[0];
	*b = sv[1];
}

T_DECLARE_CASE(plain_http_origin_form_no_dialreq_returns_500)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* origin-form URL; Host header used as fallback target */
	const char req[] = "GET / HTTP/1.1\r\nHost: example\r\n\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);

	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[1024];
		const ssize_t n =
			recv_all_with_timeout(loop, peer_fd, rsp, sizeof(rsp));
		T_EXPECT(n > 0);
		/* dialreq_new_ok=false -> make_dialreq returns NULL -> 500 */
		T_EXPECT(has_http_status(rsp, (size_t)n, "500"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

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

	/* dialreq_new_ok=false -> make_dialreq returns NULL -> 500 */
	T_EXPECT(assert_response_status(loop, peer_fd, "500"));

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
	test_server_init(&s);

	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[1024];
		const ssize_t n =
			recv_all_with_timeout(loop, peer_fd, rsp, sizeof(rsp));
		T_EXPECT(n > 0);
		T_EXPECT(has_http_status(rsp, (size_t)n, "400"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(invalid_te_returns_400)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "TE: gzip\r\n"
			   "\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);

	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[1024];
		const ssize_t n =
			recv_all_with_timeout(loop, peer_fd, rsp, sizeof(rsp));
		T_EXPECT(n > 0);
		T_EXPECT(has_http_status(rsp, (size_t)n, "400"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(connect_with_invalid_target_returns_500)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	const char req[] = "CONNECT not-a-valid-hostport HTTP/1.1\r\n"
			   "Host: ignored\r\n"
			   "\r\n";

	reset_stub_state();
	init_server(&loop, &s);

	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[1024];
		const ssize_t n =
			recv_all_with_timeout(loop, peer_fd, rsp, sizeof(rsp));
		T_EXPECT(n > 0);
		T_EXPECT(has_http_status(rsp, (size_t)n, "500"));
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
	drive_loop(loop);

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
			recv_all_with_timeout(loop, peer_fd, rsp, sizeof(rsp));
		T_EXPECT(n > 0);
		T_EXPECT(
			memmem(rsp, (size_t)n, "200 Connection established",
			       26) != NULL);
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
	S.transfer_auto_finish = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		const ssize_t n =
			recv_all_with_timeout(loop, peer_fd, rsp, sizeof(rsp));
		T_EXPECT(n > 0);
		T_EXPECT(
			memmem(rsp, (size_t)n, "200 Connection established",
			       26) != NULL);
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
	drive_loop(loop);

	T_EXPECT(assert_response_status(loop, peer_fd, "502"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(authorization_header_without_space_returns_400)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "Authorization: BasicOnly\r\n"
			   "\r\n";

	reset_stub_state();
	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	T_EXPECT(assert_response_status(loop, peer_fd, "400"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_auth_required_without_basic_credentials_returns_407)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int_least32_t ruleset_stub = 0;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "Proxy-Authorization: Bearer token\r\n"
			   "\r\n";

	reset_stub_state();
	test_conf.auth_required = true;
	G.ruleset = (struct ruleset *)&ruleset_stub;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	T_EXPECT(assert_response_status(loop, peer_fd, "407"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_auth_required_with_invalid_basic_returns_407)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int_least32_t ruleset_stub = 0;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "Proxy-Authorization: Basic dXNlcm9ubHk=\r\n"
			   "\r\n";

	reset_stub_state();
	test_conf.auth_required = true;
	G.ruleset = (struct ruleset *)&ruleset_stub;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	T_EXPECT(assert_response_status(loop, peer_fd, "407"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_resolve_failure_returns_500)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int_least32_t ruleset_stub = 0;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
			   "\r\n";

	reset_stub_state();
	test_conf.auth_required = true;
	G.ruleset = (struct ruleset *)&ruleset_stub;
	S.ruleset_resolve_ok = false;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	T_EXPECT(assert_response_status(loop, peer_fd, "500"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_finish_without_req_returns_403)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int_least32_t ruleset_stub = 0;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "\r\n";

	reset_stub_state();
	G.ruleset = (struct ruleset *)&ruleset_stub;
	S.ruleset_resolve_ok = true;
	S.ruleset_reply_with_req = false;
	S.ruleset_finish_now = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	T_EXPECT(assert_response_status(loop, peer_fd, "403"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_finish_with_req_and_dialer_error_returns_502)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int_least32_t ruleset_stub = 0;
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
	drive_loop(loop);

	T_EXPECT(assert_response_status(loop, peer_fd, "502"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(timeout_in_process_state_cancels_ruleset)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int_least32_t ruleset_stub = 0;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "\r\n";

	reset_stub_state();
	test_conf.timeout = 0.01;
	G.ruleset = (struct ruleset *)&ruleset_stub;
	S.ruleset_resolve_ok = true;
	S.ruleset_reply_with_req = true;
	S.ruleset_finish_now = false;
	S.ruleset_state_nonnull = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	test_run_for(loop, TEST_WAIT_TIMEOUT_SEC);

	T_EXPECT(S.ruleset_cancel_calls > 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(timeout_in_connect_state_cancels_dialer)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	const char req[] = "CONNECT example.com:80 HTTP/1.1\r\n"
			   "\r\n";

	reset_stub_state();
	test_conf.timeout = 0.01;
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	S.dialer_invoke_now = false;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	test_run_for(loop, TEST_WAIT_TIMEOUT_SEC);

	T_EXPECT(S.dialer_cancel_calls > 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(plain_http_absolute_url_no_dialreq_returns_500)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = false;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	T_EXPECT(assert_response_status(loop, peer_fd, "500"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(plain_http_absolute_url_no_host_returns_400)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	/* non-http:// URL with no Host header -> 400 */
	const char req[] = "GET /path HTTP/1.1\r\n\r\n";

	reset_stub_state();

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	T_EXPECT(assert_response_status(loop, peer_fd, "400"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(plain_http_absolute_url_dialer_error_returns_502)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	S.dialer_result_fd = -1;
	S.dialer_err = DIALER_ERR_CONNECT;
	S.dialer_syserr = ECONNREFUSED;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	T_EXPECT(assert_response_status(loop, peer_fd, "502"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(plain_http_absolute_url_established)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;
	S.transfer_auto_finish = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	/* The request is forwarded; the connection should close after transfer */
	{
		unsigned char buf[4096];
		const ssize_t n = recv_all_with_timeout(
			loop, upstream_fd, buf, sizeof(buf));
		/* upstream receives the forwarded request */
		T_EXPECT(n > 0);
		T_EXPECT(memmem(buf, (size_t)n, "GET / HTTP/1.1", 14) != NULL);
		T_EXPECT(
			memmem(buf, (size_t)n, "Connection: close", 17) !=
			NULL);
	}

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(plain_http_post_with_body_forwarded)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	const char req[] = "POST http://example.com/submit HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "Content-Type: application/x-www-form-urlencoded\r\n"
			   "Content-Length: 7\r\n"
			   "\r\n"
			   "a=b&c=d";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;
	S.transfer_auto_finish = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char buf[4096];
		const ssize_t n = recv_all_with_timeout(
			loop, upstream_fd, buf, sizeof(buf));
		T_EXPECT(n > 0);
		T_EXPECT(
			memmem(buf, (size_t)n, "POST /submit HTTP/1.1", 21) !=
			NULL);
		T_EXPECT(
			memmem(buf, (size_t)n, "Content-Length: 7", 17) !=
			NULL);
		/* body forwarded */
		T_EXPECT(memmem(buf, (size_t)n, "a=b&c=d", 7) != NULL);
	}

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* Verify that the HTTP version from the client request is preserved in the
 * forwarded request line, not hard-coded to HTTP/1.1. */
T_DECLARE_CASE(plain_http_version_preserved_in_forwarded_request)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	const char req[] = "GET http://example.com/page HTTP/1.0\r\n"
			   "Host: example.com\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;
	S.transfer_auto_finish = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char buf[4096];
		const ssize_t n = recv_all_with_timeout(
			loop, upstream_fd, buf, sizeof(buf));
		T_EXPECT(n > 0);
		T_EXPECT(
			memmem(buf, (size_t)n, "GET /page HTTP/1.0", 18) !=
			NULL);
	}

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* For proxy_pass requests, Transfer-Encoding: chunked must be forwarded so
 * the upstream knows how to read the request body. */
T_DECLARE_CASE(plain_http_te_chunked_forwarded_to_upstream)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	const char req[] = "POST http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;
	S.transfer_auto_finish = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char buf[4096];
		const ssize_t n = recv_all_with_timeout(
			loop, upstream_fd, buf, sizeof(buf));
		T_EXPECT(n > 0);
		T_EXPECT(
			memmem(buf, (size_t)n, "Transfer-Encoding: chunked",
			       26) != NULL);
	}

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* RFC 7230 §6.1: headers listed in the Connection field are hop-by-hop and
 * must not be forwarded, even if they are not in the static list. */
T_DECLARE_CASE(plain_http_dynamic_hop_by_hop_not_forwarded)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "Connection: X-Hop\r\n"
			   "X-Hop: secret-value\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;
	S.transfer_auto_finish = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char buf[4096];
		const ssize_t n = recv_all_with_timeout(
			loop, upstream_fd, buf, sizeof(buf));
		T_EXPECT(n > 0);
		/* dynamic hop-by-hop header must not reach upstream */
		T_EXPECT(memmem(buf, (size_t)n, "X-Hop", 5) == NULL);
		/* end-to-end headers must still be forwarded */
		T_EXPECT(
			memmem(buf, (size_t)n, "Host: example.com", 17) !=
			NULL);
	}

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* Proxy-Authorization is consumed by the proxy and must not be leaked to the
 * upstream server in the forwarded plain HTTP request. */
T_DECLARE_CASE(plain_http_proxy_authorization_not_forwarded)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	/* dXNlcjpwYXNz = base64("user:pass") */
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;
	S.transfer_auto_finish = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char buf[4096];
		const ssize_t n = recv_all_with_timeout(
			loop, upstream_fd, buf, sizeof(buf));
		T_EXPECT(n > 0);
		T_EXPECT(
			memmem(buf, (size_t)n, "Proxy-Authorization", 19) ==
			NULL);
	}

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(plain_http_response_content_length_preserved)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	unsigned char buf[4096];
	unsigned char rsp[4096];
	const char req[] = "GET http://example.com/data HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "\r\n";
	const char upstream_rsp[] = "HTTP/1.1 200 OK\r\n"
				    "Content-Length: 5\r\n"
				    "\r\n"
				    "hello";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;
	test_conf.conn_cache = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		const ssize_t n = recv_all_with_timeout(
			loop, upstream_fd, buf, sizeof(buf));
		T_EXPECT(n > 0);
		T_EXPECT(
			memmem(buf, (size_t)n, "GET /data HTTP/1.1", 18) !=
			NULL);
	}
	T_CHECK(write_all(upstream_fd, upstream_rsp, strlen(upstream_rsp)) ==
		0);
	drive_loop(loop);

	{
		const ssize_t n =
			recv_all_with_timeout(loop, peer_fd, rsp, sizeof(rsp));
		T_EXPECT(n > 0);
		T_EXPECT(
			memmem(rsp, (size_t)n, "Content-Length: 5", 17) !=
			NULL);
		T_EXPECT(
			memmem(rsp, (size_t)n, "Transfer-Encoding", 17) ==
			NULL);
		T_EXPECT(memmem(rsp, (size_t)n, "hello", 5) != NULL);
	}
	T_EXPECT_EQ(S.conn_cache_put_calls, 1);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	reset_stub_state();
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(plain_http_response_conn_close_large_body_complete)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	unsigned char reqbuf[4096];
	const char req[] = "GET http://example.com/data HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "\r\n";
	const size_t body_len = 32768;
	unsigned char *body = NULL;
	unsigned char *rsp = NULL;
	char hdr[256];

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;
	test_conf.conn_cache = true;

	body = malloc(body_len);
	T_CHECK(body != NULL);
	for (size_t i = 0; i < body_len; i++) {
		body[i] = (unsigned char)('a' + (char)(i % 26));
	}
	rsp = malloc(body_len + sizeof(hdr) + 512u);
	T_CHECK(rsp != NULL);

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		const ssize_t n = recv_all_with_timeout(
			loop, upstream_fd, reqbuf, sizeof(reqbuf));
		T_EXPECT(n > 0);
		T_EXPECT(
			memmem(reqbuf, (size_t)n, "GET /data HTTP/1.1", 18) !=
			NULL);
	}

	{
		const int n = snprintf(
			hdr, sizeof(hdr),
			"HTTP/1.1 200 OK\r\n"
			"Connection: close\r\n"
			"Content-Length: %zu\r\n"
			"\r\n",
			body_len);
		T_CHECK(n > 0 && (size_t)n < sizeof(hdr));
	}
	T_CHECK(write_all(upstream_fd, hdr, strlen(hdr)) == 0);
	T_CHECK(write_all(upstream_fd, body, body_len) == 0);
	drive_loop(loop);

	{
		const ssize_t n = recv_all_with_timeout(
			loop, peer_fd, rsp, body_len + sizeof(hdr) + 512u);
		const unsigned char *body_start;
		const unsigned char *hdr_end;
		size_t body_recv;
		T_EXPECT(n > 0);
		hdr_end = memmem(rsp, (size_t)n, "\r\n\r\n", 4);
		T_EXPECT(hdr_end != NULL);
		T_EXPECT(
			memmem(rsp, (size_t)n, "Content-Length: ", 16) != NULL);
		body_start = hdr_end + 4;
		body_recv = (size_t)n - (size_t)(body_start - rsp);
		T_EXPECT_EQ(body_recv, body_len);
		T_EXPECT(memcmp(body_start, body, body_len) == 0);
	}

	free(rsp);
	free(body);
	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	reset_stub_state();
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(plain_http_response_chunked_strips_content_length)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	unsigned char reqbuf[4096];
	unsigned char rsp[4096];
	const char req[] = "GET http://example.com/data HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "\r\n";
	const char upstream_rsp[] = "HTTP/1.1 200 OK\r\n"
				    "Transfer-Encoding: chunked\r\n"
				    "Content-Length: 1\r\n"
				    "\r\n"
				    "5\r\n"
				    "hello\r\n"
				    "0\r\n"
				    "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;
	test_conf.conn_cache = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		const ssize_t n = recv_all_with_timeout(
			loop, upstream_fd, reqbuf, sizeof(reqbuf));
		T_EXPECT(n > 0);
		T_EXPECT(
			memmem(reqbuf, (size_t)n, "GET /data HTTP/1.1", 18) !=
			NULL);
	}

	T_CHECK(write_all(upstream_fd, upstream_rsp, strlen(upstream_rsp)) ==
		0);
	drive_loop(loop);

	{
		const ssize_t n =
			recv_all_with_timeout(loop, peer_fd, rsp, sizeof(rsp));
		T_EXPECT(n > 0);
		T_EXPECT(
			memmem(rsp, (size_t)n, "Transfer-Encoding: chunked",
			       26) != NULL);
		T_EXPECT(memmem(rsp, (size_t)n, "Content-Length:", 15) == NULL);
		T_EXPECT(memmem(rsp, (size_t)n, "hello", 5) != NULL);
	}

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	reset_stub_state();
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(plain_http_response_eof_framed_large_body_complete)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	unsigned char reqbuf[4096];
	const char req[] = "GET http://example.com/stream HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "\r\n";
	const char upstream_hdr[] = "HTTP/1.1 200 OK\r\n"
				    "Connection: close\r\n"
				    "\r\n";
	const size_t body_len = 12288;
	unsigned char body[body_len];
	unsigned char rsp[body_len + 16384u];
	unsigned char decoded[body_len];

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;
	test_conf.conn_cache = true;

	for (size_t i = 0; i < body_len; i++) {
		body[i] = (unsigned char)('a' + (char)(i % 26));
	}
	body[0] = 'B';
	body[1] = 'E';
	body[2] = 'G';
	body[3] = 'I';
	body[4] = 'N';
	body[body_len - 5] = 'E';
	body[body_len - 4] = 'N';
	body[body_len - 3] = 'D';
	body[body_len - 2] = '!';
	body[body_len - 1] = '!';
	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		const ssize_t n = recv_all_with_timeout(
			loop, upstream_fd, reqbuf, sizeof(reqbuf));
		T_EXPECT(n > 0);
		T_EXPECT(
			memmem(reqbuf, (size_t)n, "GET /stream HTTP/1.1", 20) !=
			NULL);
	}

	T_CHECK(write_all(upstream_fd, upstream_hdr, strlen(upstream_hdr)) ==
		0);
	T_CHECK(write_all(upstream_fd, body, body_len) == 0);
	T_CHECK(shutdown(upstream_fd, SHUT_WR) == 0);
	for (int i = 0; i < 3; i++) {
		test_run_for(loop, TEST_WAIT_RECV_SEC);
	}

	{
		ssize_t n = 0;
		size_t off = 0;
		size_t decoded_len = 0;
		for (int i = 0; i < 12 && off < body_len + 16384u; i++) {
			const ssize_t got = recv_all_with_timeout(
				loop, peer_fd, rsp + off,
				(body_len + 16384u) - off);
			T_EXPECT(got >= 0);
			off += (size_t)got;
			if (got == 0) {
				break;
			}
		}
		n = (ssize_t)off;
		T_EXPECT(n > 0);
		T_EXPECT(
			memmem(rsp, (size_t)n, "Transfer-Encoding: chunked",
			       26) != NULL);
		T_EXPECT(memmem(rsp, (size_t)n, "Content-Length:", 15) == NULL);
		T_EXPECT(decode_chunked_response_body(
			rsp, (size_t)n, decoded, sizeof(decoded),
			&decoded_len));
		T_EXPECT_EQ(decoded_len, body_len);
		T_EXPECT(memcmp(decoded, body, body_len) == 0);
	}

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	reset_stub_state();
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(plain_http_reuses_cached_upstream_connection)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd1 = -1;
	int peer_fd2 = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	unsigned char buf[4096];
	unsigned char rsp[4096];
	const char req1[] = "GET http://example.com/one HTTP/1.1\r\n"
			    "Host: example.com\r\n"
			    "\r\n";
	const char req2[] = "GET http://example.com/two HTTP/1.1\r\n"
			    "Host: example.com\r\n"
			    "\r\n";
	const char rsp1[] = "HTTP/1.1 200 OK\r\n"
			    "Content-Length: 3\r\n"
			    "\r\n"
			    "one";
	const char rsp2[] = "HTTP/1.1 200 OK\r\n"
			    "Content-Length: 3\r\n"
			    "\r\n"
			    "two";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;
	test_conf.conn_cache = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req1, &peer_fd1);
	drive_loop(loop);
	{
		const ssize_t n = recv_all_with_timeout(
			loop, upstream_fd, buf, sizeof(buf));
		T_EXPECT(n > 0);
		T_EXPECT(memmem(buf, (size_t)n, "/one HTTP/1.1", 13) != NULL);
	}
	T_CHECK(write_all(upstream_fd, rsp1, strlen(rsp1)) == 0);
	drive_loop(loop);
	{
		const ssize_t n =
			recv_all_with_timeout(loop, peer_fd1, rsp, sizeof(rsp));
		T_EXPECT(n > 0);
		T_EXPECT(memmem(rsp, (size_t)n, "one", 3) != NULL);
	}
	T_CHECK(close(peer_fd1) == 0);

	S.dialer_result_fd = -1;
	serve_payload(loop, &s, req2, &peer_fd2);
	drive_loop(loop);
	{
		const ssize_t n = recv_all_with_timeout(
			loop, upstream_fd, buf, sizeof(buf));
		T_EXPECT(n > 0);
		T_EXPECT(memmem(buf, (size_t)n, "/two HTTP/1.1", 13) != NULL);
	}
	T_CHECK(write_all(upstream_fd, rsp2, strlen(rsp2)) == 0);
	drive_loop(loop);
	{
		const ssize_t n =
			recv_all_with_timeout(loop, peer_fd2, rsp, sizeof(rsp));
		T_EXPECT(n > 0);
		T_EXPECT(memmem(rsp, (size_t)n, "two", 3) != NULL);
	}
	T_EXPECT_EQ(S.conn_cache_get_calls, 2);
	T_EXPECT_EQ(S.conn_cache_put_calls, 2);

	T_CHECK(close(peer_fd2) == 0);
	T_CHECK(close(upstream_fd) == 0);
	reset_stub_state();
	ev_loop_destroy(loop);
}

/* A successful plain HTTP forward must count exactly one success, and
 * establish a bidirectional relay between client and upstream. */
T_DECLARE_CASE(plain_http_forward_success_counted_once)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "\r\n";

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;
	S.transfer_auto_finish = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	T_EXPECT(s.stats.num_success == 1);

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
	S.transfer_auto_finish = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	T_EXPECT(s.stats.num_success == 1);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

int main(void)
{
	T_DECLARE_CTX(t);
	reset_stub_state();
	T_RUN_CASE(t, plain_http_origin_form_no_dialreq_returns_500);
	T_RUN_CASE(t, split_request_is_parsed_incrementally);
	T_RUN_CASE(t, plain_http_absolute_url_no_dialreq_returns_500);
	T_RUN_CASE(t, plain_http_absolute_url_no_host_returns_400);
	T_RUN_CASE(t, plain_http_absolute_url_dialer_error_returns_502);
	T_RUN_CASE(t, plain_http_absolute_url_established);
	T_RUN_CASE(t, plain_http_post_with_body_forwarded);
	T_RUN_CASE(t, plain_http_version_preserved_in_forwarded_request);
	T_RUN_CASE(t, plain_http_te_chunked_forwarded_to_upstream);
	T_RUN_CASE(t, plain_http_dynamic_hop_by_hop_not_forwarded);
	T_RUN_CASE(t, plain_http_proxy_authorization_not_forwarded);
	T_RUN_CASE(t, plain_http_response_content_length_preserved);
	T_RUN_CASE(t, plain_http_response_conn_close_large_body_complete);
	T_RUN_CASE(t, plain_http_response_chunked_strips_content_length);
	T_RUN_CASE(t, plain_http_response_eof_framed_large_body_complete);
	T_RUN_CASE(t, plain_http_reuses_cached_upstream_connection);
	T_RUN_CASE(t, plain_http_forward_success_counted_once);
	T_RUN_CASE(t, malformed_proxy_authorization_returns_400);
	T_RUN_CASE(t, invalid_te_returns_400);
	T_RUN_CASE(t, connect_with_invalid_target_returns_500);
	T_RUN_CASE(t, valid_connect_dialer_error_returns_502);
	T_RUN_CASE(t, valid_connect_established_with_hijack);
	T_RUN_CASE(
		t, connect_hijack_finalize_does_not_touch_overwritten_dialreq);
	T_RUN_CASE(t, connect_with_transfer_encoding_chunked_is_accepted);
	T_RUN_CASE(t, connect_success_counted_once);
	T_RUN_CASE(t, authorization_header_without_space_returns_400);
	T_RUN_CASE(
		t, ruleset_auth_required_without_basic_credentials_returns_407);
	T_RUN_CASE(t, ruleset_auth_required_with_invalid_basic_returns_407);
	T_RUN_CASE(t, ruleset_resolve_failure_returns_500);
	T_RUN_CASE(t, ruleset_finish_without_req_returns_403);
	T_RUN_CASE(t, ruleset_finish_with_req_and_dialer_error_returns_502);
	T_RUN_CASE(t, timeout_in_process_state_cancels_ruleset);
	T_RUN_CASE(t, timeout_in_connect_state_cancels_dialer);

	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
