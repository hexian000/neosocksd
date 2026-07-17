/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for http_proxy.c; mocked: dialer, transfer, ruleset, server. */

#include "http_proxy.h"

#include "conf.h"
#include "dialer.h"
#include "ruleset/ruleset.h"
#include "server.h"
#include "transfer.h"
#include "util.h"

#include "meta/arraysize.h"
#include "os/socket.h"
#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

static const ev_tstamp TEST_WAIT_SHORT_SEC = 0.016;
static const ev_tstamp TEST_WAIT_RECV_SEC = 0.128;
/* Upper bound on how long ev_run() may sleep while a helper polls a socket
 * that is not registered with the event loop, so fragmented/delayed peer
 * writes (e.g. the MSYS2/Cygwin socket emulation) are observed promptly. */
static const ev_tstamp TEST_TICK_SEC = 0.002;
/* Consecutive idle polls (each ~TEST_TICK_SEC apart) with no new bytes that
 * mark the end of a received burst. */
#define TEST_RECV_QUIET_TICKS 6

static ev_tstamp test_timeout_wait_window(const ev_tstamp timeout_sec)
{
	ev_tstamp wait_sec = timeout_sec * 4.0;
	if (wait_sec < TEST_WAIT_SHORT_SEC) {
		wait_sec = TEST_WAIT_SHORT_SEC;
	}
	return wait_sec;
}

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

static bool
test_step_timed_out(struct ev_loop *loop, const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	ev_run(loop, EVRUN_ONCE);
	ev_timer_stop(loop, &w_timeout);
	return watchdog.fired;
}

static void drive_loop(struct ev_loop *loop)
{
	for (int_fast32_t i = 0; i < 16; i++) {
		if (test_step_timed_out(loop, TEST_WAIT_SHORT_SEC)) {
			break;
		}
	}
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
	T_CHECK(socket_set_cloexec(sv[0]));
	T_CHECK(socket_set_nonblock(sv[0]));
	T_CHECK(socket_set_cloexec(sv[1]));
	T_CHECK(socket_set_nonblock(sv[1]));
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
	T_CHECK(socket_set_cloexec(sv[0]));
	T_CHECK(socket_set_nonblock(sv[0]));
	T_CHECK(socket_set_cloexec(sv[1]));
	T_CHECK(socket_set_nonblock(sv[1]));
	S.ruleset_loop = loop;
	http_proxy_serve(s, loop, sv[0], (const struct sockaddr *)&sa);
	T_CHECK(write_all(sv[1], req, strlen(req)) == 0);

	*peer_fd = sv[1];
}

static void
test_tick_cb(struct ev_loop *loop, struct ev_timer *w, const int revents)
{
	/* No-op: this timer exists only to bound ev_run(EVRUN_ONCE) sleeps. */
	(void)loop;
	(void)w;
	(void)revents;
}

/* Receive at least min_bytes from fd, up to cap bytes.
 * Returns number of bytes received, or -1 on error.
 * Exits early if at least min_bytes received and no more data available. */
static ssize_t recv_at_least(
	struct ev_loop *loop, const int fd, unsigned char *restrict buf,
	const size_t cap, const size_t min_bytes)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout, w_tick;
	size_t off = 0;
	int_fast32_t idle = 0;

	ev_timer_init(&w_timeout, test_watchdog_cb, TEST_WAIT_RECV_SEC, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	ev_timer_init(&w_tick, test_tick_cb, TEST_TICK_SEC, TEST_TICK_SEC);
	ev_timer_start(loop, &w_tick);
	while (!watchdog.fired && off < cap) {
		const ssize_t n = recv(fd, buf + off, cap - off, MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* Once the minimum is met, allow a short quiet window
				 * for trailing fragments (the peer may split a reply
				 * across writes) before returning. */
				if (off >= min_bytes &&
				    ++idle >= TEST_RECV_QUIET_TICKS) {
					break;
				}
				ev_run(loop, EVRUN_ONCE);
				continue;
			}
			ev_timer_stop(loop, &w_tick);
			ev_timer_stop(loop, &w_timeout);
			return -1;
		}
		if (n == 0) {
			break;
		}
		off += (size_t)n;
		idle = 0;
	}
	ev_timer_stop(loop, &w_tick);
	ev_timer_stop(loop, &w_timeout);
	return (ssize_t)off;
}

/* Drive the loop and read from fd until EOF (or cap/timeout). */
static size_t recv_all(
	struct ev_loop *loop, const int fd, unsigned char *restrict buf,
	const size_t cap)
{
	size_t off = 0;
	for (int i = 0; i < 4096 && off < cap; i++) {
		const ssize_t n = recv(fd, buf + off, cap - off, 0);
		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n == 0) {
			break; /* EOF */
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			(void)test_step_timed_out(loop, TEST_WAIT_SHORT_SEC);
			continue;
		}
		break;
	}
	return off;
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
	T_CHECK(socket_set_cloexec(sv[0]));
	T_CHECK(socket_set_nonblock(sv[0]));
	T_CHECK(socket_set_cloexec(sv[1]));
	T_CHECK(socket_set_nonblock(sv[1]));
	*a = sv[0];
	*b = sv[1];
}

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - request-form handling, CONNECT tunneling and proxy behavior.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(plain_http_origin_form_returns_400)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* origin-form URL is not allowed; proxy requires absolute-form */
	const char req[] = "GET / HTTP/1.1\r\nHost: example\r\n\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
	test_server_init(&s);

	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[1024];
		const ssize_t n =
			recv_at_least(loop, peer_fd, rsp, sizeof(rsp), 17);
		T_EXPECT(n >= 17);
		/* origin-form → 400 Bad Request */
		T_EXPECT(has_http_status(rsp, (size_t)n, "400"));
		(void)shutdown(peer_fd, SHUT_WR);
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

/* Regression: bytes past a Content-Length-bounded body are a pipelined
 * second request; the proxy must reject (400) rather than smuggle them
 * upstream as body content. */
/* proxy_pass forwards a Content-Length request body to the upstream and the
 * Content-Length response body back to the client through the framing pumps. */
T_DECLARE_CASE(proxy_pass_forwards_content_length)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "POST http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
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

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	/* the upstream receives the rebuilt request line + headers + body */
	unsigned char up[1024];
	const ssize_t un = recv_at_least(loop, upstream_fd, up, sizeof(up), 1);
	T_EXPECT(un > 0);
	T_EXPECT(memmem(up, (size_t)un, "POST / HTTP/1.1", 15) != NULL);
	T_EXPECT(memmem(up, (size_t)un, "Content-Length: 5", 17) != NULL);
	T_EXPECT(memmem(up, (size_t)un, "hello", 5) != NULL);

	/* upstream replies with a Content-Length response */
	static const char resp[] =
		"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
	T_CHECK(write_all(upstream_fd, resp, sizeof(resp) - 1) == 0);
	(void)shutdown(upstream_fd, SHUT_WR);
	drive_loop(loop);

	/* the client receives the rebuilt response + body */
	unsigned char cl[1024];
	const ssize_t cn = recv_at_least(loop, peer_fd, cl, sizeof(cl), 1);
	T_EXPECT(cn > 0);
	T_EXPECT(memmem(cl, (size_t)cn, "200 OK", 6) != NULL);
	T_EXPECT(memmem(cl, (size_t)cn, "Content-Length: 3", 17) != NULL);
	T_EXPECT(memmem(cl, (size_t)cn, "abc", 3) != NULL);

	/* traffic is counted per direction */
	T_EXPECT((uintmax_t)s.byt_up >= 5); /* request body "hello" */
	T_EXPECT((uintmax_t)s.byt_down >= 3); /* response body "abc" */

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* A chunked request body is dechunked/rechunked to the upstream, and bytes
 * after the chunk terminator (a pipelined second request) are NOT forwarded. */
T_DECLARE_CASE(proxy_pass_chunked_request_discards_surplus)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "POST http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "\r\n"
			   "5\r\nhello\r\n0\r\n\r\n"
			   "GET http://example.com/admin HTTP/1.1\r\n\r\n";

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

	unsigned char up[1024];
	const ssize_t un = recv_at_least(loop, upstream_fd, up, sizeof(up), 1);
	T_EXPECT(un > 0);
	T_EXPECT(
		memmem(up, (size_t)un, "Transfer-Encoding: chunked", 26) !=
		NULL);
	T_EXPECT(memmem(up, (size_t)un, "hello", 5) != NULL);
	/* the pipelined request past the chunk terminator is discarded */
	T_EXPECT(memmem(up, (size_t)un, "admin", 5) == NULL);

	static const char resp[] =
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
	T_CHECK(write_all(upstream_fd, resp, sizeof(resp) - 1) == 0);
	(void)shutdown(upstream_fd, SHUT_WR);
	drive_loop(loop);

	unsigned char cl[1024];
	const ssize_t cn = recv_at_least(loop, peer_fd, cl, sizeof(cl), 1);
	T_EXPECT(cn > 0);
	T_EXPECT(memmem(cl, (size_t)cn, "200 OK", 6) != NULL);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* A bodyless request followed by a pipelined second request: the second
 * request must not reach the upstream. */
T_DECLARE_CASE(proxy_pass_bodyless_pipelined_not_forwarded)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "\r\n"
			   "GET http://example.com/admin HTTP/1.1\r\n\r\n";

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

	unsigned char up[1024];
	const ssize_t un = recv_at_least(loop, upstream_fd, up, sizeof(up), 1);
	T_EXPECT(un > 0);
	T_EXPECT(memmem(up, (size_t)un, "GET / HTTP/1.1", 14) != NULL);
	T_EXPECT(memmem(up, (size_t)un, "admin", 5) == NULL);

	static const char resp[] =
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
	T_CHECK(write_all(upstream_fd, resp, sizeof(resp) - 1) == 0);
	(void)shutdown(upstream_fd, SHUT_WR);
	drive_loop(loop);

	unsigned char cl[1024];
	const ssize_t cn = recv_at_least(loop, peer_fd, cl, sizeof(cl), 1);
	T_EXPECT(cn > 0);
	T_EXPECT(memmem(cl, (size_t)cn, "200 OK", 6) != NULL);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* A chunked upstream response is re-chunked to the client. */
T_DECLARE_CASE(proxy_pass_chunked_response)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n\r\n";

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

	static const char resp[] = "HTTP/1.1 200 OK\r\n"
				   "Transfer-Encoding: chunked\r\n"
				   "\r\n"
				   "3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n";
	T_CHECK(write_all(upstream_fd, resp, sizeof(resp) - 1) == 0);
	(void)shutdown(upstream_fd, SHUT_WR);
	drive_loop(loop);

	unsigned char cl[1024];
	const ssize_t cn = recv_at_least(loop, peer_fd, cl, sizeof(cl), 1);
	T_EXPECT(cn > 0);
	T_EXPECT(memmem(cl, (size_t)cn, "200 OK", 6) != NULL);
	T_EXPECT(
		memmem(cl, (size_t)cn, "Transfer-Encoding: chunked", 26) !=
		NULL);
	/* the re-chunked body carries the original decoded bytes, terminated */
	T_EXPECT(memmem(cl, (size_t)cn, "abc", 3) != NULL);
	T_EXPECT(memmem(cl, (size_t)cn, "defg", 4) != NULL);
	T_EXPECT(memmem(cl, (size_t)cn, "0\r\n\r\n", 5) != NULL);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* Regression: an upstream response with a transfer-coding other than "chunked"
 * (and no Content-Length) cannot be framed, so it must be rejected with 502
 * rather than forwarded with the header dropped and the body mis-framed. */
T_DECLARE_CASE(proxy_pass_unknown_response_transfer_encoding_returns_502)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
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

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	unsigned char up[1024];
	(void)recv_at_least(loop, upstream_fd, up, sizeof(up), 1);

	static const char resp[] =
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nxxxx";
	T_CHECK(write_all(upstream_fd, resp, sizeof(resp) - 1) == 0);
	(void)shutdown(upstream_fd, SHUT_WR);
	drive_loop(loop);

	unsigned char cl[1024];
	const ssize_t cn = recv_at_least(loop, peer_fd, cl, sizeof(cl), 1);
	T_EXPECT(cn > 0);
	T_EXPECT(memmem(cl, (size_t)cn, "502", 3) != NULL);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* A malformed chunked request body is answered with a 400 and closed. */
T_DECLARE_CASE(proxy_pass_malformed_chunked_request_returns_400)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "POST http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "\r\n"
			   "ZZZ\r\n";

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

	/* the client receives a 400 error page, then the connection closes */
	unsigned char b[256];
	const ssize_t n = recv_at_least(loop, peer_fd, b, sizeof(b), 1);
	T_EXPECT(n > 0);
	T_EXPECT(has_http_status(b, (size_t)n, "400"));

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* An EOF-delimited upstream response (no Content-Length, no chunked) is
 * forwarded to the client and bounded by the upstream close. */
T_DECLARE_CASE(proxy_pass_eof_response)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n\r\n";

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

	static const char resp[] =
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nclose-bound";
	T_CHECK(write_all(upstream_fd, resp, sizeof(resp) - 1) == 0);
	(void)shutdown(upstream_fd, SHUT_WR);
	drive_loop(loop);

	unsigned char cl[1024];
	const ssize_t cn = recv_at_least(loop, peer_fd, cl, sizeof(cl), 1);
	T_EXPECT(cn > 0);
	T_EXPECT(memmem(cl, (size_t)cn, "200 OK", 6) != NULL);
	T_EXPECT(memmem(cl, (size_t)cn, "Connection: close", 17) != NULL);
	T_EXPECT(memmem(cl, (size_t)cn, "close-bound", 11) != NULL);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* A HEAD response is bodiless even when it carries a Content-Length. */
T_DECLARE_CASE(proxy_pass_head_response_bodiless)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "HEAD http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n\r\n";

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

	/* upstream sends a HEAD response: headers with Content-Length, no body */
	static const char resp[] =
		"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
	T_CHECK(write_all(upstream_fd, resp, sizeof(resp) - 1) == 0);
	(void)shutdown(upstream_fd, SHUT_WR);
	drive_loop(loop);

	unsigned char cl[1024];
	const ssize_t cn = recv_at_least(loop, peer_fd, cl, sizeof(cl), 1);
	T_EXPECT(cn > 0);
	T_EXPECT(memmem(cl, (size_t)cn, "Content-Length: 42", 18) != NULL);
	/* the client response ends at the header terminator: no body bytes */
	unsigned char *const end = memmem(cl, (size_t)cn, "\r\n\r\n", 4);
	T_CHECK(end != NULL);
	T_EXPECT_EQ((size_t)(end + 4 - cl), (size_t)cn);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* An interim 1xx (100 Continue) response is relayed to the client ahead of the
 * final response. */
T_DECLARE_CASE(proxy_pass_forwards_100_continue)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "POST http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "Content-Length: 5\r\n"
			   "Expect: 100-continue\r\n"
			   "\r\n"
			   "hello";

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

	unsigned char up[1024];
	(void)recv_at_least(loop, upstream_fd, up, sizeof(up), 1);

	/* upstream sends 100 Continue, then the final response */
	static const char cont[] = "HTTP/1.1 100 Continue\r\n\r\n";
	T_CHECK(write_all(upstream_fd, cont, sizeof(cont) - 1) == 0);
	drive_loop(loop);
	static const char resp[] =
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
	T_CHECK(write_all(upstream_fd, resp, sizeof(resp) - 1) == 0);
	(void)shutdown(upstream_fd, SHUT_WR);
	drive_loop(loop);

	unsigned char cl[1024];
	const ssize_t cn = recv_at_least(loop, peer_fd, cl, sizeof(cl), 1);
	T_EXPECT(cn > 0);
	unsigned char *const p100 = memmem(cl, (size_t)cn, "100 Continue", 12);
	unsigned char *const p200 = memmem(cl, (size_t)cn, "200 OK", 6);
	T_CHECK(p100 != NULL);
	T_CHECK(p200 != NULL);
	T_EXPECT(p100 < p200); /* interim precedes the final response */

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* Regression: an interim (1xx) response's end-to-end headers must be forwarded
 * to the client -- a 103 Early Hints Link: header is the whole point of the
 * response and was previously stripped. */
T_DECLARE_CASE(proxy_pass_forwards_interim_headers)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n\r\n";

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

	unsigned char up[1024];
	(void)recv_at_least(loop, upstream_fd, up, sizeof(up), 1);

	/* upstream sends 103 Early Hints with a Link header, then the final 200 */
	static const char hints[] = "HTTP/1.1 103 Early Hints\r\n"
				    "Link: </style.css>; rel=preload\r\n\r\n";
	T_CHECK(write_all(upstream_fd, hints, sizeof(hints) - 1) == 0);
	drive_loop(loop);
	static const char resp[] =
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
	T_CHECK(write_all(upstream_fd, resp, sizeof(resp) - 1) == 0);
	(void)shutdown(upstream_fd, SHUT_WR);
	drive_loop(loop);

	unsigned char cl[2048];
	const ssize_t cn = recv_at_least(loop, peer_fd, cl, sizeof(cl), 1);
	T_EXPECT(cn > 0);
	/* the reason phrase is rebuilt from http_status(), so assert the code
	 * and the forwarded Link header rather than the reason text */
	unsigned char *const p103 = memmem(cl, (size_t)cn, "HTTP/1.1 103", 12);
	unsigned char *const link =
		memmem(cl, (size_t)cn, "Link: </style.css>", 18);
	unsigned char *const p200 = memmem(cl, (size_t)cn, "200 OK", 6);
	T_CHECK(p103 != NULL);
	T_CHECK(link !=
		NULL); /* the interim's Link header reached the client */
	T_CHECK(p200 != NULL);
	T_EXPECT(p103 < link && link < p200);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* Several pipelined 1xx interim responses arriving in one read must all be
 * forwarded ahead of the final response; the rsp phase machine iterates over
 * them (previously it recursed one frame per interim). */
T_DECLARE_CASE(proxy_pass_multiple_interim_responses)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n\r\n";

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
	unsigned char up[1024];
	(void)recv_at_least(loop, upstream_fd, up, sizeof(up), 1);

	/* three interims then the final response, all in a single write */
	static const char resp[] =
		"HTTP/1.1 103 Early Hints\r\n\r\n"
		"HTTP/1.1 103 Early Hints\r\n\r\n"
		"HTTP/1.1 100 Continue\r\n\r\n"
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
	T_CHECK(write_all(upstream_fd, resp, sizeof(resp) - 1) == 0);
	(void)shutdown(upstream_fd, SHUT_WR);
	drive_loop(loop);

	unsigned char cl[1024];
	const ssize_t cn = recv_at_least(loop, peer_fd, cl, sizeof(cl), 1);
	T_EXPECT(cn > 0);
	unsigned char *const p100 = memmem(cl, (size_t)cn, "100 Continue", 12);
	unsigned char *const p200 = memmem(cl, (size_t)cn, "200 OK", 6);
	T_CHECK(p100 != NULL);
	T_CHECK(p200 != NULL);
	/* every pipelined interim must be forwarded (as a canonical 1xx status
	 * line -- the proxy re-emits the reason phrase from http_status(), which
	 * has no entry for 103, so match on the status-line prefix): both 103
	 * interims precede the 100 Continue, which precedes the final 200 OK */
	unsigned char *const p103a = memmem(cl, (size_t)cn, "HTTP/1.1 103", 12);
	T_CHECK(p103a != NULL);
	const size_t off103a = (size_t)(p103a + 12 - cl);
	unsigned char *const p103b =
		memmem(p103a + 12, (size_t)cn - off103a, "HTTP/1.1 103", 12);
	T_CHECK(p103b != NULL);
	T_EXPECT(p103a < p103b);
	T_EXPECT(p103b < p100); /* both interims precede the 100 Continue */
	T_EXPECT(p100 < p200); /* interims precede the final response */
	T_EXPECT(memmem(cl, (size_t)cn, "ok", 2) != NULL);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* Regression: framing headers on a 1xx interim response must not leak into the
 * following final response. A 103 carrying Transfer-Encoding: chunked ahead of
 * a Content-Length final response previously left rsp_chunked set, so the final
 * body was (mis)dechunked and the response corrupted. */
T_DECLARE_CASE(proxy_pass_interim_framing_does_not_leak)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n\r\n";

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
	unsigned char up[1024];
	(void)recv_at_least(loop, upstream_fd, up, sizeof(up), 1);

	static const char interim[] = "HTTP/1.1 103 Early Hints\r\n"
				      "Transfer-Encoding: chunked\r\n\r\n";
	T_CHECK(write_all(upstream_fd, interim, sizeof(interim) - 1) == 0);
	drive_loop(loop);
	static const char resp[] =
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
	T_CHECK(write_all(upstream_fd, resp, sizeof(resp) - 1) == 0);
	(void)shutdown(upstream_fd, SHUT_WR);
	drive_loop(loop);

	unsigned char cl[1024];
	const ssize_t cn = recv_at_least(loop, peer_fd, cl, sizeof(cl), 1);
	T_EXPECT(cn > 0);
	/* the final response must be forwarded intact and Content-Length framed;
	 * the interim's chunked framing must not have leaked onto it */
	T_EXPECT(memmem(cl, (size_t)cn, "200 OK", 6) != NULL);
	T_EXPECT(memmem(cl, (size_t)cn, "Content-Length: 5", 17) != NULL);
	T_EXPECT(memmem(cl, (size_t)cn, "hello", 5) != NULL);
	T_EXPECT(
		memmem(cl, (size_t)cn, "Transfer-Encoding: chunked", 26) ==
		NULL);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* Regression: an upstream Content-Length with a leading sign must be rejected
 * (502), not fed through strtoumax where "-1" wraps to SIZE_MAX. */
T_DECLARE_CASE(proxy_pass_negative_content_length_rejected)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n\r\n";

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
	unsigned char up[1024];
	(void)recv_at_least(loop, upstream_fd, up, sizeof(up), 1);

	static const char resp[] =
		"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n";
	T_CHECK(write_all(upstream_fd, resp, sizeof(resp) - 1) == 0);
	(void)shutdown(upstream_fd, SHUT_WR);
	drive_loop(loop);

	unsigned char cl[1024];
	const ssize_t cn = recv_at_least(loop, peer_fd, cl, sizeof(cl), 1);
	T_EXPECT(cn > 0);
	T_EXPECT(memmem(cl, (size_t)cn, "502", 3) != NULL);
	/* the wrapped SIZE_MAX must never be emitted as the client's framing */
	T_EXPECT(memmem(cl, (size_t)cn, "18446744073709551615", 20) == NULL);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* Regression: an upstream response header value containing a control char must
 * be rejected (502), matching the request-side field validation, not forwarded
 * verbatim to the client. */
T_DECLARE_CASE(proxy_pass_response_control_char_header_rejected)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n\r\n";

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
	unsigned char up[1024];
	(void)recv_at_least(loop, upstream_fd, up, sizeof(up), 1);

	/* a bare control char (0x01) inside the header value; http_parsehdr keeps
	 * it since it only splits on CRLF */
	static const char resp[] = "HTTP/1.1 200 OK\r\n"
				   "X-Bad: va\x01lue\r\n"
				   "Content-Length: 0\r\n\r\n";
	T_CHECK(write_all(upstream_fd, resp, sizeof(resp) - 1) == 0);
	(void)shutdown(upstream_fd, SHUT_WR);
	drive_loop(loop);

	unsigned char cl[1024];
	const ssize_t cn = recv_at_least(loop, peer_fd, cl, sizeof(cl), 1);
	T_EXPECT(cn > 0);
	T_EXPECT(memmem(cl, (size_t)cn, "502", 3) != NULL);
	/* the injected control char must never reach the client */
	T_EXPECT(memmem(cl, (size_t)cn, "\x01", 1) == NULL);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* Regression: more upstream response headers than the forwarding table holds
 * must be a fatal error (502), matching the request side, not silently dropped. */
T_DECLARE_CASE(proxy_pass_too_many_response_headers_rejected)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n\r\n";

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
	unsigned char up[1024];
	(void)recv_at_least(loop, upstream_fd, up, sizeof(up), 1);

	/* 101 forwardable headers > PROXY_MAX_HEADERS (100) */
	char *const resp = malloc(8192);
	T_CHECK(resp != NULL);
	int off = snprintf(resp, 8192, "HTTP/1.1 200 OK\r\n");
	for (int i = 0; i < 101; i++) {
		off += snprintf(
			resp + off, (size_t)(8192 - off), "X-H%d: v\r\n", i);
	}
	off += snprintf(resp + off, (size_t)(8192 - off), "\r\n");
	T_CHECK(write_all(upstream_fd, resp, (size_t)off) == 0);
	(void)shutdown(upstream_fd, SHUT_WR);
	drive_loop(loop);

	unsigned char cl[1024];
	const ssize_t cn = recv_at_least(loop, peer_fd, cl, sizeof(cl), 1);
	free(resp);
	T_EXPECT(cn > 0);
	T_EXPECT(memmem(cl, (size_t)cn, "502", 3) != NULL);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* A request body larger than the pump buffer round-trips byte-for-byte
 * (multi-cycle forwarding with bounded memory). */
T_DECLARE_CASE(proxy_pass_large_body_integrity)
{
	enum { LARGE_BODY = 50000 };
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;

	char *const reqbuf = malloc(LARGE_BODY + 256);
	T_CHECK(reqbuf != NULL);
	const int hlen = snprintf(
		reqbuf, 256,
		"POST http://example.com/ HTTP/1.1\r\n"
		"Host: example.com\r\nContent-Length: %d\r\n\r\n",
		(int)LARGE_BODY);
	for (int i = 0; i < LARGE_BODY; i++) {
		reqbuf[hlen + i] = (char)('A' + (i % 26));
	}
	reqbuf[hlen + LARGE_BODY] = '\0';

	reset_stub_state();
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;

	init_server(&loop, &s);
	serve_payload(loop, &s, reqbuf, &peer_fd);

	/* read the whole forwarded request from the upstream (headers + body) */
	unsigned char *const up = malloc(LARGE_BODY + 512);
	T_CHECK(up != NULL);
	const size_t un =
		recv_all(loop, upstream_fd, up, (size_t)LARGE_BODY + 512);
	unsigned char *const body = memmem(up, un, "\r\n\r\n", 4);
	T_CHECK(body != NULL);
	const size_t bodyoff = (size_t)(body - up) + 4;
	T_EXPECT_EQ(un - bodyoff, (size_t)LARGE_BODY);
	bool intact = true;
	for (int i = 0; i < LARGE_BODY; i++) {
		if (up[bodyoff + (size_t)i] !=
		    (unsigned char)('A' + (i % 26))) {
			intact = false;
			break;
		}
	}
	T_EXPECT(intact);

	free(reqbuf);
	free(up);
	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* An established stream with an unresponsive upstream is bounded by the global
 * timeout used as an idle timeout, and closes without counting as a reject. */
T_DECLARE_CASE(proxy_pass_idle_stream_times_out)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n\r\n";

	reset_stub_state();
	test_conf.timeout = 0.05;
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	/* let the stream establish (request forwarded to the upstream) */
	struct server_success_wait_ctx wc = { .s = &s, .expected = 1 };
	T_EXPECT(test_wait_until(loop, server_success_reached, &wc, 1.0));

	/* the upstream never responds: the idle timeout must close the stream */
	test_run_for(loop, test_timeout_wait_window(test_conf.timeout));

	unsigned char b[64];
	const ssize_t n = recv(peer_fd, b, sizeof(b), 0);
	T_EXPECT_EQ(n, (ssize_t)0); /* connection closed by the idle timeout */
	/* an established-then-idle stream is not a rejected connection */
	T_EXPECT_EQ((uintmax_t)s.stats.num_reject_timeout, (uintmax_t)0);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* Once the response body is streaming, the idle timeout is released: a quiet
 * period longer than the timeout must NOT close a long-lived stream (SSE). */
T_DECLARE_CASE(proxy_pass_streaming_response_survives_idle)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1, upstream_fd = -1, dialed_fd = -1;
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n\r\n";

	reset_stub_state();
	test_conf.timeout = 0.05;
	S.dialreq_new_ok = true;
	S.dialaddr_parse_ok = true;
	make_fd_pair(&dialed_fd, &upstream_fd);
	S.dialer_result_fd = dialed_fd;
	S.dialer_err = DIALER_OK;
	S.dialer_syserr = 0;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	/* upstream sends a streaming (event-stream) response header, no body yet:
	 * this drives the proxy into RSP_BODY, which releases the idle timeout */
	static const char hdr[] = "HTTP/1.1 200 OK\r\n"
				  "Content-Type: text/event-stream\r\n"
				  "Transfer-Encoding: chunked\r\n\r\n";
	unsigned char up[256];
	(void)recv_at_least(
		loop, upstream_fd, up, sizeof(up), 1); /* the request */
	T_CHECK(write_all(upstream_fd, hdr, sizeof(hdr) - 1) == 0);
	drive_loop(loop);

	/* the client sees the response header block */
	unsigned char cl[256];
	ssize_t cn = recv_at_least(loop, peer_fd, cl, sizeof(cl), 1);
	T_EXPECT(cn > 0);
	T_EXPECT(memmem(cl, (size_t)cn, "text/event-stream", 17) != NULL);

	/* a quiet period longer than the idle timeout must not tear it down */
	test_run_for(loop, test_timeout_wait_window(test_conf.timeout));
	T_EXPECT_EQ((uintmax_t)s.stats.num_reject_timeout, (uintmax_t)0);

	/* the stream is still alive: a late event is delivered to the client */
	static const char event[] = "7\r\ndata: 1\r\n"; /* one chunked event */
	T_CHECK(write_all(upstream_fd, event, sizeof(event) - 1) == 0);
	drive_loop(loop);
	unsigned char ev[256];
	cn = recv_at_least(loop, peer_fd, ev, sizeof(ev), 1);
	T_EXPECT(cn > 0); /* not EOF -> the connection stayed open */
	T_EXPECT(memmem(ev, (size_t)cn, "data: 1", 7) != NULL);

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
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

	/* origin-form → 400 Bad Request */
	T_EXPECT(assert_response_status(loop, peer_fd, "400"));

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
			recv_at_least(loop, peer_fd, rsp, sizeof(rsp), 17);
		T_EXPECT(n >= 17);
		T_EXPECT(has_http_status(rsp, (size_t)n, "400"));
		(void)shutdown(peer_fd, SHUT_WR);
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
			recv_at_least(loop, peer_fd, rsp, sizeof(rsp), 17);
		T_EXPECT(n >= 17);
		T_EXPECT(has_http_status(rsp, (size_t)n, "400"));
		(void)shutdown(peer_fd, SHUT_WR);
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
			recv_at_least(loop, peer_fd, rsp, sizeof(rsp), 17);
		T_EXPECT(n >= 17);
		T_EXPECT(has_http_status(rsp, (size_t)n, "500"));
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
	test_conf.timeout = 0.01;
	G.ruleset = (struct ruleset *)&ruleset_stub;
	S.ruleset_resolve_ok = true;
	S.ruleset_reply_with_req = true;
	S.ruleset_finish_now = false;
	S.ruleset_state_nonnull = true;

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	test_run_for(loop, test_timeout_wait_window(test_conf.timeout));

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

	test_run_for(loop, test_timeout_wait_window(test_conf.timeout));

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

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	/* The request is forwarded; the connection should close after transfer */
	{
		unsigned char buf[4096];
		const ssize_t n =
			recv_at_least(loop, upstream_fd, buf, sizeof(buf), 20);
		/* upstream receives the forwarded request */
		T_EXPECT(n >= 20);
		T_EXPECT(memmem(buf, (size_t)n, "GET / HTTP/1.1", 14) != NULL);
		T_EXPECT(
			memmem(buf, (size_t)n, "Connection: close", 17) !=
			NULL);
		(void)shutdown(upstream_fd, SHUT_WR);
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
	unsigned char buf[4096];
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

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	{
		const ssize_t n =
			recv_at_least(loop, upstream_fd, buf, sizeof(buf), 25);
		T_EXPECT(n >= 25);
		T_EXPECT(
			memmem(buf, (size_t)n, "POST /submit HTTP/1.1", 21) !=
			NULL);
		T_EXPECT(
			memmem(buf, (size_t)n, "Content-Length: 7", 17) !=
			NULL);
		/* body forwarded */
		T_EXPECT(memmem(buf, (size_t)n, "a=b&c=d", 7) != NULL);
		(void)shutdown(upstream_fd, SHUT_WR);
	}

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* A request carrying "Expect: 100-continue" with a body is forwarded to the
 * upstream; this exercises the Expect header handling path. */
T_DECLARE_CASE(plain_http_expect_100_continue_with_body_forwarded)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	int peer_fd = -1;
	int upstream_fd = -1;
	int dialed_fd = -1;
	unsigned char buf[4096];
	const char req[] = "POST http://example.com/submit HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "Expect: 100-continue\r\n"
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

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	{
		const ssize_t n =
			recv_at_least(loop, upstream_fd, buf, sizeof(buf), 25);
		T_EXPECT(n >= 25);
		T_EXPECT(
			memmem(buf, (size_t)n, "POST /submit HTTP/1.1", 21) !=
			NULL);
		T_EXPECT(memmem(buf, (size_t)n, "a=b&c=d", 7) != NULL);
		(void)shutdown(upstream_fd, SHUT_WR);
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
	unsigned char buf[4096];
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

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	{
		const ssize_t n =
			recv_at_least(loop, upstream_fd, buf, sizeof(buf), 25);
		T_EXPECT(n >= 25);
		T_EXPECT(
			memmem(buf, (size_t)n, "GET /page HTTP/1.0", 18) !=
			NULL);
		(void)shutdown(upstream_fd, SHUT_WR);
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
	unsigned char buf[4096];
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

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	{
		const ssize_t n =
			recv_at_least(loop, upstream_fd, buf, sizeof(buf), 30);
		T_EXPECT(n >= 30);
		T_EXPECT(memmem(buf, (size_t)n, "POST / HTTP/1.1", 15) != NULL);
		T_EXPECT(
			memmem(buf, (size_t)n, "Transfer-Encoding: chunked",
			       26) != NULL);
		(void)shutdown(upstream_fd, SHUT_WR);
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
	unsigned char buf[4096];
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

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	{
		const ssize_t n =
			recv_at_least(loop, upstream_fd, buf, sizeof(buf), 25);
		T_EXPECT(n >= 25);
		/* dynamic hop-by-hop header must not reach upstream */
		T_EXPECT(memmem(buf, (size_t)n, "X-Hop", 5) == NULL);
		/* end-to-end headers must still be forwarded */
		T_EXPECT(
			memmem(buf, (size_t)n, "Host: example.com", 17) !=
			NULL);
		(void)shutdown(upstream_fd, SHUT_WR);
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
	unsigned char buf[4096];
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

	init_server(&loop, &s);
	serve_payload(loop, &s, req, &peer_fd);

	{
		const ssize_t n =
			recv_at_least(loop, upstream_fd, buf, sizeof(buf), 25);
		T_EXPECT(n >= 25);
		T_EXPECT(
			memmem(buf, (size_t)n, "Proxy-Authorization", 19) ==
			NULL);
		(void)shutdown(upstream_fd, SHUT_WR);
	}

	T_CHECK(close(peer_fd) == 0);
	T_CHECK(close(upstream_fd) == 0);
	ev_loop_destroy(loop);
}

/* A successful plain HTTP forward must count exactly one success, and
 * establish a bidirectional relay between client and upstream. */
T_DECLARE_CASE(plain_http_forward_success_counted_once)
{
	struct ev_loop *loop = NULL;
	struct server s = { 0 };
	struct server_success_wait_ctx wait_ctx = { 0 };
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

/*
 * Regression: a client that doesn't wait for the "200 Connection
 * established" reply before sending payload (e.g. TCP fast open) has its
 * CONNECT request and payload delivered in a single recv(). Unlike
 * proxy_pass, a CONNECT tunnel has no build_forward_req()/cbuf salvage step,
 * so any bytes past the request/headers were silently dropped instead of
 * being forwarded to the upstream once the tunnel opens.
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

T_DECLARE_CASE(request_with_cl_and_te_is_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* CL appears before TE; RFC 9112 §6.3 requires 400 */
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "Content-Length: 5\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
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

T_DECLARE_CASE(request_with_te_and_cl_is_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* TE appears before CL; both orderings must be rejected */
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "Content-Length: 5\r\n"
			   "\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
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

T_DECLARE_CASE(request_with_duplicate_cl_is_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* RFC 9112 §6.3: duplicate Content-Length must be rejected */
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "Content-Length: 5\r\n"
			   "Content-Length: 5\r\n"
			   "\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
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

T_DECLARE_CASE(request_with_invalid_cl_is_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* Comma-list "5, 5" is not valid 1*DIGIT; must be rejected */
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "Host: example.com\r\n"
			   "Content-Length: 5, 5\r\n"
			   "\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
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

T_DECLARE_CASE(request_header_value_with_bare_cr_is_rejected)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	/* Bare CR in a field value is a CTL; RFC 9112 §2.2 SHOULD reject.
	 * The \r before "Injected" is not followed by \n so strstr("\r\n")
	 * finds the real CRLF later; value = "foo\rInjected: bar". */
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "X-Custom: foo\r"
			   "Injected: bar\r\n"
			   "\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
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
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "X-Custom: foo\x01"
			   "bar\r\n"
			   "\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
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
	const char req[] = "GET http://example.com/ HTTP/1.1\r\n"
			   "X Invalid: foo\r\n"
			   "\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
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

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(plain_http_origin_form_returns_400),
	T_CASE(proxy_pass_forwards_content_length),
	T_CASE(proxy_pass_chunked_request_discards_surplus),
	T_CASE(proxy_pass_bodyless_pipelined_not_forwarded),
	T_CASE(proxy_pass_chunked_response),
	T_CASE(proxy_pass_unknown_response_transfer_encoding_returns_502),
	T_CASE(proxy_pass_malformed_chunked_request_returns_400),
	T_CASE(proxy_pass_eof_response),
	T_CASE(proxy_pass_head_response_bodiless),
	T_CASE(proxy_pass_forwards_100_continue),
	T_CASE(proxy_pass_forwards_interim_headers),
	T_CASE(proxy_pass_multiple_interim_responses),
	T_CASE(proxy_pass_interim_framing_does_not_leak),
	T_CASE(proxy_pass_negative_content_length_rejected),
	T_CASE(proxy_pass_response_control_char_header_rejected),
	T_CASE(proxy_pass_too_many_response_headers_rejected),
	T_CASE(proxy_pass_large_body_integrity),
	T_CASE(proxy_pass_idle_stream_times_out),
	T_CASE(proxy_pass_streaming_response_survives_idle),
	T_CASE(split_request_is_parsed_incrementally),
	T_CASE(plain_http_absolute_url_no_dialreq_returns_500),
	T_CASE(plain_http_absolute_url_no_host_returns_400),
	T_CASE(plain_http_absolute_url_dialer_error_returns_502),
	T_CASE(plain_http_absolute_url_established),
	T_CASE(plain_http_post_with_body_forwarded),
	T_CASE(plain_http_expect_100_continue_with_body_forwarded),
	T_CASE(plain_http_version_preserved_in_forwarded_request),
	T_CASE(plain_http_te_chunked_forwarded_to_upstream),
	T_CASE(plain_http_dynamic_hop_by_hop_not_forwarded),
	T_CASE(plain_http_proxy_authorization_not_forwarded),
	T_CASE(plain_http_forward_success_counted_once),
	T_CASE(malformed_proxy_authorization_returns_400),
	T_CASE(invalid_te_returns_400),
	T_CASE(connect_with_invalid_target_returns_500),
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
	T_CASE(ruleset_resolve_failure_returns_500),
	T_CASE(ruleset_finish_without_req_returns_403),
	T_CASE(ruleset_finish_with_req_and_dialer_error_returns_502),
	T_CASE(timeout_in_process_state_cancels_ruleset),
	T_CASE(timeout_in_connect_state_cancels_dialer),
	T_CASE(request_with_cl_and_te_is_rejected),
	T_CASE(request_with_te_and_cl_is_rejected),
	T_CASE(request_with_duplicate_cl_is_rejected),
	T_CASE(request_with_invalid_cl_is_rejected),
	T_CASE(request_header_value_with_bare_cr_is_rejected),
	T_CASE(request_header_value_with_ctl_is_rejected),
	T_CASE(request_header_name_with_invalid_token_is_rejected),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	reset_stub_state();
	const int ret = testing_main(argc, argv, suite);
	reset_stub_state();
	return ret;
}
