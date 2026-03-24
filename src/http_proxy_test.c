/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http_proxy.h"

#include "conf.h"
#include "dialer.h"
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
struct globals G = { 0 };

static struct config test_conf = {
	.timeout = 1.0,
	.auth_required = false,
	.bidir_timeout = false,
};

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
	bool transfer_auto_finish;
	bool ruleset_resolve_ok;
	bool ruleset_reply_with_req;
	bool ruleset_finish_now;
	bool ruleset_state_nonnull;
	struct ev_loop *ruleset_loop;
	struct ruleset_state *ruleset_state_ptr;
	int_least32_t ruleset_cancel_calls;
	int_least32_t dialer_cancel_calls;
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
};

static int_least32_t ruleset_state_token = 0;

static void reset_stub_state(void)
{
	S.dialreq_new_ok = false;
	S.dialaddr_parse_ok = false;
	S.dialer_invoke_now = true;
	S.dialer_result_fd = -1;
	S.dialer_err = DIALER_ERR_CONNECT;
	S.dialer_syserr = ECONNREFUSED;
	S.transfer_auto_finish = true;
	S.ruleset_resolve_ok = false;
	S.ruleset_reply_with_req = false;
	S.ruleset_finish_now = false;
	S.ruleset_state_nonnull = false;
	S.ruleset_loop = NULL;
	S.ruleset_state_ptr = NULL;
	S.ruleset_cancel_calls = 0;
	S.dialer_cancel_calls = 0;
	test_conf.timeout = 1.0;
	test_conf.auth_required = false;
	test_conf.bidir_timeout = false;
	G.ruleset = NULL;
	G.conf = &test_conf;
}

const char *dialer_strerror(const enum dialer_error err)
{
	(void)err;
	return "stub";
}

struct dialreq *dialreq_new(const size_t num_proxy)
{
	(void)num_proxy;
	if (!S.dialreq_new_ok) {
		return NULL;
	}
	return calloc(1, sizeof(struct dialreq));
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

void dialer_do(struct dialer *d, struct ev_loop *loop, const struct dialreq *req)
{
	d->req = req;
	(void)loop;
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
	const bool is_uplink)
{
	t->state = XFER_INIT;
	t->state_cb = *callback;
	(void)src_fd;
	(void)dst_fd;
	t->byt_transferred = byt_transferred;
	(void)is_uplink;
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
	if (S.ruleset_reply_with_req) {
		callback->request.req = dialreq_new(0);
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

static void drive_loop(struct ev_loop *loop)
{
	for (size_t i = 0; i < 64; i++) {
		ev_run(loop, EVRUN_NOWAIT);
		(void)usleep(1000);
	}
}

static ssize_t recv_all_with_timeout(
	const int fd, unsigned char *restrict buf, const size_t cap)
{
	size_t off = 0;
	/*
	 * Poll non-blocking reads for a short window to avoid test hangs when
	 * peer closure timing varies across platforms.
	 */
	size_t idle_rounds = 0;
	const size_t idle_rounds_max = 200;
	while (off < cap) {
		const ssize_t n = recv(fd, buf + off, cap - off, MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				if (idle_rounds++ >= idle_rounds_max) {
					break;
				}
				(void)usleep(1000);
				continue;
			}
			return -1;
		}
		if (n == 0) {
			break;
		}
		off += (size_t)n;
		idle_rounds = 0;
	}
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

static void init_server(struct ev_loop **loop, struct server *restrict s)
{
	*loop = ev_loop_new(0);
	T_CHECK(*loop != NULL);
	s->loop = *loop;
	G.conf = &test_conf;
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

static bool
assert_response_status(const int peer_fd, const char *restrict status)
{
	unsigned char rsp[1024];
	const ssize_t n = recv_all_with_timeout(peer_fd, rsp, sizeof(rsp));
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

T_DECLARE_CASE(non_connect_returns_403)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const char req[] = "GET / HTTP/1.1\r\nHost: example\r\n\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
	G.conf = &test_conf;

	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[1024];
		const ssize_t n =
			recv_all_with_timeout(peer_fd, rsp, sizeof(rsp));
		T_EXPECT(n > 0);
		T_EXPECT(has_http_status(rsp, (size_t)n, "403"));
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

	T_EXPECT(assert_response_status(peer_fd, "403"));

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
	G.conf = &test_conf;

	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[1024];
		const ssize_t n =
			recv_all_with_timeout(peer_fd, rsp, sizeof(rsp));
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
	G.conf = &test_conf;

	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[1024];
		const ssize_t n =
			recv_all_with_timeout(peer_fd, rsp, sizeof(rsp));
		T_EXPECT(n > 0);
		T_EXPECT(has_http_status(rsp, (size_t)n, "400"));
	}

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(connect_with_invalid_target_returns_500)
{
	struct ev_loop *loop = ev_loop_new(0);
	struct server s = { 0 };
	int peer_fd = -1;
	const char req[] = "CONNECT not-a-valid-hostport HTTP/1.1\r\n"
			   "Host: ignored\r\n"
			   "\r\n";

	T_CHECK(loop != NULL);
	s.loop = loop;
	G.conf = &test_conf;

	serve_payload(loop, &s, req, &peer_fd);
	drive_loop(loop);

	{
		unsigned char rsp[1024];
		const ssize_t n =
			recv_all_with_timeout(peer_fd, rsp, sizeof(rsp));
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

	T_EXPECT(assert_response_status(peer_fd, "502"));

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
			recv_all_with_timeout(peer_fd, rsp, sizeof(rsp));
		T_EXPECT(n > 0);
		T_EXPECT(
			memmem(rsp, (size_t)n, "200 Connection established",
			       26) != NULL);
	}

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

	T_EXPECT(assert_response_status(peer_fd, "502"));

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

	T_EXPECT(assert_response_status(peer_fd, "400"));

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

	T_EXPECT(assert_response_status(peer_fd, "407"));

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

	T_EXPECT(assert_response_status(peer_fd, "407"));

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

	T_EXPECT(assert_response_status(peer_fd, "500"));

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(ruleset_finish_without_req_returns_500)
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

	T_EXPECT(assert_response_status(peer_fd, "500"));

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

	T_EXPECT(assert_response_status(peer_fd, "502"));

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

	for (size_t i = 0; i < 1000; i++) {
		ev_run(loop, EVRUN_NOWAIT);
		(void)usleep(1000);
	}

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

	for (size_t i = 0; i < 1000; i++) {
		ev_run(loop, EVRUN_NOWAIT);
		(void)usleep(1000);
	}

	T_EXPECT(S.dialer_cancel_calls > 0);

	T_CHECK(close(peer_fd) == 0);
	ev_loop_destroy(loop);
}

int main(void)
{
	T_DECLARE_CTX(t);
	reset_stub_state();
	T_RUN_CASE(t, non_connect_returns_403);
	T_RUN_CASE(t, split_request_is_parsed_incrementally);
	T_RUN_CASE(t, malformed_proxy_authorization_returns_400);
	T_RUN_CASE(t, invalid_te_returns_400);
	T_RUN_CASE(t, connect_with_invalid_target_returns_500);
	T_RUN_CASE(t, valid_connect_dialer_error_returns_502);
	T_RUN_CASE(t, valid_connect_established_with_hijack);
	T_RUN_CASE(t, connect_with_transfer_encoding_chunked_is_accepted);
	T_RUN_CASE(t, authorization_header_without_space_returns_400);
	T_RUN_CASE(
		t, ruleset_auth_required_without_basic_credentials_returns_407);
	T_RUN_CASE(t, ruleset_auth_required_with_invalid_basic_returns_407);
	T_RUN_CASE(t, ruleset_resolve_failure_returns_500);
	T_RUN_CASE(t, ruleset_finish_without_req_returns_500);
	T_RUN_CASE(t, ruleset_finish_with_req_and_dialer_error_returns_502);
	T_RUN_CASE(t, timeout_in_process_state_cancels_ruleset);
	T_RUN_CASE(t, timeout_in_connect_state_cancels_dialer);

	return T_RESULT(t) ? 0 : 1;
}
