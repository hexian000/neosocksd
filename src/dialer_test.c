/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for dialer.c; mocked: HTTP/SOCKS peers (hand-rolled over sockets). */

#include "dialer.h"

#include "conf.h"
#include "proto/socks.h"
#include "resolver.h"
#include "server.h"

#include "utils/testing.h"

#include <ev.h>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - raw loopback proxy peers and shared fixtures (no collaborator module
 * is linked; the dialer's peers are hand-rolled over socketpairs/listeners).
 * ---------------------------------------------------------------------- */

static struct config test_conf = {
	.timeout = 0.2,
};

static const ev_tstamp TEST_WAIT_SHORT_SEC = 0.064;
static const ev_tstamp TEST_WAIT_RESPONSE_SEC = 0.256;
/* Short tick so ev_run() wakes promptly when mock servers write in fragments
 * (needed for MSYS2/Cygwin socket emulation). */
static const ev_tstamp TEST_TICK_SEC = 0.002;

struct dialer_result {
	bool called;
	int fd;
};

struct test_watchdog {
	bool fired;
};

struct proxy_server {
	int listener_fd;
	int peer_fd;
	char request[1024];
	size_t request_len;
	const char *response;
	/* Bytes of `response` written per pump() call once the request is
	 * complete; 0 (the default) sends the whole response in one write,
	 * matching every existing test. A nonzero value spreads delivery
	 * across multiple dialer_recv() events, e.g. to reproduce bugs in
	 * how partial reads are accounted for. */
	size_t response_chunk;
	size_t response_off;
	bool request_complete;
	bool response_sent;
	bool failed;
};

static void close_if_open(int *restrict fd)
{
	if (*fd >= 0) {
		T_CHECK(close(*fd) == 0);
		*fd = -1;
	}
}

static void dialer_finish_cb(struct ev_loop *loop, void *data, const int fd)
{
	struct dialer_result *const result = data;
	(void)loop;
	result->called = true;
	result->fd = fd;
}

static bool dialer_called_predicate(void *data)
{
	const struct dialer_result *const result = data;
	return result->called;
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
test_tick_cb(struct ev_loop *loop, struct ev_timer *w, const int revents)
{
	/* No-op: this timer exists only to bound ev_run(EVRUN_ONCE) sleeps. */
	(void)loop;
	(void)w;
	(void)revents;
}

static bool test_wait_until(
	struct ev_loop *loop, bool (*predicate)(void *), void *predicate_data,
	const ev_tstamp timeout_sec, bool (*step)(void *), void *step_data)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timeout, w_tick;
	bool ok = true;

	ev_timer_init(&w_timeout, test_watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	/* Bound ev_run() sleeps so the step callback (an unwatched mock server)
	 * keeps getting serviced even while the dialer waits on a reply. */
	ev_timer_init(&w_tick, test_tick_cb, TEST_TICK_SEC, TEST_TICK_SEC);
	ev_timer_start(loop, &w_tick);
	while (!watchdog.fired && !predicate(predicate_data) && ok) {
		ev_run(loop, EVRUN_ONCE);
		if (step != NULL) {
			ok = step(step_data);
		}
	}
	ev_timer_stop(loop, &w_tick);
	ev_timer_stop(loop, &w_timeout);
	return ok && predicate(predicate_data);
}

static bool fd_set_nonblock(const int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		return false;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

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
	T_CHECK(listen(fd, 1) == 0);
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
	T_CHECK(listen(fd, 1) == 0);
	T_CHECK(fd_set_nonblock(fd));
	T_CHECK(getsockname(fd, (struct sockaddr *)&bound_addr, &len) == 0);
	*port = ntohs(bound_addr.sin6_port);
	return fd;
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

static bool proxy_server_pump(void *data)
{
	struct proxy_server *const server = data;

	if (server->peer_fd < 0) {
		server->peer_fd = accept_nowait(server->listener_fd);
		if (server->peer_fd < 0) {
			return true;
		}
	}
	if (!server->request_complete) {
		const size_t avail =
			sizeof(server->request) - server->request_len - 1;
		const ssize_t n = recv_nowait(
			server->peer_fd, server->request + server->request_len,
			avail);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return true;
			}
			server->failed = true;
			return false;
		}
		if (n == 0) {
			server->failed = true;
			return false;
		}
		server->request_len += (size_t)n;
		server->request[server->request_len] = '\0';
		if (server->request_len + 1 >= sizeof(server->request)) {
			server->failed = true;
			return false;
		}
		if (strstr(server->request, "\r\n\r\n") != NULL) {
			server->request_complete = true;
		}
	}
	if (server->request_complete && !server->response_sent) {
		const size_t total = strlen(server->response);
		const size_t chunk = server->response_chunk != 0 ?
					     server->response_chunk :
					     total;
		size_t n = chunk;
		if (server->response_off + n > total) {
			n = total - server->response_off;
		}
		if (n > 0 &&
		    !write_all(
			    server->peer_fd,
			    server->response + server->response_off, n)) {
			server->failed = true;
			return false;
		}
		server->response_off += n;
		if (server->response_off >= total) {
			server->response_sent = true;
		}
	}
	return true;
}

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - address/request parsing and CONNECT handshakes against raw
 * loopback peers.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(dialaddr_parse_and_format_variants)
{
	struct dialaddr addr = { 0 };
	char buf[128];

	T_EXPECT(dialaddr_parse(&addr, "127.0.0.1:1080", 14));
	T_EXPECT_EQ(addr.type, ATYP_INET);
	T_EXPECT_EQ(addr.port, UINT16_C(1080));
	T_EXPECT_EQ(dialaddr_format(buf, sizeof(buf), &addr), 14);
	T_EXPECT_STREQ(buf, "127.0.0.1:1080");

	T_EXPECT(dialaddr_parse(&addr, "[::1]:5353", 10));
	T_EXPECT_EQ(addr.type, ATYP_INET6);
	T_EXPECT_EQ(addr.port, UINT16_C(5353));
	T_EXPECT_EQ(dialaddr_format(buf, sizeof(buf), &addr), 10);
	T_EXPECT_STREQ(buf, "[::1]:5353");

	T_EXPECT(dialaddr_parse(&addr, "example.com:443", 15));
	T_EXPECT_EQ(addr.type, ATYP_DOMAIN);
	T_EXPECT_EQ(addr.port, UINT16_C(443));
	T_EXPECT_EQ(addr.domain.len, strlen("example.com"));
	T_EXPECT_MEMEQ(addr.domain.name, "example.com", addr.domain.len);
	T_EXPECT_EQ(dialaddr_format(buf, sizeof(buf), &addr), 15);
	T_EXPECT_STREQ(buf, "example.com:443");

	T_EXPECT(!dialaddr_parse(&addr, "missing-port", 12));
	T_EXPECT(!dialaddr_parse(&addr, "127.0.0.1:70000", 15));
}

T_DECLARE_CASE(dialaddr_set_and_copy)
{
	struct sockaddr_in in = {
		.sin_family = AF_INET,
		.sin_port = htons(UINT16_C(8080)),
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
	};
	struct sockaddr_in6 in6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(UINT16_C(8443)),
		.sin6_addr = in6addr_loopback,
	};
	struct dialaddr addr = { 0 };
	struct dialaddr copied = { 0 };
	char buf[128];

	T_EXPECT(dialaddr_set(&addr, (const struct sockaddr *)&in, sizeof(in)));
	T_EXPECT_EQ(addr.type, ATYP_INET);
	T_EXPECT_EQ(addr.port, UINT16_C(8080));
	T_EXPECT(dialaddr_set(
		&copied, (const struct sockaddr *)&in6, sizeof(in6)));
	T_EXPECT_EQ(copied.type, ATYP_INET6);
	T_EXPECT_EQ(copied.port, UINT16_C(8443));
	T_EXPECT(!dialaddr_set(
		&copied, (const struct sockaddr *)&in6, sizeof(in6) - 1));

	addr = (struct dialaddr){ 0 };
	addr.type = ATYP_DOMAIN;
	addr.port = UINT16_C(53);
	addr.domain.len = (uint_least8_t)strlen("resolver.local");
	(void)memcpy(addr.domain.name, "resolver.local", addr.domain.len);
	dialaddr_copy(&copied, &addr);
	T_EXPECT_EQ(copied.type, ATYP_DOMAIN);
	T_EXPECT_EQ(copied.port, UINT16_C(53));
	T_EXPECT_EQ(dialaddr_format(buf, sizeof(buf), &copied), 17);
	T_EXPECT_STREQ(buf, "resolver.local:53");
}

T_DECLARE_CASE(dialreq_parse_and_format_proxy_chain)
{
	struct dialreq *req = dialreq_parse(
		"example.com:443",
		"http://user:pass@127.0.0.1:8080,socks5://127.0.0.2");
	char buf[256];

	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->num_proxy, 2);
	T_EXPECT_EQ(req->proxy[0].proto, PROTO_HTTP);
	T_EXPECT_EQ(req->proxy[0].addr.type, ATYP_INET);
	T_EXPECT_EQ(req->proxy[0].addr.port, UINT16_C(8080));
	T_EXPECT_STREQ(req->proxy[0].username, "user");
	T_EXPECT_STREQ(req->proxy[0].password, "pass");
	T_EXPECT_EQ(req->proxy[1].proto, PROTO_SOCKS5);
	T_EXPECT_EQ(req->proxy[1].addr.port, UINT16_C(1080));
	T_EXPECT_EQ(req->proxy[1].username, NULL);
	T_EXPECT_EQ(dialreq_format(buf, sizeof(buf), req), 63);
	T_EXPECT_STREQ(
		buf,
		"http://127.0.0.1:8080->socks5://127.0.0.2:1080->example.com:443");
	dialreq_free(req);
}

T_DECLARE_CASE(dialreq_parse_scheme_default_ports)
{
	/* http defaults to port 80, socks4a/socks5 to 1080 when omitted. */
	struct dialreq *req =
		dialreq_parse("example.com:443", "http://127.0.0.1");
	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->num_proxy, 1);
	T_EXPECT_EQ(req->proxy[0].proto, PROTO_HTTP);
	T_EXPECT_EQ(req->proxy[0].addr.port, UINT16_C(80));
	dialreq_free(req);

	req = dialreq_parse("example.com:443", "socks4a://127.0.0.1");
	T_CHECK(req != NULL);
	T_EXPECT_EQ(req->proxy[0].proto, PROTO_SOCKS4A);
	T_EXPECT_EQ(req->proxy[0].addr.port, UINT16_C(1080));
	dialreq_free(req);
}

T_DECLARE_CASE(dialreq_parse_rejects_bad_proxy_uris)
{
	/* unknown scheme */
	T_EXPECT_EQ(
		dialreq_parse("example.com:443", "ftp://127.0.0.1:21"), NULL);
	/* missing scheme / unparseable */
	T_EXPECT_EQ(dialreq_parse("example.com:443", "127.0.0.1:1080"), NULL);
	/* port out of range */
	T_EXPECT_EQ(
		dialreq_parse("example.com:443", "http://127.0.0.1:99999"),
		NULL);
	/* non-numeric port */
	T_EXPECT_EQ(
		dialreq_parse("example.com:443", "http://127.0.0.1:abc"), NULL);
}

T_DECLARE_CASE(dialreq_parse_rejects_overlong_proxy_uri)
{
	char uri[1100];
	const int n = snprintf(uri, sizeof(uri), "socks5://");
	memset(uri + n, 'a', sizeof(uri) - 1 - (size_t)n);
	uri[sizeof(uri) - 1] = '\0';
	T_EXPECT_EQ(dialreq_parse("example.com:443", uri), NULL);
}

T_DECLARE_CASE(dialreq_replace_swaps_on_success)
{
	struct dialreq *req = dialreq_parse("example.com:443", NULL);
	T_CHECK(req != NULL);

	T_EXPECT(dialreq_replace(&req, "example.org:80", NULL));
	T_CHECK(req != NULL);
	char buf[64];
	T_EXPECT(dialreq_format(buf, sizeof(buf), req) > 0);
	T_EXPECT_STREQ(buf, "example.org:80");

	dialreq_free(req);
}

T_DECLARE_CASE(dialreq_replace_keeps_old_on_failure)
{
	struct dialreq *req = dialreq_parse("example.com:443", NULL);
	T_CHECK(req != NULL);
	struct dialreq *const original = req;

	/* unknown scheme: dialreq_parse fails, so req must be left untouched */
	T_EXPECT(!dialreq_replace(
		&req, "example.com:443", "ftp://127.0.0.1:21"));
	T_EXPECT_EQ(req, original);
	char buf[64];
	T_EXPECT(dialreq_format(buf, sizeof(buf), req) > 0);
	T_EXPECT_STREQ(buf, "example.com:443");

	dialreq_free(req);
}

T_DECLARE_CASE(dialreq_new_copies_base_request)
{
	struct dialreq *base = dialreq_parse(
		"example.com:443", "socks5://alice:secret@127.0.0.1");
	struct dialreq *copy;
	char buf[256];

	T_CHECK(base != NULL);
	copy = dialreq_new(base, 1);
	T_CHECK(copy != NULL);
	T_EXPECT_EQ(copy->num_proxy, 1);
	T_EXPECT_EQ(copy->proxy[0].proto, PROTO_SOCKS5);
	T_EXPECT_STREQ(copy->proxy[0].username, "alice");
	T_EXPECT_STREQ(copy->proxy[0].password, "secret");
	T_EXPECT_EQ(copy->proxy[0].addr.port, UINT16_C(1080));
	T_EXPECT_EQ(dialreq_format(buf, sizeof(buf), copy), 40);
	T_EXPECT_STREQ(buf, "socks5://127.0.0.1:1080->example.com:443");
	dialreq_free(copy);
	dialreq_free(base);
}

T_DECLARE_CASE(dialer_strerror_known_and_unknown)
{
	T_EXPECT_STREQ(dialer_strerror(DIALER_OK), "success");
	T_EXPECT_STREQ(
		dialer_strerror(DIALER_ERR_PROXY_AUTH),
		"proxy authentication failed");
	T_EXPECT_STREQ(
		dialer_strerror((enum dialer_error)DIALER_ERR_MAX),
		"unknown error");
}

T_DECLARE_CASE(direct_connect_reports_success)
{
	uint_fast16_t port = 0;
	const int listener_fd = make_listener(&port);
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char addr[32];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(addr, sizeof(addr), "127.0.0.1:%u", (unsigned)port) >
		0);
	req = dialreq_parse(addr, NULL);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SHORT_SEC,
		NULL, NULL);
	int accepted_fd =
		wait_for_accept(loop, listener_fd, TEST_WAIT_SHORT_SEC);
	int client_fd = result.fd;
	const bool accepted = accepted_fd >= 0;
	const bool has_client_fd = client_fd >= 0;
	const enum dialer_error err = d.err;
	close_if_open(&accepted_fd);
	close_if_open(&client_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	T_CHECK(close(listener_fd) == 0);

	T_EXPECT(completed);
	T_EXPECT(result.called);
	T_EXPECT(has_client_fd);
	T_EXPECT(accepted);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(local_address_blocked_by_egress_policy)
{
	struct config conf = test_conf;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req = dialreq_parse("10.0.0.1:9", NULL);

	T_CHECK(loop != NULL);
	T_CHECK(req != NULL);
	conf.block_local = true;
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SHORT_SEC,
		NULL, NULL);
	const enum dialer_error err = d.err;
	dialreq_free(req);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_BLOCKED);
	T_EXPECT_EQ(d.syserr, 0);
}

/*
 * Regression: sa_ipclassify() (vendored, read-only) has no IPv4-mapped
 * awareness, so an IPv4-mapped IPv6 literal was classified IPCLASS_GLOBAL
 * and sailed straight past block_local/block_loopback/block_multicast --
 * defeating the egress policy for anyone reaching it via a SOCKS5
 * ATYP_INET6 request (or a TPROXY dual-stack listener).
 */
T_DECLARE_CASE(v4_mapped_local_address_blocked_by_egress_policy)
{
	struct config conf = test_conf;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req = dialreq_parse("[::ffff:10.0.0.1]:9", NULL);

	T_CHECK(loop != NULL);
	T_CHECK(req != NULL);
	conf.block_local = true;
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SHORT_SEC,
		NULL, NULL);
	const enum dialer_error err = d.err;
	dialreq_free(req);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_BLOCKED);
	T_EXPECT_EQ(d.syserr, 0);
}

/*
 * Same gap, different flag: an IPv4-mapped loopback literal must be caught
 * by block_loopback specifically (not just block_local).
 */
T_DECLARE_CASE(v4_mapped_loopback_address_blocked_by_egress_policy)
{
	struct config conf = test_conf;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req = dialreq_parse("[::ffff:127.0.0.1]:9", NULL);

	T_CHECK(loop != NULL);
	T_CHECK(req != NULL);
	conf.block_loopback = true;
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SHORT_SEC,
		NULL, NULL);
	const enum dialer_error err = d.err;
	dialreq_free(req);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_BLOCKED);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(http_connect_success_sends_expected_request)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/1.1 200 Connection Established\r\n\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[128];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri),
			"http://user:pass@127.0.0.1:%u", (unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		proxy_server_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_STREQ(
		server.request,
		"CONNECT example.com:443 HTTP/1.1\r\n"
		"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n");
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/*
 * Regression: a proxy reply delivered one byte at a time (as a slow/adversarial
 * upstream hop might) must still be parsed correctly. dialer_recv() peeks
 * (MSG_PEEK) rather than consumes, and nothing is consumed until the status
 * line is complete; before the fix, re-peeking before any consume happened
 * re-added the same already-seen bytes into rbuf.len on every fragment
 * (triangular growth: len after k one-byte fragments ~= k*(k+1)/2). The
 * status line below is long enough (57 bytes to the first CRLF) that this
 * growth deterministically exceeds DIALER_RBUF_SIZE (1032) well before the
 * ~59 real bytes have arrived, tripping "response too long" (PROXY_PROTO)
 * even though the real response is tiny and entirely ordinary.
 */
T_DECLARE_CASE(http_connect_success_with_byte_at_a_time_response)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/1.1 200 Connection Established for "
			    "upstream target\r\n\r\n",
		.response_chunk = 1,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[128];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		proxy_server_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.response_sent);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(http_connect_407_maps_to_proxy_auth)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response =
			"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[96];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		proxy_server_pump, &server);
	const enum dialer_error err = d.err;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_AUTH);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(http_connect_403_maps_to_proxy_reject)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/1.1 403 Forbidden\r\n\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[96];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		proxy_server_pump, &server);
	const enum dialer_error err = d.err;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_REJECT);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(http_connect_502_maps_to_proxy_refused)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/1.1 502 Bad Gateway\r\n\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[96];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		proxy_server_pump, &server);
	const enum dialer_error err = d.err;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_REFUSED);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(http_connect_non_200_maps_to_proxy_proto)
{
	uint_fast16_t port = 0;
	int listener_fd = make_listener(&port);
	struct proxy_server server = {
		.listener_fd = listener_fd,
		.peer_fd = -1,
		.response = "HTTP/1.1 500 Internal Server Error\r\n\r\n",
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[96];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		proxy_server_pump, &server);
	const enum dialer_error err = d.err;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_PROTO);
	T_EXPECT_EQ(d.syserr, 0);
}

struct socks4_raw_server {
	int listener_fd;
	int peer_fd;
	unsigned char buf[512];
	size_t buf_len;
	bool request_complete;
	bool response_sent;
	bool failed;
	uint_least8_t rsp_code;
};

/* Returns true when a complete SOCKS4/4a request has been accumulated. */
static bool
socks4_request_complete(const unsigned char *restrict buf, const size_t len)
{
	const unsigned char *userid_end;

	if (len <= SOCKS4_HDR_LEN) {
		return false;
	}
	userid_end = memchr(buf + SOCKS4_HDR_LEN, '\0', len - SOCKS4_HDR_LEN);
	if (userid_end == NULL) {
		return false;
	}
	/* SOCKS4a: header IP 0.0.0.x (x != 0) means a domain name follows. */
	if (buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] != 0) {
		const unsigned char *const host_start = userid_end + 1;
		const size_t host_space =
			len - SOCKS4_HDR_LEN -
			(size_t)(host_start - (buf + SOCKS4_HDR_LEN));
		return memchr(host_start, '\0', host_space) != NULL;
	}
	return true;
}

static bool socks4_raw_pump(void *data)
{
	struct socks4_raw_server *const s = data;

	if (s->peer_fd < 0) {
		s->peer_fd = accept_nowait(s->listener_fd);
		if (s->peer_fd < 0) {
			return true;
		}
	}
	if (!s->request_complete) {
		const ssize_t n = recv_nowait(
			s->peer_fd, s->buf + s->buf_len,
			sizeof(s->buf) - s->buf_len);
		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				s->failed = true;
				return false;
			}
		} else if (n == 0) {
			s->failed = true;
			return false;
		} else {
			s->buf_len += (size_t)n;
		}
		if (socks4_request_complete(s->buf, s->buf_len)) {
			s->request_complete = true;
		}
	}
	if (s->request_complete && !s->response_sent) {
		const unsigned char rsp[SOCKS4_HDR_LEN] = {
			0, s->rsp_code, 0, 0, 0, 0, 0, 0,
		};
		if (!write_all(s->peer_fd, rsp, sizeof(rsp))) {
			s->failed = true;
			return false;
		}
		s->response_sent = true;
	}
	return true;
}

T_DECLARE_CASE(socks4a_rejected_maps_to_proxy_refused)
{
	uint_fast16_t port = 0;
	struct socks4_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.rsp_code = SOCKS4RSP_REJECTED,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks4a://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		socks4_raw_pump, &server);
	const enum dialer_error err = d.err;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_REFUSED);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(socks4a_granted_reports_success)
{
	uint_fast16_t port = 0;
	struct socks4_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.rsp_code = SOCKS4RSP_GRANTED,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks4a://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		socks4_raw_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.request_complete);
	T_EXPECT(server.response_sent);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

enum socks5_pump_phase {
	SOCKS5_PHASE_AUTH,
	SOCKS5_PHASE_USERPASS,
	SOCKS5_PHASE_CONNECT,
	SOCKS5_PHASE_DONE,
};

struct socks5_raw_server {
	int listener_fd;
	int peer_fd;
	unsigned char buf[512];
	size_t buf_len;
	enum socks5_pump_phase phase;
	bool response_sent;
	bool failed;
	uint_least8_t rsp_code;
	/* auth method offered in the negotiation reply (default 0 == NOAUTH) */
	uint_least8_t auth_method;
	/* additional handshakes to service on the same connection after the
	 * first, for a tunnelled multi-hop proxy chain (default 0) */
	int extra_hops;
};

static bool socks5_raw_pump(void *data)
{
	struct socks5_raw_server *const s = data;

	if (s->peer_fd < 0) {
		s->peer_fd = accept_nowait(s->listener_fd);
		if (s->peer_fd < 0) {
			return true;
		}
	}
	/* Once the CONNECT response has been sent, the handshake is complete. */
	if (s->phase == SOCKS5_PHASE_DONE) {
		return true;
	}
	const ssize_t n = recv_nowait(
		s->peer_fd, s->buf + s->buf_len, sizeof(s->buf) - s->buf_len);
	if (n < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			s->failed = true;
			return false;
		}
	} else if (n == 0) {
		if (s->phase != SOCKS5_PHASE_DONE) {
			s->failed = true;
			return false;
		}
	} else {
		s->buf_len += (size_t)n;
	}
	if (s->phase == SOCKS5_PHASE_AUTH) {
		/* Need: version(1) + nmethods(1) + methods(nmethods) */
		if (s->buf_len < 2) {
			return true;
		}
		const size_t auth_len = (size_t)2 + s->buf[1];
		if (s->buf_len < auth_len) {
			return true;
		}
		const unsigned char auth_rsp[2] = { SOCKS5, s->auth_method };
		if (!write_all(s->peer_fd, auth_rsp, sizeof(auth_rsp))) {
			s->failed = true;
			return false;
		}
		s->buf_len -= auth_len;
		memmove(s->buf, s->buf + auth_len, s->buf_len);
		s->phase = (s->auth_method == SOCKS5AUTH_USERPASS) ?
				   SOCKS5_PHASE_USERPASS :
				   SOCKS5_PHASE_CONNECT;
	}
	if (s->phase == SOCKS5_PHASE_USERPASS) {
		/* USERPASS sub-negotiation (RFC 1929):
		 * ver(1) ulen(1) uname(ulen) plen(1) passwd(plen) */
		if (s->buf_len < 2) {
			return true;
		}
		const size_t ulen = s->buf[1];
		if (s->buf_len < (size_t)2 + ulen + 1) {
			return true;
		}
		const size_t plen = s->buf[2 + ulen];
		const size_t up_len = (size_t)2 + ulen + 1 + plen;
		if (s->buf_len < up_len) {
			return true;
		}
		/* reply version 0x01, status 0x00 (success) */
		const unsigned char up_rsp[2] = { 0x01, 0x00 };
		if (!write_all(s->peer_fd, up_rsp, sizeof(up_rsp))) {
			s->failed = true;
			return false;
		}
		s->buf_len -= up_len;
		memmove(s->buf, s->buf + up_len, s->buf_len);
		s->phase = SOCKS5_PHASE_CONNECT;
	}
	if (s->phase == SOCKS5_PHASE_CONNECT) {
		/* SOCKS5 request: hdr(4) + addr_data + port(2) */
		if (s->buf_len < SOCKS5_HDR_LEN + 1) {
			return true;
		}
		size_t addr_len;
		switch (s->buf[3]) {
		case SOCKS5ADDR_IPV4:
			addr_len = sizeof(struct in_addr);
			break;
		case SOCKS5ADDR_IPV6:
			addr_len = sizeof(struct in6_addr);
			break;
		case SOCKS5ADDR_DOMAIN:
			addr_len = (size_t)1 + s->buf[SOCKS5_HDR_LEN];
			break;
		default:
			s->failed = true;
			return false;
		}
		const size_t req_len =
			SOCKS5_HDR_LEN + addr_len + sizeof(in_port_t);
		if (s->buf_len < req_len) {
			return true;
		}
		/* Respond with rsp_code; bind address 0.0.0.0:0 */
		const unsigned char connect_rsp
			[SOCKS5_HDR_LEN + sizeof(struct in_addr) +
			 sizeof(in_port_t)] = {
				SOCKS5, s->rsp_code, 0, SOCKS5ADDR_IPV4,
				0,	0,	     0, 0,
				0,	0,
			};
		if (!write_all(s->peer_fd, connect_rsp, sizeof(connect_rsp))) {
			s->failed = true;
			return false;
		}
		s->buf_len -= req_len;
		memmove(s->buf, s->buf + req_len, s->buf_len);
		s->response_sent = true;
		if (s->extra_hops > 0) {
			/* the dialer tunnels the next hop's SOCKS5 handshake
			 * over this same connection; negotiate again */
			s->extra_hops--;
			s->phase = SOCKS5_PHASE_AUTH;
		} else {
			s->phase = SOCKS5_PHASE_DONE;
		}
	}
	return true;
}

T_DECLARE_CASE(socks5_noallowed_maps_to_proxy_reject)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_NOALLOWED,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		socks5_raw_pump, &server);
	const enum dialer_error err = d.err;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.response_sent);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_REJECT);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(socks5_connect_success)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		socks5_raw_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.response_sent);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/* Regression: an over-255-byte SOCKS5 username must make send_socks5_auth
 * fail with a real error, not leave d.err at DIALER_OK (which socks.c maps to
 * SOCKS5RSP_SUCCEEDED, telling the client a failed dial succeeded). */
T_DECLARE_CASE(socks5_oversized_username_fails)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
		.auth_method = SOCKS5AUTH_USERPASS,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char longuser[300];
	char proxy_uri[512];

	T_CHECK(loop != NULL);
	memset(longuser, 'a', sizeof(longuser) - 1);
	longuser[sizeof(longuser) - 1] = '\0';
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri),
			"socks5://%s:p@127.0.0.1:%u", longuser,
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	(void)test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		socks5_raw_pump, &server);
	const enum dialer_error err = d.err;
	const bool called = result.called;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(called);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT(err != DIALER_OK);
}

/* Live multi-hop: the dialer must advance d->jump and re-run the SOCKS5
 * handshake over the tunnelled connection for each proxy in the chain. */
T_DECLARE_CASE(socks5_chain_two_hops_success)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
		.extra_hops = 1,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[128];

	T_CHECK(loop != NULL);
	/* first hop is the mock; the second hop address is never really dialed
	 * (the mock replies SUCCEEDED for it), it only drives a second
	 * handshake over the same connection */
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri),
			"socks5://127.0.0.1:%u,socks5://127.0.0.2:1080",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		socks5_raw_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT_EQ(server.extra_hops, 0);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/* Drive a full SOCKS5 USERPASS sub-negotiation to success: the mock offers
 * USERPASS, parses the credentials the dialer sends, and replies with a 0x00
 * status. Exercises recv_socks5_auth()'s happy path (version 0x01, status
 * 0x00 -> STATE_HANDSHAKE3), which the NOAUTH cases never reach. */
T_DECLARE_CASE(socks5_userpass_auth_success)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
		.auth_method = SOCKS5AUTH_USERPASS,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri),
			"socks5://user:pass@127.0.0.1:%u", (unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		socks5_raw_pump, &server);
	int client_fd = result.fd;
	const enum dialer_error err = d.err;
	close_if_open(&client_fd);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed);
	T_EXPECT(!server.failed);
	T_EXPECT(server.response_sent);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/* Regression: when we have no credentials we advertise only NOAUTH, so a
 * server selecting USERPASS picked a method we never offered. The dialer must
 * reject it as a protocol error rather than dereference the NULL username in
 * send_socks5_auth (a crash in release builds where the ASSERT is compiled
 * out). */
T_DECLARE_CASE(socks5_unoffered_userpass_maps_to_proxy_proto)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
		.auth_method = SOCKS5AUTH_USERPASS,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	/* no userinfo -> proxy->username == NULL -> only NOAUTH offered */
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	(void)test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		socks5_raw_pump, &server);
	const enum dialer_error err = d.err;
	const bool called = result.called;
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(called);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_PROTO);
}

/* Regression: a dialer completing a proxied dial leaves jump == num_proxy and
 * a stale dialed_fd. Re-driving it with a second dialer_do() (as
 * http_client's stale-connection cache-retry does) without dialer_init() must
 * reset that per-dial state; otherwise send_dispatch reads proxy[num_proxy]
 * out of bounds. */
T_DECLARE_CASE(socks5_redial_after_success_resets_state)
{
	uint_fast16_t port = 0;
	struct socks5_raw_server server = {
		.listener_fd = make_listener(&port),
		.peer_fd = -1,
		.phase = SOCKS5_PHASE_AUTH,
		.rsp_code = SOCKS5RSP_SUCCEEDED,
	};
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);

	/* first dial */
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed1 = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		socks5_raw_pump, &server);
	int client_fd1 = result.fd;
	T_EXPECT(completed1);
	T_EXPECT(!server.failed);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(d.err, DIALER_OK);
	close_if_open(&client_fd1);

	/* reset the mock to service a fresh connection for the second dial */
	close_if_open(&server.peer_fd);
	server.phase = SOCKS5_PHASE_AUTH;
	server.buf_len = 0;
	server.response_sent = false;

	/* second dial reuses the completed dialer without dialer_init() */
	result.called = false;
	result.fd = -1;
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed2 = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		socks5_raw_pump, &server);
	int client_fd2 = result.fd;
	const enum dialer_error err2 = d.err;
	close_if_open(&client_fd2);
	close_if_open(&server.peer_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	close_if_open(&server.listener_fd);

	T_EXPECT(completed2);
	T_EXPECT(!server.failed);
	T_EXPECT(result.fd >= 0);
	T_EXPECT_EQ(err2, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/* dialer_cancel() while a SOCKS5 handshake is still in flight must stop the
 * dialer, report DIALER_CANCELLED, and never invoke the finish callback. */
T_DECLARE_CASE(dialer_cancel_stops_in_flight_dial)
{
	uint_fast16_t port = 0;
	const int listener_fd = make_listener(&port);
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)port) > 0);
	/* the listener is never accepted/pumped, so the handshake cannot
	 * complete and the dialer stays in flight until we cancel it */
	req = dialreq_parse("example.com:443", proxy_uri);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	for (int i = 0; i < 4; i++) {
		ev_run(loop, EVRUN_NOWAIT);
	}
	T_EXPECT(!result.called);
	dialer_cancel(&d, loop);
	const enum dialer_error err = d.err;

	dialreq_free(req);
	ev_loop_destroy(loop);
	T_CHECK(close(listener_fd) == 0);

	T_EXPECT(!result.called);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_CANCELLED);
}

T_DECLARE_CASE(direct_connect_ipv6_reports_success)
{
	uint_fast16_t port = 0;
	const int listener_fd = make_listener6(&port);
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char addr[32];

	T_CHECK(loop != NULL);
	T_CHECK(snprintf(addr, sizeof(addr), "[::1]:%u", (unsigned)port) > 0);
	req = dialreq_parse(addr, NULL);
	T_CHECK(req != NULL);
	dialer_init(
		&d,
		&(struct dialer_cb){
			.func = dialer_finish_cb,
			.data = &result,
		},
		NULL, NULL);
	dialer_do(&d, loop, req, &test_conf, NULL, NULL);
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SHORT_SEC,
		NULL, NULL);
	int accepted_fd =
		wait_for_accept(loop, listener_fd, TEST_WAIT_SHORT_SEC);
	int client_fd = result.fd;
	const bool accepted = accepted_fd >= 0;
	const bool has_client_fd = client_fd >= 0;
	const enum dialer_error err = d.err;
	close_if_open(&accepted_fd);
	close_if_open(&client_fd);
	dialreq_free(req);
	ev_loop_destroy(loop);
	T_CHECK(close(listener_fd) == 0);

	T_EXPECT(completed);
	T_EXPECT(result.called);
	T_EXPECT(has_client_fd);
	T_EXPECT(accepted);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

/* Drive dialer with req, assert successful CONNECT accepted on final_fd;
 * both produced fds are closed on return. */
T_DECLARE_SUBCASE(
	expect_dial_success, struct ev_loop *restrict loop,
	struct dialreq *restrict req, const struct config *restrict conf,
	struct resolver *restrict resolver, const int final_fd)
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
	const bool completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		NULL, NULL);
	int client_fd = result.fd;
	const bool has_client_fd = client_fd >= 0;
	const enum dialer_error err = d.err;
	const int syserr = d.syserr;
	int accepted_fd =
		wait_for_accept(loop, final_fd, TEST_WAIT_RESPONSE_SEC);
	const bool has_accepted = accepted_fd >= 0;
	close_if_open(&accepted_fd);
	close_if_open(&client_fd);

	T_EXPECT(completed);
	T_EXPECT(has_client_fd);
	T_EXPECT(has_accepted);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(syserr, 0);
}

T_DECLARE_CASE(direct_connect_domain_resolves_and_succeeds)
{
	struct config conf = test_conf;
	uint_fast16_t final_port;
	int final_fd = make_listener(&final_port);
	struct ev_loop *loop = ev_loop_new(0);
	struct resolver *resolver;
	struct dialreq *req;
	char target_addr[32];

	T_CHECK(loop != NULL);
	conf.resolve_pf = PF_INET;
	resolver = resolver_new(loop, &conf);
	T_CHECK(resolver != NULL);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "localhost:%u",
			(unsigned)final_port) > 0);
	req = dialreq_parse(target_addr, NULL);
	T_CHECK(req != NULL);
	T_CALL_SUBCASE(
		expect_dial_success, loop, req, &conf, resolver, final_fd);
	dialreq_free(req);
	resolver_free(resolver);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(dialaddr_parse_and_format_variants),
	T_CASE(dialaddr_set_and_copy),
	T_CASE(dialreq_parse_and_format_proxy_chain),
	T_CASE(dialreq_parse_scheme_default_ports),
	T_CASE(dialreq_parse_rejects_bad_proxy_uris),
	T_CASE(dialreq_parse_rejects_overlong_proxy_uri),
	T_CASE(dialreq_replace_swaps_on_success),
	T_CASE(dialreq_replace_keeps_old_on_failure),
	T_CASE(dialreq_new_copies_base_request),
	T_CASE(dialer_strerror_known_and_unknown),
	T_CASE(direct_connect_reports_success),
	T_CASE(direct_connect_ipv6_reports_success),
	T_CASE(local_address_blocked_by_egress_policy),
	T_CASE(v4_mapped_local_address_blocked_by_egress_policy),
	T_CASE(v4_mapped_loopback_address_blocked_by_egress_policy),
	T_CASE(http_connect_success_sends_expected_request),
	T_CASE(http_connect_success_with_byte_at_a_time_response),
	T_CASE(http_connect_407_maps_to_proxy_auth),
	T_CASE(http_connect_403_maps_to_proxy_reject),
	T_CASE(http_connect_502_maps_to_proxy_refused),
	T_CASE(http_connect_non_200_maps_to_proxy_proto),
	T_CASE(socks4a_rejected_maps_to_proxy_refused),
	T_CASE(socks4a_granted_reports_success),
	T_CASE(socks5_noallowed_maps_to_proxy_reject),
	T_CASE(socks5_connect_success),
	T_CASE(socks5_oversized_username_fails),
	T_CASE(socks5_userpass_auth_success),
	T_CASE(socks5_unoffered_userpass_maps_to_proxy_proto),
	T_CASE(socks5_redial_after_success_resets_state),
	T_CASE(socks5_chain_two_hops_success),
	T_CASE(dialer_cancel_stops_in_flight_dial),
	T_CASE(direct_connect_domain_resolves_and_succeeds),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	resolver_init();
	const int ret = testing_main(argc, argv, suite);
	resolver_cleanup();
	return ret;
}
