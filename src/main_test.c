/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * main_test - black-box / integration tests against the real modules.
 *
 * Unlike the per-module {M}_test.c files, which isolate a single module and
 * mock its collaborators, this test links the real implementations together
 * and exercises them end to end. It also hosts the project fuzz suite.
 *
 * Linked translation units (see CMakeLists.txt):
 *   dialer.c, socks.c, http_proxy.c, server.c, transfer.c,
 *   resolver.c, util.c, proto/http.c, proto/codec.c, version.c
 * The ruleset host and the server's forward/api/tproxy entry points are the
 * only collaborators stubbed (see the mock section), so the dialer can reach
 * the real socks/http proxy handlers over loopback.
 */

#include "dialer.h"

#include "api_server.h"
#include "conf.h"
#include "forward.h"
#include "proto/codec.h"
#include "proto/http.h"
#include "proto/socks.h"
#include "resolver.h"
#if WITH_RULESET
#include "ruleset.h"
#endif
#include "server.h"
#include "socks.h"
#include "transfer.h"
#include "util.h"

#include "io/memory.h"
#include "io/stream.h"
#include "utils/buffer.h"
#include "utils/gc.h"

#include "utils/testing.h"

#include <ev.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* -------------------------------------------------------------------------
 * mock - the ruleset host and the server's forward/api/tproxy entry points are
 * stubbed; everything else is the real module. Shared fixtures live here too.
 * ---------------------------------------------------------------------- */

static struct config test_conf = {
	.timeout = 0.2,
};

static struct config proxy_conf = {
	.timeout = 0.5,
};

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

static const ev_tstamp TEST_WAIT_SHORT_SEC = 0.064;
static const ev_tstamp TEST_WAIT_RESPONSE_SEC = 0.256;

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

static int make_listener(uint_least16_t *restrict port)
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

static int make_listener6(uint_least16_t *restrict port)
{
	const int fd = socket(AF_INET6, SOCK_STREAM, 0);
	const int enable = 1;
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
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
		if (!write_all(
			    server->peer_fd, server->response,
			    strlen(server->response))) {
			server->failed = true;
			return false;
		}
		server->response_sent = true;
	}
	return true;
}

/* -------------------------------------------------------------------------
 * regression - dialer unit checks and end-to-end CONNECT through the real
 * socks/http proxy handlers (direct, single-hop and chained).
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
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
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
	uint_least16_t port = 0;
	const int listener_fd = make_listener(&port);
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char addr[32];
	bool completed;
	int accepted_fd;
	int client_fd;
	bool accepted;
	bool has_client_fd;
	enum dialer_error err;

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
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SHORT_SEC,
		NULL, NULL);
	accepted_fd = wait_for_accept(loop, listener_fd, TEST_WAIT_SHORT_SEC);
	client_fd = result.fd;
	accepted = accepted_fd >= 0;
	has_client_fd = client_fd >= 0;
	err = d.err;
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
	bool completed;
	enum dialer_error err;

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
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SHORT_SEC,
		NULL, NULL);
	err = d.err;
	dialreq_free(req);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_BLOCKED);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(http_connect_success_sends_expected_request)
{
	uint_least16_t port = 0;
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
	bool completed;
	int client_fd;
	enum dialer_error err;

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
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		proxy_server_pump, &server);
	client_fd = result.fd;
	err = d.err;
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

T_DECLARE_CASE(http_connect_407_maps_to_proxy_auth)
{
	uint_least16_t port = 0;
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
	bool completed;
	enum dialer_error err;

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
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		proxy_server_pump, &server);
	err = d.err;
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

/* mock (cont.) - ruleset host stubs and the real-proxy fixtures below. */
#if WITH_RULESET
void ruleset_cancel(struct ev_loop *loop, struct ruleset_state *restrict state)
{
	(void)loop;
	(void)state;
}

bool ruleset_resolve(
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

bool ruleset_loadconfig(
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
 * use_http; conf must outlive the server. */
static uint_least16_t start_proxy_ex(
	struct server *restrict s, struct ev_loop *restrict loop,
	const bool use_http, struct config *restrict conf,
	struct resolver *restrict resolver)
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

	T_CHECK(server_init(
		s, loop, conf, resolver, transfer_create(loop, 1), NULL, NULL));
	T_CHECK(getsockname(
			s->listeners[0].w_accept.fd,
			(struct sockaddr *)&bound_addr, &len) == 0);
	return ntohs(bound_addr.sin_port);
}

static uint_least16_t start_proxy(
	struct server *restrict s, struct ev_loop *restrict loop,
	const bool use_http, struct config *restrict conf)
{
	return start_proxy_ex(s, loop, use_http, conf, NULL);
}

static void stop_proxy(struct server *restrict s)
{
	server_stop(s);
	gc_finalizeall();
	transfer_join(s->xfer);
	s->xfer = NULL;
}

/* Run the event loop for the given duration to allow sessions to drain. */
static void drain_loop(struct ev_loop *restrict loop, const ev_tstamp sec)
{
	struct test_watchdog watchdog = { 0 };
	struct ev_timer w_timer;

	ev_timer_init(&w_timer, test_watchdog_cb, sec, 0.0);
	w_timer.data = &watchdog;
	ev_timer_start(loop, &w_timer);
	while (!watchdog.fired) {
		ev_run(loop, EVRUN_ONCE);
	}
}

/* Bind a listener on an ephemeral loopback port, immediately close it, and
 * return the port so that any connection attempt will be refused. */
static uint_least16_t make_closed_port(void)
{
	uint_least16_t port = 0;
	const int fd = make_listener(&port);

	T_CHECK(close(fd) == 0);
	return port;
}

T_DECLARE_CASE(socks5_connect_success_via_real_proxy)
{
	uint_least16_t proxy_port, final_port;
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
	proxy_port = start_proxy(&proxy_s, loop, false, &proxy_conf);
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
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		NULL, NULL);
	client_fd = result.fd;
	has_client_fd = client_fd >= 0;
	err = d.err;
	accepted_fd = accept_nowait(final_fd);
	has_accepted = accepted_fd >= 0;
	close_if_open(&accepted_fd);
	close_if_open(&client_fd);
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);

	T_EXPECT(completed);
	T_EXPECT(has_client_fd);
	T_EXPECT(has_accepted);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(socks5_connrefused_proxied_correctly)
{
	uint_least16_t proxy_port;
	const uint_least16_t closed_port = make_closed_port();
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64], target_addr[32];
	bool completed;
	enum dialer_error err;

	T_CHECK(loop != NULL);
	proxy_port = start_proxy(&proxy_s, loop, false, &proxy_conf);
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
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		NULL, NULL);
	err = d.err;
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_REFUSED);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(socks5_noauth_rejected_when_auth_required)
{
	struct config auth_conf = proxy_conf;
	uint_least16_t proxy_port;
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
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		NULL, NULL);
	err = d.err;
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_AUTH);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(socks5_credentials_accepted_when_auth_required)
{
	struct config auth_conf = proxy_conf;
	uint_least16_t proxy_port, final_port;
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
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		NULL, NULL);
	client_fd = result.fd;
	has_client_fd = client_fd >= 0;
	err = d.err;
	accepted_fd = accept_nowait(final_fd);
	has_accepted = accepted_fd >= 0;
	close_if_open(&accepted_fd);
	close_if_open(&client_fd);
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);

	T_EXPECT(completed);
	T_EXPECT(has_client_fd);
	T_EXPECT(has_accepted);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(socks4a_connect_success_via_real_proxy)
{
	uint_least16_t proxy_port, final_port;
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
	proxy_port = start_proxy(&proxy_s, loop, false, &proxy_conf);
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
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		NULL, NULL);
	client_fd = result.fd;
	has_client_fd = client_fd >= 0;
	err = d.err;
	accepted_fd = accept_nowait(final_fd);
	has_accepted = accepted_fd >= 0;
	close_if_open(&accepted_fd);
	close_if_open(&client_fd);
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);

	T_EXPECT(completed);
	T_EXPECT(has_client_fd);
	T_EXPECT(has_accepted);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(http_proxy_connect_success_via_real_proxy)
{
	uint_least16_t proxy_port, final_port;
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
	proxy_port = start_proxy(&proxy_s, loop, true, &proxy_conf);
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
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		NULL, NULL);
	client_fd = result.fd;
	has_client_fd = client_fd >= 0;
	err = d.err;
	accepted_fd = accept_nowait(final_fd);
	has_accepted = accepted_fd >= 0;
	close_if_open(&accepted_fd);
	close_if_open(&client_fd);
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);

	T_EXPECT(completed);
	T_EXPECT(has_client_fd);
	T_EXPECT(has_accepted);
	T_EXPECT_EQ(err, DIALER_OK);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(http_connect_403_maps_to_proxy_reject)
{
	uint_least16_t port = 0;
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
	bool completed;
	enum dialer_error err;

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
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		proxy_server_pump, &server);
	err = d.err;
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
	uint_least16_t port = 0;
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
	bool completed;
	enum dialer_error err;

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
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		proxy_server_pump, &server);
	err = d.err;
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
	uint_least16_t port = 0;
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
	bool completed;
	enum dialer_error err;

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
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		proxy_server_pump, &server);
	err = d.err;
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
	unsigned char rsp_code;
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
	ssize_t n;

	if (s->peer_fd < 0) {
		s->peer_fd = accept_nowait(s->listener_fd);
		if (s->peer_fd < 0) {
			return true;
		}
	}
	if (!s->request_complete) {
		n = recv_nowait(
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
	uint_least16_t port = 0;
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
	bool completed;
	enum dialer_error err;

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
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		socks4_raw_pump, &server);
	err = d.err;
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

enum socks5_pump_phase {
	SOCKS5_PHASE_AUTH,
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
	unsigned char rsp_code;
};

static bool socks5_raw_pump(void *data)
{
	struct socks5_raw_server *const s = data;
	ssize_t n;
	size_t addr_len;
	size_t req_len;

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
	n = recv_nowait(
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
		const unsigned char auth_rsp[2] = { SOCKS5, SOCKS5AUTH_NOAUTH };
		if (!write_all(s->peer_fd, auth_rsp, sizeof(auth_rsp))) {
			s->failed = true;
			return false;
		}
		s->buf_len -= auth_len;
		memmove(s->buf, s->buf + auth_len, s->buf_len);
		s->phase = SOCKS5_PHASE_CONNECT;
	}
	if (s->phase == SOCKS5_PHASE_CONNECT) {
		/* SOCKS5 request: hdr(4) + addr_data + port(2) */
		if (s->buf_len < SOCKS5_HDR_LEN + 1) {
			return true;
		}
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
		req_len = SOCKS5_HDR_LEN + addr_len + sizeof(in_port_t);
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
		s->phase = SOCKS5_PHASE_DONE;
		s->response_sent = true;
	}
	return true;
}

T_DECLARE_CASE(socks5_noallowed_maps_to_proxy_reject)
{
	uint_least16_t port = 0;
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
	bool completed;
	enum dialer_error err;

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
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		socks5_raw_pump, &server);
	err = d.err;
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

T_DECLARE_CASE(http_proxy_connrefused_proxied_correctly)
{
	uint_least16_t proxy_port;
	const uint_least16_t closed_port = make_closed_port();
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char proxy_uri[64], target_addr[32];
	bool completed;
	enum dialer_error err;

	T_CHECK(loop != NULL);
	proxy_port = start_proxy(&proxy_s, loop, true, &proxy_conf);
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
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		NULL, NULL);
	err = d.err;
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_REFUSED);
	T_EXPECT_EQ(d.syserr, 0);
}

T_DECLARE_CASE(direct_connect_ipv6_reports_success)
{
	uint_least16_t port = 0;
	const int listener_fd = make_listener6(&port);
	struct ev_loop *loop = ev_loop_new(0);
	struct dialer_result result = { .fd = -1 };
	struct dialer d;
	struct dialreq *req;
	char addr[32];
	bool completed;
	int accepted_fd;
	int client_fd;
	bool accepted;
	bool has_client_fd;
	enum dialer_error err;

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
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_SHORT_SEC,
		NULL, NULL);
	accepted_fd = wait_for_accept(loop, listener_fd, TEST_WAIT_SHORT_SEC);
	client_fd = result.fd;
	accepted = accepted_fd >= 0;
	has_client_fd = client_fd >= 0;
	err = d.err;
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

/* Drive the dialer with @p req until completion and assert a successful
 * CONNECT whose final hop is accepted on @p final_fd. The client uses @p conf
 * (with optional @p resolver for domain targets). Both produced fds are
 * closed before returning. */
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

T_DECLARE_CASE(socks5_connect_ipv6_target_via_real_proxy)
{
	uint_least16_t proxy_port, final_port;
	int final_fd = make_listener6(&final_port);
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialreq *req;
	char proxy_uri[64], target_addr[48];

	T_CHECK(loop != NULL);
	proxy_port = start_proxy(&proxy_s, loop, false, &proxy_conf);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "[::1]:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	T_CALL_SUBCASE(
		expect_dial_success, loop, req, &test_conf, NULL, final_fd);
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
}

T_DECLARE_CASE(http_proxy_connect_ipv6_target_via_real_proxy)
{
	uint_least16_t proxy_port, final_port;
	int final_fd = make_listener6(&final_port);
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialreq *req;
	char proxy_uri[64], target_addr[48];

	T_CHECK(loop != NULL);
	proxy_port = start_proxy(&proxy_s, loop, true, &proxy_conf);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "[::1]:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "http://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	T_CALL_SUBCASE(
		expect_dial_success, loop, req, &test_conf, NULL, final_fd);
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
}

T_DECLARE_CASE(http_proxy_connect_with_credentials_via_real_proxy)
{
	uint_least16_t proxy_port, final_port;
	int final_fd = make_listener(&final_port);
	struct server proxy_s;
	struct ev_loop *loop = ev_loop_new(0);
	struct dialreq *req;
	char proxy_uri[128], target_addr[32];

	T_CHECK(loop != NULL);
	proxy_port = start_proxy(&proxy_s, loop, true, &proxy_conf);
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
	T_CALL_SUBCASE(
		expect_dial_success, loop, req, &test_conf, NULL, final_fd);
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	stop_proxy(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
}

/* Chain two real proxies of the given protocols and assert an end-to-end
 * CONNECT to a final loopback listener succeeds. This exercises the dialer's
 * multi-hop traversal against real server handshakes. */
T_DECLARE_SUBCASE(
	run_chain_success, const bool first_http, const bool second_http)
{
	uint_least16_t port1, port2, final_port;
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
	T_CALL_SUBCASE(
		expect_dial_success, loop, req, &test_conf, NULL, final_fd);
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	stop_proxy(&proxy2);
	stop_proxy(&proxy1);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
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

T_DECLARE_CASE(direct_connect_domain_resolves_and_succeeds)
{
	struct config conf = test_conf;
	uint_least16_t final_port;
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

T_DECLARE_CASE(socks5_connect_domain_target_via_real_proxy)
{
	struct config server_conf = proxy_conf;
	uint_least16_t proxy_port, final_port;
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
	proxy_port =
		start_proxy_ex(&proxy_s, loop, false, &server_conf, resolver);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "localhost:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks5://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	T_CALL_SUBCASE(
		expect_dial_success, loop, req, &test_conf, NULL, final_fd);
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	stop_proxy(&proxy_s);
	resolver_free(resolver);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
}

/* SOCKS4a has no native IPv6: the client encodes an IPv6 target as a textual
 * hostname ("::1"). The proxy parses it as a domain and resolves it. */
T_DECLARE_CASE(socks4a_connect_ipv6_target_via_real_proxy)
{
	struct config server_conf = proxy_conf;
	uint_least16_t proxy_port, final_port;
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
	proxy_port =
		start_proxy_ex(&proxy_s, loop, false, &server_conf, resolver);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "[::1]:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks4a://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	T_CALL_SUBCASE(
		expect_dial_success, loop, req, &test_conf, NULL, final_fd);
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	stop_proxy(&proxy_s);
	resolver_free(resolver);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
}

T_DECLARE_CASE(socks4a_connect_domain_target_via_real_proxy)
{
	struct config server_conf = proxy_conf;
	uint_least16_t proxy_port, final_port;
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
	proxy_port =
		start_proxy_ex(&proxy_s, loop, false, &server_conf, resolver);
	T_CHECK(snprintf(
			target_addr, sizeof(target_addr), "localhost:%u",
			(unsigned)final_port) > 0);
	T_CHECK(snprintf(
			proxy_uri, sizeof(proxy_uri), "socks4a://127.0.0.1:%u",
			(unsigned)proxy_port) > 0);
	req = dialreq_parse(target_addr, proxy_uri);
	T_CHECK(req != NULL);
	T_CALL_SUBCASE(
		expect_dial_success, loop, req, &test_conf, NULL, final_fd);
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	stop_proxy(&proxy_s);
	resolver_free(resolver);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);
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

static void close_checked(int *restrict fd)
{
	if (*fd < 0) {
		return;
	}
	const int closing = *fd;
	*fd = -1;
	T_CHECK(close(closing) == 0);
}

static void drain_stream(struct stream *restrict s)
{
	size_t total = 0;
	for (;;) {
		unsigned char out[1024];
		size_t len = sizeof(out);
		const int err = stream_read(s, out, &len);
		if (err != 0 || len == 0) {
			break;
		}
		total += len;
		if (total >= FUZZ_MAX_STREAM_OUTPUT) {
			break;
		}
	}
}

typedef struct stream *(*codec_reader_fn)(struct stream *base);

static void
fuzz_codec_reader(struct prng *restrict p, codec_reader_fn new_reader)
{
	unsigned char input[FUZZ_MAX_CODEC_INPUT];
	const size_t len = prng_size(p, 0, sizeof(input));
	prng_fill(p, input, len);

	struct stream *const base = io_memreader(input, len);
	T_CHECK(base != NULL);
	struct stream *const reader = new_reader(base);
	if (reader == NULL) {
		return;
	}
	drain_stream(reader);
	/* Malformed fuzz inputs may be rejected during close-time validation. */
	(void)stream_close(reader);
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
	if (strcasecmp(key, "TE") == 0) {
		return parsehdr_accept_te(c->conn, value);
	}
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
	struct header_cb_ctx cbctx = {
		.conn = &conn,
	};
	const struct http_parsehdr_cb cb = {
		.func = parse_header_cb,
		.ctx = &cbctx,
	};
	unsigned char input[FUZZ_MAX_HTTP_INPUT];
	const size_t len = prng_size(p, 0, sizeof(input));
	prng_fill(p, input, len);

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
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
	close_checked(&sv[0]);
	close_checked(&sv[1]);
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

#define CALL_PARSEHDR(fn)                                                      \
	do {                                                                   \
		(void)memcpy(copy, value, len + 1);                            \
		(void)fn(&conn, copy);                                         \
	} while (0)
	CALL_PARSEHDR(parsehdr_accept_te);
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
	UNUSED(_t_);

	struct prng p;
	prng_seed(&p, fuzz_case_seed(1));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_codec_reader(&p, codec_inflate_reader);
	}
}

T_DECLARE_CASE(fuzz_zlib)
{
	UNUSED(_t_);

	struct prng p;
	prng_seed(&p, fuzz_case_seed(2));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_codec_reader(&p, codec_zlib_reader);
	}
}

T_DECLARE_CASE(fuzz_gzip)
{
	UNUSED(_t_);

	struct prng p;
	prng_seed(&p, fuzz_case_seed(3));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_codec_reader(&p, codec_gzip_reader);
	}
}

T_DECLARE_CASE(fuzz_http_req)
{
	UNUSED(_t_);

	struct prng p;
	prng_seed(&p, fuzz_case_seed(4));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_http_conn(&p, STATE_PARSE_REQUEST);
	}
}

T_DECLARE_CASE(fuzz_http_resp)
{
	UNUSED(_t_);

	struct prng p;
	prng_seed(&p, fuzz_case_seed(5));
	for (size_t i = 0; i < fuzz_iterations; i++) {
		fuzz_http_conn(&p, STATE_PARSE_RESPONSE);
	}
}

T_DECLARE_CASE(fuzz_parsehdr)
{
	UNUSED(_t_);

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

int main(void)
{
	fuzz_seed = read_seed();
	fuzz_iterations = read_iterations();
	(void)fprintf(
		stderr, "fuzz seed=0x%016" PRIx64 " iter=%zu\n", fuzz_seed,
		fuzz_iterations);

	T_DECLARE_CTX(t);
	resolver_init();
	T_RUN_CASE(t, dialaddr_parse_and_format_variants);
	T_RUN_CASE(t, dialaddr_set_and_copy);
	T_RUN_CASE(t, dialreq_parse_and_format_proxy_chain);
	T_RUN_CASE(t, dialreq_parse_scheme_default_ports);
	T_RUN_CASE(t, dialreq_parse_rejects_bad_proxy_uris);
	T_RUN_CASE(t, dialreq_parse_rejects_overlong_proxy_uri);
	T_RUN_CASE(t, dialreq_new_copies_base_request);
	T_RUN_CASE(t, dialer_strerror_known_and_unknown);
	T_RUN_CASE(t, direct_connect_reports_success);
	T_RUN_CASE(t, direct_connect_ipv6_reports_success);
	T_RUN_CASE(t, local_address_blocked_by_egress_policy);
	T_RUN_CASE(t, http_connect_success_sends_expected_request);
	T_RUN_CASE(t, http_connect_407_maps_to_proxy_auth);
	T_RUN_CASE(t, socks5_connect_success_via_real_proxy);
	T_RUN_CASE(t, socks5_connrefused_proxied_correctly);
	T_RUN_CASE(t, socks5_noauth_rejected_when_auth_required);
	T_RUN_CASE(t, socks5_credentials_accepted_when_auth_required);
	T_RUN_CASE(t, socks4a_connect_success_via_real_proxy);
	T_RUN_CASE(t, http_proxy_connect_success_via_real_proxy);
	T_RUN_CASE(t, http_proxy_connrefused_proxied_correctly);
	T_RUN_CASE(t, http_connect_403_maps_to_proxy_reject);
	T_RUN_CASE(t, http_connect_502_maps_to_proxy_refused);
	T_RUN_CASE(t, http_connect_non_200_maps_to_proxy_proto);
	T_RUN_CASE(t, socks4a_rejected_maps_to_proxy_refused);
	T_RUN_CASE(t, socks5_noallowed_maps_to_proxy_reject);
	T_RUN_CASE(t, socks5_connect_ipv6_target_via_real_proxy);
	T_RUN_CASE(t, http_proxy_connect_ipv6_target_via_real_proxy);
	T_RUN_CASE(t, http_proxy_connect_with_credentials_via_real_proxy);
	T_RUN_CASE(t, chain_socks5_to_http_connect_success);
	T_RUN_CASE(t, chain_http_to_socks5_connect_success);
	T_RUN_CASE(t, chain_socks5_to_socks5_connect_success);
	T_RUN_CASE(t, direct_connect_domain_resolves_and_succeeds);
	T_RUN_CASE(t, socks5_connect_domain_target_via_real_proxy);
	T_RUN_CASE(t, socks4a_connect_ipv6_target_via_real_proxy);
	T_RUN_CASE(t, socks4a_connect_domain_target_via_real_proxy);

	T_RUN_CASE(t, fuzz_inflate);
	T_RUN_CASE(t, fuzz_zlib);
	T_RUN_CASE(t, fuzz_gzip);
	T_RUN_CASE(t, fuzz_http_req);
	T_RUN_CASE(t, fuzz_http_resp);
	T_RUN_CASE(t, fuzz_parsehdr);

	const bool ok = T_RESULT(t);
	resolver_cleanup();
	return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
