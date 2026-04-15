/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "dialer.h"

#include "api_server.h"
#include "conf.h"
#include "forward.h"
#if WITH_RULESET
#include "ruleset.h"
#endif
#include "server.h"
#include "transfer.h"

#include "utils/testing.h"

#include <ev.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
		&d, &(struct dialer_cb){
			    .func = dialer_finish_cb,
			    .data = &result,
		    });
	dialer_do(&d, loop, req, &test_conf, NULL);
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
		&d, &(struct dialer_cb){
			    .func = dialer_finish_cb,
			    .data = &result,
		    });
	dialer_do(&d, loop, req, &conf, NULL);
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
		&d, &(struct dialer_cb){
			    .func = dialer_finish_cb,
			    .data = &result,
		    });
	dialer_do(&d, loop, req, &test_conf, NULL);
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
		&d, &(struct dialer_cb){
			    .func = dialer_finish_cb,
			    .data = &result,
		    });
	dialer_do(&d, loop, req, &test_conf, NULL);
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

bool ruleset_loadfile(struct ruleset *restrict r, const char *restrict filename)
{
	(void)r;
	(void)filename;
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

#if WITH_LUA
bool conf_loadfile(
	const char *restrict path, const int argc,
	const char *const restrict argv[const restrict],
	struct config *restrict conf)
{
	(void)path;
	(void)argc;
	(void)argv;
	(void)conf;
	return false;
}
#endif /* WITH_LUA */

bool conf_reload(struct config *restrict conf)
{
	(void)conf;
	return false;
}

/* Start a proxy server on an ephemeral loopback port and return that port.
 * Sets conf->listen or conf->http_listen to "127.0.0.1:0" depending on
 * use_http; conf must outlive the server. */
static uint_least16_t start_proxy(
	struct server *restrict s, struct ev_loop *restrict loop,
	const bool use_http, struct config *restrict conf)
{
	if (use_http) {
		conf->listen = NULL;
		conf->http_listen = "127.0.0.1:0";
	} else {
		conf->listen = "127.0.0.1:0";
		conf->http_listen = NULL;
	}
	struct sockaddr_in bound_addr;
	socklen_t len = sizeof(bound_addr);

	T_CHECK(server_init(s, loop, conf, NULL, NULL, NULL));
	T_CHECK(getsockname(
			s->listeners[0].w_accept.fd,
			(struct sockaddr *)&bound_addr, &len) == 0);
	return ntohs(bound_addr.sin_port);
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
		&d, &(struct dialer_cb){
			    .func = dialer_finish_cb,
			    .data = &result,
		    });
	dialer_do(&d, loop, req, &test_conf, NULL);
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
	server_stop(&proxy_s);
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
		&d, &(struct dialer_cb){
			    .func = dialer_finish_cb,
			    .data = &result,
		    });
	dialer_do(&d, loop, req, &test_conf, NULL);
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		NULL, NULL);
	err = d.err;
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	server_stop(&proxy_s);
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
		&d, &(struct dialer_cb){
			    .func = dialer_finish_cb,
			    .data = &result,
		    });
	dialer_do(&d, loop, req, &test_conf, NULL);
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		NULL, NULL);
	err = d.err;
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	server_stop(&proxy_s);
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
		&d, &(struct dialer_cb){
			    .func = dialer_finish_cb,
			    .data = &result,
		    });
	dialer_do(&d, loop, req, &test_conf, NULL);
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
	server_stop(&proxy_s);
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
		&d, &(struct dialer_cb){
			    .func = dialer_finish_cb,
			    .data = &result,
		    });
	dialer_do(&d, loop, req, &test_conf, NULL);
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
	server_stop(&proxy_s);
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
		&d, &(struct dialer_cb){
			    .func = dialer_finish_cb,
			    .data = &result,
		    });
	dialer_do(&d, loop, req, &test_conf, NULL);
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
	server_stop(&proxy_s);
	ev_loop_destroy(loop);
	T_CHECK(close(final_fd) == 0);

	T_EXPECT(completed);
	T_EXPECT(has_client_fd);
	T_EXPECT(has_accepted);
	T_EXPECT_EQ(err, DIALER_OK);
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
		&d, &(struct dialer_cb){
			    .func = dialer_finish_cb,
			    .data = &result,
		    });
	dialer_do(&d, loop, req, &test_conf, NULL);
	completed = test_wait_until(
		loop, dialer_called_predicate, &result, TEST_WAIT_RESPONSE_SEC,
		NULL, NULL);
	err = d.err;
	dialreq_free(req);
	drain_loop(loop, TEST_WAIT_SHORT_SEC);
	server_stop(&proxy_s);
	ev_loop_destroy(loop);

	T_EXPECT(completed);
	T_EXPECT_EQ(result.fd, -1);
	T_EXPECT_EQ(err, DIALER_ERR_PROXY_REFUSED);
	T_EXPECT_EQ(d.syserr, 0);
}

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, dialaddr_parse_and_format_variants);
	T_RUN_CASE(t, dialaddr_set_and_copy);
	T_RUN_CASE(t, dialreq_parse_and_format_proxy_chain);
	T_RUN_CASE(t, dialreq_new_copies_base_request);
	T_RUN_CASE(t, dialer_strerror_known_and_unknown);
	T_RUN_CASE(t, direct_connect_reports_success);
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
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
