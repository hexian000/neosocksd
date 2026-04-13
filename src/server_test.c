/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "server.h"

#include "conf.h"
#include "os/socket.h"
#include "utils/testing.h"

#include <arpa/inet.h>
#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

void socket_set_transparent(const int fd, const bool tproxy)
{
	(void)fd;
	(void)tproxy;
}

static struct config make_conf(void)
{
	return (struct config){
		.timeout = 1.0,
		.tcp_nodelay = true,
		.tcp_keepalive = true,
	};
}

struct test_watchdog {
	bool fired;
};

struct serve_ctx {
	int calls;
};

static void
watchdog_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	struct test_watchdog *const watchdog = watcher->data;

	(void)revents;
	watchdog->fired = true;
	ev_break(loop, EVBREAK_ONE);
}

static bool test_wait_until(
	struct ev_loop *loop, bool (*predicate)(void *), void *data,
	const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	ev_timer w_timeout;

	ev_timer_init(&w_timeout, watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	while (!watchdog.fired) {
		if (predicate(data)) {
			ev_timer_stop(loop, &w_timeout);
			return true;
		}
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_timeout);
	return predicate(data);
}

static void set_loopback_addr(struct sockaddr_in *restrict addr)
{
	*addr = (struct sockaddr_in){
		.sin_family = AF_INET,
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
		.sin_port = 0,
	};
}

static uint16_t bound_port(const int fd)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	T_CHECK(getsockname(fd, (struct sockaddr *)&addr, &len) == 0);
	return ntohs(addr.sin_port);
}

static int connect_loopback(const uint16_t port)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr;

	T_CHECK(fd >= 0);
	addr = (struct sockaddr_in){
		.sin_family = AF_INET,
		.sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
		.sin_port = htons(port),
	};
	T_CHECK(connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0);
	return fd;
}

static bool served_once(void *data)
{
	const struct serve_ctx *ctx = data;
	return ctx->calls == 1;
}

static bool accepted_once(void *data)
{
	const struct server *s = data;
	return s->listeners[0].stats.num_accept == 1;
}

static void serve_cb(
	struct server *s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	struct serve_ctx *ctx = s->data;

	(void)loop;
	(void)accepted_sa;
	ctx->calls++;
	CLOSE_FD(accepted_fd);
}

T_DECLARE_CASE(test_server_start_accept_and_stop)
{
	struct ev_loop *loop = EV_DEFAULT;
	struct config conf = make_conf();
	struct serve_ctx serve_ctx = { 0 };
	struct server s;
	struct sockaddr_in bindaddr;
	uint16_t port;
	int client_fd = -1;

	set_loopback_addr(&bindaddr);
	server_init(&s, loop);
	s.conf = &conf;
	s.data = &serve_ctx;

	T_EXPECT(server_add_listener(
		&s, (const struct sockaddr *)&bindaddr, serve_cb));
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, served_once, &serve_ctx, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 1);
	T_EXPECT(s.stats.started != -1);

	CLOSE_FD(client_fd);
	server_stop(&s);
	T_EXPECT_EQ(s.stats.started, -1);
}

T_DECLARE_CASE(test_server_rejects_when_session_limit_exceeded)
{
	struct ev_loop *loop = EV_DEFAULT;
	struct config conf = make_conf();
	struct serve_ctx serve_ctx = { 0 };
	struct server s;
	struct sockaddr_in bindaddr;
	uint16_t port;
	int client_fd = -1;

	set_loopback_addr(&bindaddr);
	conf.max_sessions = 1;
	server_init(&s, loop);
	s.conf = &conf;
	s.data = &serve_ctx;
	s.stats.num_sessions = 2;

	T_EXPECT(server_add_listener(
		&s, (const struct sockaddr *)&bindaddr, serve_cb));
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, accepted_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 0);
	T_EXPECT_EQ(serve_ctx.calls, 0);

	CLOSE_FD(client_fd);
	server_stop(&s);
}

int main(void)
{
	T_DECLARE_CTX(t);

	T_RUN_CASE(t, test_server_start_accept_and_stop);
	T_RUN_CASE(t, test_server_rejects_when_session_limit_exceeded);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
