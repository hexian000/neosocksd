/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "server.h"

#include "api_server.h"
#include "conf.h"
#include "forward.h"
#include "http_proxy.h"
#if WITH_RULESET
#include "ruleset.h"
#endif
#include "socks.h"
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

struct dialreq *
dialreq_parse(const char *restrict addr, const char *restrict csv)
{
	(void)addr;
	(void)csv;
	return NULL;
}

void dialreq_free(struct dialreq *req)
{
	(void)req;
}

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

void http_proxy_serve(
	struct server *s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	(void)s;
	(void)loop;
	(void)accepted_sa;
	(void)close(accepted_fd);
}

void socks_serve(
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

#if WITH_RULESET
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

static struct config make_conf(const char *listen)
{
	return (struct config){
		.listen = listen,
		.timeout = 1.0,
		.tcp_nodelay = true,
		.tcp_keepalive = true,
	};
}

struct test_watchdog {
	bool fired;
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
	const struct server *s = data;
	return s->listeners[0].stats.num_serve == 1;
}

static bool accepted_once(void *data)
{
	const struct server *s = data;
	return s->listeners[0].stats.num_accept == 1;
}

static bool listener_backing_off(void *data)
{
	const struct listener *l = data;
	return !ev_is_active(&l->w_accept) && ev_is_active(&l->w_timer);
}

T_DECLARE_CASE(test_server_start_accept_and_stop)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint16_t port;
	int client_fd = -1;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, served_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 1);
	T_EXPECT(s.stats.started != -1);

	SOCKET_CLOSE_FD(client_fd);
	server_stop(&s);
	T_EXPECT_EQ(s.stats.started, -1);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(test_server_rejects_when_session_limit_exceeded)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint16_t port;
	int client_fd = -1;

	conf.max_sessions = 1;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	s.num_sessions = 2;
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, accepted_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 0);

	SOCKET_CLOSE_FD(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(test_server_rejects_when_full_startup_limit_exceeded)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint16_t port;
	int client_fd = -1;

	conf.startup_limit_full = 1;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	s.stats.num_halfopen = 2;
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, accepted_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 0);

	SOCKET_CLOSE_FD(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(test_server_rejects_when_probabilistic_startup_limit_hits)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint16_t port;
	int client_fd = -1;

	conf.startup_limit_start = 1;
	conf.startup_limit_rate = 100;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	s.stats.num_halfopen = 2;
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, accepted_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 0);

	SOCKET_CLOSE_FD(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

T_DECLARE_CASE(test_server_accept_error_restarts_listener)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	struct listener *l;
	uint16_t port;
	int pipefd[2] = { -1, -1 };
	int client_fd = -1;
	int listener_fd;

	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	l = &s.listeners[0];
	listener_fd = l->w_accept.fd;
	port = bound_port(listener_fd);
	T_CHECK(pipe(pipefd) == 0);

	ev_io_stop(loop, &l->w_accept);
	ev_io_set(&l->w_accept, pipefd[0], EV_READ);
	ev_io_start(loop, &l->w_accept);
	T_CHECK(write(pipefd[1], "x", 1) == 1);

	T_EXPECT(test_wait_until(loop, listener_backing_off, l, 0.5));
	T_EXPECT(!ev_is_active(&l->w_accept));
	T_EXPECT(ev_is_active(&l->w_timer));

	ev_io_set(&l->w_accept, listener_fd, EV_READ);
	SOCKET_CLOSE_FD(pipefd[0]);
	SOCKET_CLOSE_FD(pipefd[1]);
	client_fd = connect_loopback(port);
	T_EXPECT(test_wait_until(loop, served_once, &s, 1.0));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 1);

	SOCKET_CLOSE_FD(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * max_sessions uses > (not >=) comparison.  Verify that exactly
 * max_sessions concurrent sessions are allowed, and the next is
 * rejected.
 */
T_DECLARE_CASE(test_server_allows_when_at_max_sessions)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint16_t port;
	int client_fd = -1;

	conf.max_sessions = 1;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	/* Exactly at the limit — should still accept. */
	s.num_sessions = 1;
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, served_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_accept, 1);
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 1);

	SOCKET_CLOSE_FD(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * max_sessions == 0 means unlimited.
 */
T_DECLARE_CASE(test_server_zero_max_sessions_allows_unlimited)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint16_t port;
	int client_fd = -1;

	/* max_sessions=0: no limit.  Use a large num_sessions to
	 * confirm the guard is not triggered. */
	conf.max_sessions = 0;
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	s.num_sessions = (size_t)999999;
	port = bound_port(s.listeners[0].w_accept.fd);
	client_fd = connect_loopback(port);

	T_EXPECT(test_wait_until(loop, served_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 1);

	SOCKET_CLOSE_FD(client_fd);
	server_stop(&s);
	ev_loop_destroy(loop);
}

/*
 * Two listeners (proxy + http) on the same server must work independently.
 */
T_DECLARE_CASE(test_server_dual_listener_independent_accepts)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct config conf = make_conf("127.0.0.1:0");
	struct server s;
	uint16_t port_a, port_b;
	int client_fd = -1;

	conf.http_listen = "127.0.0.1:0";
	T_EXPECT(server_init(&s, loop, &conf, NULL, NULL, NULL, NULL));
	/* Two listeners must have been created (proxy + http). */
	T_EXPECT_EQ(s.num_listeners, (size_t)2);

	port_a = bound_port(s.listeners[0].w_accept.fd);
	port_b = bound_port(s.listeners[1].w_accept.fd);
	T_EXPECT(port_a != port_b);

	/* Connect to the first listener. */
	client_fd = connect_loopback(port_a);
	T_EXPECT(test_wait_until(loop, served_once, &s, 0.5));
	T_EXPECT_EQ(s.listeners[0].stats.num_serve, 1);
	T_EXPECT_EQ(s.listeners[1].stats.num_serve, 0);
	SOCKET_CLOSE_FD(client_fd);

	/* Connect to the second listener. */
	client_fd = connect_loopback(port_b);
	{
		const size_t num_serve = s.listeners[0].stats.num_serve;
		struct test_watchdog wd = { 0 };
		ev_timer w;
		ev_timer_init(&w, watchdog_cb, 0.5, 0.0);
		w.data = &wd;
		ev_timer_start(loop, &w);
		while (!wd.fired && s.listeners[1].stats.num_serve == 0) {
			ev_run(loop, EVRUN_ONCE);
		}
		ev_timer_stop(loop, &w);
		T_EXPECT_EQ(s.listeners[0].stats.num_serve, num_serve);
		T_EXPECT_EQ(s.listeners[1].stats.num_serve, 1);
	}
	SOCKET_CLOSE_FD(client_fd);

	server_stop(&s);
	ev_loop_destroy(loop);
}

int main(void)
{
	T_DECLARE_CTX(t);

	T_RUN_CASE(t, test_server_start_accept_and_stop);
	T_RUN_CASE(t, test_server_rejects_when_session_limit_exceeded);
	T_RUN_CASE(t, test_server_allows_when_at_max_sessions);
	T_RUN_CASE(t, test_server_zero_max_sessions_allows_unlimited);
	T_RUN_CASE(t, test_server_rejects_when_full_startup_limit_exceeded);
	T_RUN_CASE(
		t, test_server_rejects_when_probabilistic_startup_limit_hits);
	T_RUN_CASE(t, test_server_accept_error_restarts_listener);
	T_RUN_CASE(t, test_server_dual_listener_independent_accepts);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
