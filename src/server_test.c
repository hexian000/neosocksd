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

T_DECLARE_CASE(test_server_start_accept_and_stop)
{
	struct ev_loop *loop = EV_DEFAULT;
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

	CLOSE_FD(client_fd);
	server_stop(&s);
	T_EXPECT_EQ(s.stats.started, -1);
}

T_DECLARE_CASE(test_server_rejects_when_session_limit_exceeded)
{
	struct ev_loop *loop = EV_DEFAULT;
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
