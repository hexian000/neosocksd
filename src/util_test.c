/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for util.c; mocked: resolver; links version.c. */

#include "util.h"

#include "resolver.h"
#include "transfer.h"

#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - stubs for the resolver symbols referenced by util.c.
 * ---------------------------------------------------------------------- */

void resolver_init(void)
{
}

void resolver_cleanup(void)
{
}

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - io-event helpers and formatting cases.
 * ---------------------------------------------------------------------- */

static void dummy_io_cb(struct ev_loop *loop, ev_io *w, const int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

T_DECLARE_CASE(util_modify_io_events_stop)
{
	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);

	ev_io w;
	ev_io_init(&w, dummy_io_cb, sv[0], EV_READ);
	ev_io_start(loop, &w);
	T_EXPECT(ev_is_active(&w));

	modify_io_events(loop, &w, EV_NONE);
	T_EXPECT(!ev_is_active(&w));

	ev_loop_destroy(loop);
	(void)close(sv[0]);
	(void)close(sv[1]);
}

T_DECLARE_CASE(util_modify_io_events_change)
{
	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);

	ev_io w;
	ev_io_init(&w, dummy_io_cb, sv[0], EV_READ);
	ev_io_start(loop, &w);

	modify_io_events(loop, &w, EV_WRITE);
	T_EXPECT(ev_is_active(&w));
	T_EXPECT_EQ(w.events & (EV_READ | EV_WRITE), EV_WRITE);

	modify_io_events(loop, &w, EV_NONE);
	T_EXPECT(!ev_is_active(&w));

	ev_loop_destroy(loop);
	(void)close(sv[0]);
	(void)close(sv[1]);
}

T_DECLARE_CASE(util_init_runs_without_crash)
{
	/* Exercises setlocale, setvbuf, slog setup, and sigaction(SIGPIPE). */
	init(0, NULL);
	T_EXPECT(true);
}

T_DECLARE_CASE(util_loadlibs_unloadlibs)
{
	/* Exercises srand64 and resolver_init (stub). */
	loadlibs();
	unloadlibs();
	T_EXPECT(true);
}

T_DECLARE_CASE(util_modify_io_events_no_op_stop)
{
	/* Calling modify_io_events with EV_NONE on an inactive watcher
	 * is a no-op: the watcher must remain inactive. */
	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);

	ev_io w;
	ev_io_init(&w, dummy_io_cb, sv[0], EV_READ);
	/* watcher is inactive; do NOT call ev_io_start */
	T_EXPECT(!ev_is_active(&w));

	modify_io_events(loop, &w, EV_NONE);
	T_EXPECT(!ev_is_active(&w));

	ev_loop_destroy(loop);
	(void)close(sv[0]);
	(void)close(sv[1]);
}

T_DECLARE_CASE(util_modify_io_events_start_inactive)
{
	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);

	ev_io w;
	ev_io_init(&w, dummy_io_cb, sv[0], EV_READ);

	modify_io_events(loop, &w, EV_READ);
	T_EXPECT(ev_is_active(&w));
	T_EXPECT_EQ(w.events & (EV_READ | EV_WRITE), EV_READ);

	ev_io_stop(loop, &w);
	ev_loop_destroy(loop);
	(void)close(sv[0]);
	(void)close(sv[1]);
}

T_DECLARE_CASE(util_modify_io_events_same_events_noop)
{
	/* Setting the same events on an active watcher must not stop/restart it. */
	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);

	ev_io w;
	ev_io_init(&w, dummy_io_cb, sv[0], EV_READ);
	ev_io_start(loop, &w);
	T_EXPECT(ev_is_active(&w));

	modify_io_events(loop, &w, EV_READ);
	T_EXPECT(ev_is_active(&w));
	T_EXPECT_EQ(w.events & (EV_READ | EV_WRITE), EV_READ);

	ev_io_stop(loop, &w);
	ev_loop_destroy(loop);
	(void)close(sv[0]);
	(void)close(sv[1]);
}

T_DECLARE_CASE(util_socket_bind_netdev_invalid_fd)
{
	/* An invalid fd causes setsockopt to fail; socket_bind_netdev
	 * must log a warning and return without crashing. */
	socket_bind_netdev(-1, "lo");
	T_EXPECT(true);
}

T_DECLARE_CASE(util_socket_bind_netdev_empty_name)
{
	/* An empty device name is a no-op on platforms without SO_BINDTODEVICE
	 * and triggers a setsockopt call (that fails) on Linux; no crash. */
	socket_bind_netdev(-1, "");
	T_EXPECT(true);
}

T_DECLARE_CASE(util_socket_set_transparent_invalid_fd_aborts)
{
	/* socket_set_transparent is fatal-on-error by design. Requesting
	 * transparency on an invalid fd must abort the process on every build:
	 * setsockopt fails with EBADF where IP_TRANSPARENT exists, and the
	 * CHECKMSGF guard fails where it does not. Fork so the abort is
	 * contained, and assert the child died on SIGABRT. */
	const pid_t pid = fork();
	T_CHECK(pid >= 0);
	if (pid == 0) {
		/* child: suppress the expected fatal log, then trigger it */
		slog_setoutput(SLOG_OUTPUT_DISCARD);
		socket_set_transparent(-1, true);
		_exit(EXIT_SUCCESS); /* not reached */
	}
	int status = 0;
	T_CHECK(waitpid(pid, &status, 0) == pid);
	T_EXPECT(WIFSIGNALED(status));
	T_EXPECT_EQ(WTERMSIG(status), SIGABRT);
}

/* The time-jump sentinel must sit far enough in the future that it can never
 * become pending -- its callback is a hard failure if it ever runs. */
T_DECLARE_CASE(util_loop_watch_timejump_never_pending)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);

	ev_periodic w;
	loop_watch_timejump(loop, &w);
	T_EXPECT(ev_is_active(&w));
	T_EXPECT(ev_periodic_at(&w) > (ev_tstamp)TIMEJUMP_SENTINEL_AT / 2.0);

	/* an iteration that would dispatch it aborts in timejump_cb */
	ev_run(loop, EVRUN_NOWAIT);
	T_EXPECT(!ev_is_pending(&w));

	/* the sentinel is unref'd, so re-ref before stopping it */
	ev_ref(loop);
	ev_periodic_stop(loop, &w);
	ev_loop_destroy(loop);
}

/* The sentinel is unref'd, so it must not keep an otherwise-empty loop alive:
 * ev_run must return rather than block on it. Run in a child under an alarm so
 * a regression fails the test instead of hanging it. */
T_DECLARE_CASE(util_loop_watch_timejump_does_not_hold_loop)
{
	const pid_t pid = fork();
	T_CHECK(pid >= 0);
	if (pid == 0) {
		struct ev_loop *loop = ev_loop_new(0);
		if (loop == NULL) {
			_exit(EXIT_FAILURE);
		}
		ev_periodic w;
		loop_watch_timejump(loop, &w);
		alarm(5);
		ev_run(loop, 0);
		alarm(0);
		_exit(EXIT_SUCCESS);
	}
	int status = 0;
	T_CHECK(waitpid(pid, &status, 0) == pid);
	T_EXPECT(WIFEXITED(status));
	T_EXPECT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);
}

#if WITH_TCP_KEEPALIVE_PARAMS
static int getsockopt_int(const int fd, const int optname)
{
	int value = -1;
	socklen_t len = sizeof(value);
	T_CHECK(getsockopt(fd, IPPROTO_TCP, optname, &value, &len) == 0);
	return value;
}

T_DECLARE_CASE(util_socket_set_keepalive_applies_each_param)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(fd >= 0);

	socket_set_keepalive(fd, 300, 30, 5);
	T_EXPECT_EQ(getsockopt_int(fd, TCP_KEEPIDLE), 300);
	T_EXPECT_EQ(getsockopt_int(fd, TCP_KEEPINTVL), 30);
	T_EXPECT_EQ(getsockopt_int(fd, TCP_KEEPCNT), 5);

	(void)close(fd);
}

/* A non-positive value leaves that parameter at the system default. */
T_DECLARE_CASE(util_socket_set_keepalive_keeps_defaults)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	T_CHECK(fd >= 0);

	const int idle = getsockopt_int(fd, TCP_KEEPIDLE);
	const int intvl = getsockopt_int(fd, TCP_KEEPINTVL);

	socket_set_keepalive(fd, 0, -1, 7);
	T_EXPECT_EQ(getsockopt_int(fd, TCP_KEEPIDLE), idle);
	T_EXPECT_EQ(getsockopt_int(fd, TCP_KEEPINTVL), intvl);
	T_EXPECT_EQ(getsockopt_int(fd, TCP_KEEPCNT), 7);

	(void)close(fd);
}
#endif /* WITH_TCP_KEEPALIVE_PARAMS */

/* forward_readahead delivers a whole buffer over a socketpair, and counts
 * every delivered byte into the uplink counter -- these bytes bypass the
 * relay, so this call site is the only place they can be counted. */
T_DECLARE_CASE(util_forward_readahead_full_delivery)
{
	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	static const char msg[] = "hello upstream";
	xfer_counter byt = 0;
	T_EXPECT(forward_readahead(sv[0], msg, sizeof(msg) - 1, &byt));
	T_EXPECT_EQ((uintmax_t)byt, (uintmax_t)(sizeof(msg) - 1));

	char buf[sizeof(msg)] = { 0 };
	const ssize_t n = recv(sv[1], buf, sizeof(msg) - 1, 0);
	T_EXPECT_EQ(n, (ssize_t)(sizeof(msg) - 1));
	T_EXPECT(memcmp(buf, msg, sizeof(msg) - 1) == 0);

	(void)close(sv[0]);
	(void)close(sv[1]);
}

/* A NULL counter is accepted: the caller may not have one to feed. */
T_DECLARE_CASE(util_forward_readahead_null_counter)
{
	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	static const char msg[] = "no counter";
	T_EXPECT(forward_readahead(sv[0], msg, sizeof(msg) - 1, NULL));

	(void)close(sv[0]);
	(void)close(sv[1]);
}

/* A send error (here EBADF on an invalid fd) makes forward_readahead return
 * false rather than silently dropping the bytes, and counts nothing: no byte
 * reached the wire. */
T_DECLARE_CASE(util_forward_readahead_send_error_fails)
{
	static const char msg[] = "x";
	xfer_counter byt = 0;
	T_EXPECT(!forward_readahead(-1, msg, sizeof(msg) - 1, &byt));
	T_EXPECT_EQ((uintmax_t)byt, (uintmax_t)0);
}

/* A buffer larger than the socket's send capacity, with the peer never
 * draining, drives the partial-send loop and then fails on backpressure (a
 * short send is treated as failure, not queued). */
T_DECLARE_CASE(util_forward_readahead_backpressure_fails)
{
	int sv[2] = { -1, -1 };
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	/* shrink both ends and make the sender non-blocking so the send returns
	 * EAGAIN instead of blocking once the buffers fill */
	const int lo = 2048;
	(void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &lo, sizeof(lo));
	(void)setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &lo, sizeof(lo));
	const int flags = fcntl(sv[0], F_GETFL, 0);
	T_CHECK(flags >= 0);
	T_CHECK(fcntl(sv[0], F_SETFL, flags | O_NONBLOCK) == 0);

	static unsigned char big[1u << 20]; /* 1 MiB, far beyond the buffers */
	xfer_counter byt = 0;
	T_EXPECT(!forward_readahead(sv[0], big, sizeof(big), &byt));
	/* the bytes that made it out before the backpressure are counted, so a
	 * partial delivery is neither dropped from nor rounded up in the total */
	T_EXPECT((uintmax_t)byt > 0);
	T_EXPECT((uintmax_t)byt < (uintmax_t)sizeof(big));

	(void)close(sv[0]);
	(void)close(sv[1]);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(util_modify_io_events_stop),
	T_CASE(util_modify_io_events_change),
	T_CASE(util_modify_io_events_no_op_stop),
	T_CASE(util_modify_io_events_start_inactive),
	T_CASE(util_modify_io_events_same_events_noop),
	T_CASE(util_init_runs_without_crash),
	T_CASE(util_loadlibs_unloadlibs),
	T_CASE(util_socket_bind_netdev_invalid_fd),
	T_CASE(util_socket_bind_netdev_empty_name),
	T_CASE(util_socket_set_transparent_invalid_fd_aborts),
	T_CASE(util_loop_watch_timejump_never_pending),
	T_CASE(util_loop_watch_timejump_does_not_hold_loop),
#if WITH_TCP_KEEPALIVE_PARAMS
	T_CASE(util_socket_set_keepalive_applies_each_param),
	T_CASE(util_socket_set_keepalive_keeps_defaults),
#endif
	T_CASE(util_forward_readahead_full_delivery),
	T_CASE(util_forward_readahead_null_counter),
	T_CASE(util_forward_readahead_send_error_fails),
	T_CASE(util_forward_readahead_backpressure_fails),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
