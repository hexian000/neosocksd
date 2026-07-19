/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for util.c; mocked: dialreq_format, resolver; links version.c. */

#include "util.h"

#include "dialer.h"
#include "resolver.h"

#include "meta/minmax.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - stubs for the dialer/resolver symbols referenced by util.c.
 * ---------------------------------------------------------------------- */

static struct {
	int dialreq_format_len_override;
} STUB = { .dialreq_format_len_override = -1 };

int dialreq_format(
	char *restrict s, const size_t maxlen, const struct dialreq *restrict r)
{
	size_t len;

	if (STUB.dialreq_format_len_override >= 0) {
		len = (size_t)STUB.dialreq_format_len_override;
		if (s != NULL && maxlen > 0) {
			const size_t n = MIN(len, maxlen - 1);
			memset(s, 'x', n);
			s[n] = '\0';
		}
		return (int)len;
	}
	if (r == NULL || r->addr.type != ATYP_DOMAIN) {
		return -1;
	}
	len = r->addr.domain.len;
	if (s != NULL && maxlen > 0) {
		const size_t n = MIN(len, maxlen - 1);
		memcpy(s, r->addr.domain.name, n);
		s[n] = '\0';
	}
	return (int)len;
}

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
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
