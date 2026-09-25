/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Unit tests for util.c; mocked: resolver; links version.c. */

#include "util.h"

#include "resolver.h"
#include "transfer.h"

#include "meta/arraysize.h"
#include "utils/slog.h"
#include "utils/testing.h"

#include <ev.h>

#include <fcntl.h>
#include <locale.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
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

/* Switch LC_NUMERIC to the first installed locale that spells the decimal point
 * with something other than '.', and return its name; NULL when the host has
 * none. LC_NUMERIC is left in the C locale either way. */
static const char *find_comma_locale(void)
{
	static const char *const names[] = {
		"de_DE.UTF-8", "de_DE.utf8",  "de_DE",	     "de_DE@euro",
		"fr_FR.UTF-8", "fr_FR.utf8",  "fr_FR",	     "es_ES.UTF-8",
		"it_IT.UTF-8", "nl_NL.UTF-8", "pt_BR.UTF-8", "ru_RU.UTF-8",
	};
	const char *found = NULL;
	for (size_t i = 0; found == NULL && i < ARRAY_SIZE(names); i++) {
		if (setlocale(LC_NUMERIC, names[i]) == NULL) {
			continue;
		}
		if (localeconv()->decimal_point[0] != '.') {
			found = names[i];
		}
	}
	(void)setlocale(LC_NUMERIC, "C");
	return found;
}

static struct {
	bool had_lc_all;
	char lc_all[256];
} saved_env;

static void restore_locale(void *data)
{
	(void)data;
	if (saved_env.had_lc_all) {
		(void)setenv("LC_ALL", saved_env.lc_all, 1);
	} else {
		(void)unsetenv("LC_ALL");
	}
	(void)setlocale(LC_ALL, "C");
}

/* init() adopts the environment's locale but keeps LC_NUMERIC in "C": the
 * configuration dump writes numbers with "%.17g" for Lua to read back, and the
 * numeric options go through strtod(). With a comma-decimal locale in the
 * environment, setlocale(LC_ALL, "") really moves LC_NUMERIC, so dropping or
 * reordering the pin fails here; on a host with no such locale installed only
 * the unmoved half can be checked. */
T_DECLARE_CASE(util_init_pins_lc_numeric_to_c)
{
	const char *const comma = find_comma_locale();
	const char *const lc_all = getenv("LC_ALL");
	saved_env.had_lc_all = (lc_all != NULL);
	if (lc_all != NULL) {
		T_CHECK(strlen(lc_all) < sizeof(saved_env.lc_all));
		(void)snprintf(
			saved_env.lc_all, sizeof(saved_env.lc_all), "%s",
			lc_all);
	}
	T_CLEANUP(restore_locale, NULL);
	if (comma != NULL) {
		T_LOGF("LC_ALL=%s", comma);
		T_CHECK(setenv("LC_ALL", comma, 1) == 0);
	} else {
		T_LOG("no installed locale uses a non-'.' decimal point");
	}

	init(0, NULL);

	const char *const numeric = setlocale(LC_NUMERIC, NULL);
	T_CHECK(numeric != NULL);
	T_EXPECT_STREQ(numeric, "C");
	T_EXPECT_STREQ(localeconv()->decimal_point, ".");
	if (comma != NULL) {
		/* the environment did reach init(): only LC_NUMERIC was pinned */
		const char *const monetary = setlocale(LC_MONETARY, NULL);
		T_CHECK(monetary != NULL);
		T_EXPECT_STREQ(monetary, comma);
	}

	/* the conversions the pin exists for */
	char *end = NULL;
	T_EXPECT(strtod("30.5", &end) == 30.5);
	T_EXPECT_EQ(*end, '\0');
	char dump[32];
	(void)snprintf(dump, sizeof(dump), "%.17g", 12.5);
	T_EXPECT_STREQ(dump, "12.5");
}

struct escape_case {
	const char *in;
	size_t len;
	size_t maxlen;
	const char *out;
};

/* log_escape() renders byte by byte per its contract, stopping on a whole
 * escape when the buffer runs out rather than splitting one. */
T_DECLARE_CASE(util_log_escape_table)
{
	static const struct escape_case cases[] = {
		/* passthrough, and the printable-range boundaries */
		{ "host.example", 12, 64, "host.example" },
		{ " ~", 2, 64, " ~" },
		{ "\x1f", 1, 64, "\\x1f" },
		{ "\x7f", 1, 64, "\\x7f" },
		{ "\x00\x80\xff", 3, 64, "\\x00\\x80\\xff" },
		/* short forms, and the quote and backslash */
		{ "\n\r\t", 3, 64, "\\n\\r\\t" },
		{ "\\'", 2, 64, "\\\\\\'" },
		{ "a\tb", 3, 64, "a\\tb" },
		/* empty input, and a buffer with room for the terminator only */
		{ "", 0, 1, "" },
		{ "", 0, 64, "" },
		{ "ab", 2, 1, "" },
		{ "\n", 1, 1, "" },
		/* truncation: exact fit, and one byte short of a short form */
		{ "ab\n", 3, 5, "ab\\n" },
		{ "ab\n", 3, 4, "ab" },
		{ "ab", 2, 2, "a" },
		/* a hex escape is dropped whole, at every short length */
		{ "a\x01", 2, 6, "a\\x01" },
		{ "a\x01", 2, 5, "a" },
		{ "a\x01", 2, 4, "a" },
		{ "a\x01", 2, 3, "a" },
		/* output stops at the first escape that does not fit, even when a
		 * narrower byte after it would */
		{ "a\x01"
		  "b",
		  3, 5, "a" },
		{ "a'b", 3, 3, "a" },
	};
	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		const struct escape_case *const c = &cases[i];
		char buf[80];
		(void)memset(buf, 'Z', sizeof(buf));
		T_CHECK(c->maxlen < sizeof(buf));
		const size_t n = log_escape(buf, c->maxlen, c->in, c->len);
		if (strcmp(buf, c->out) != 0) {
			T_LOGF("case %zu: \"%s\"", i, buf);
		}
		T_EXPECT_STREQ(buf, c->out);
		T_EXPECT_EQ(n, strlen(c->out));
		/* nothing is written past maxlen */
		T_EXPECT_EQ(buf[c->maxlen], 'Z');
	}
}

/* A buffer of LOG_ESCAPE_STRLEN(len) + 1 bytes holds the widest rendering of
 * len bytes, and every byte value, untruncated. */
T_DECLARE_CASE(util_log_escape_strlen_bound)
{
	char in[256];
	(void)memset(in, '\x80', sizeof(in));
	char buf[LOG_ESCAPE_STRLEN(sizeof(in)) + 1];
	size_t n = log_escape(buf, sizeof(buf), in, sizeof(in));
	/* every byte took the four-character \xHH form */
	T_EXPECT_EQ(n, 4 * sizeof(in));
	T_EXPECT_EQ(strlen(buf), n);
	T_EXPECT_MEMEQ(buf + n - 4, "\\x80", 4);

	size_t want = 0;
	for (size_t i = 0; i < sizeof(in); i++) {
		const unsigned char c = (unsigned char)i;
		in[i] = (char)c;
		if (c == '\n' || c == '\r' || c == '\t' || c == '\\' ||
		    c == '\'') {
			want += 2;
		} else if (c < 0x20 || c > 0x7e) {
			want += 4;
		} else {
			want += 1;
		}
	}
	n = log_escape(buf, sizeof(buf), in, sizeof(in));
	T_EXPECT_EQ(n, want);
	T_EXPECT_EQ(strlen(buf), n);
	/* the last byte, 0xff, is the last escape: nothing was cut off */
	T_EXPECT_MEMEQ(buf + n - 4, "\\xff", 4);
}

T_DECLARE_CASE(util_loadlibs_unloadlibs)
{
	/* Exercises srand64, resolver_init and resolver_cleanup (stubs). */
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
	/* socket_set_transparent is fatal on error by design: setsockopt
	 * fails with EBADF where IP_TRANSPARENT exists, the CHECKMSGF guard
	 * fails where it does not. Fork so the abort is contained. */
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
 * draining, drives successful partial sends until EAGAIN/EWOULDBLOCK prevents
 * further progress. The remaining bytes are not queued. */
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
	T_CASE(util_init_pins_lc_numeric_to_c),
	T_CASE(util_log_escape_table),
	T_CASE(util_log_escape_strlen_bound),
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
