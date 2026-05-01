/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "util.h"

#include "dialer.h"
#include "resolver.h"

#include "utils/testing.h"

#include <ev.h>
#include <sys/socket.h>
#include <unistd.h>

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

/*
 * Stubs for symbols in util.c that are outside the scope of these tests.
 * neosocksd_version() is provided by version.c (compiled separately).
 * The functions below are only reachable via loadlibs/unloadlibs, which the
 * test runner never calls.
 */

int dialreq_format(
	char *restrict s, const size_t maxlen,
	const struct dialreq *restrict r)
{
	(void)s;
	(void)maxlen;
	(void)r;
	return -1;
}

void resolver_init(void) {}

void resolver_cleanup(void) {}

/* Tests */

T_DECLARE_CASE(util_staleconn_err_true)
{
	T_EXPECT(IS_STALECONN_ERROR(ECONNRESET));
	T_EXPECT(IS_STALECONN_ERROR(EPIPE));
	T_EXPECT(IS_STALECONN_ERROR(ECONNABORTED));
	T_EXPECT(IS_STALECONN_ERROR(ENOTCONN));
	T_EXPECT(IS_STALECONN_ERROR(EBADF));
}

T_DECLARE_CASE(util_staleconn_err_false)
{
	T_EXPECT(!IS_STALECONN_ERROR(EAGAIN));
	T_EXPECT(!IS_STALECONN_ERROR(ETIMEDOUT));
	T_EXPECT(!IS_STALECONN_ERROR(EINTR));
	T_EXPECT(!IS_STALECONN_ERROR(ENOMEM));
	T_EXPECT(!IS_STALECONN_ERROR(0));
}

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

#if WITH_SPLICE
T_DECLARE_CASE(util_pipe_new_close)
{
	struct splice_pipe p = { .fd = { -1, -1 } };
	T_EXPECT(pipe_new(&p));
	T_EXPECT(p.fd[0] >= 0);
	T_EXPECT(p.fd[1] >= 0);
	T_EXPECT(p.cap > 0);

	unsigned char buf[1] = { 0x42 };
	T_EXPECT_EQ((ssize_t)write(p.fd[1], buf, 1), (ssize_t)1);
	T_EXPECT_EQ((ssize_t)read(p.fd[0], buf, 1), (ssize_t)1);
	T_EXPECT_EQ(buf[0], 0x42);

	pipe_close(&p);
	T_EXPECT_EQ(p.fd[0], -1);
	T_EXPECT_EQ(p.fd[1], -1);
}

T_DECLARE_CASE(util_pipe_shrink)
{
	/* Start from a clean slate */
	pipe_shrink(SIZE_MAX);
	T_EXPECT_EQ(pipe_cache.len, (size_t)0);

	/* Manually place two fresh pipes into the cache */
	struct splice_pipe p1 = { .fd = { -1, -1 } };
	struct splice_pipe p2 = { .fd = { -1, -1 } };
	T_CHECK(pipe_new(&p1));
	T_CHECK(pipe_new(&p2));
	pipe_cache.pipes[0] = p1;
	pipe_cache.pipes[1] = p2;
	pipe_cache.len = 2;

	pipe_shrink(1);
	T_EXPECT_EQ(pipe_cache.len, (size_t)1);

	pipe_shrink(SIZE_MAX);
	T_EXPECT_EQ(pipe_cache.len, (size_t)0);
}
#endif /* WITH_SPLICE */

int main(void)
{
	T_DECLARE_CTX(t);
	T_RUN_CASE(t, util_staleconn_err_true);
	T_RUN_CASE(t, util_staleconn_err_false);
	T_RUN_CASE(t, util_modify_io_events_stop);
	T_RUN_CASE(t, util_modify_io_events_change);
#if WITH_SPLICE
	T_RUN_CASE(t, util_pipe_new_close);
	T_RUN_CASE(t, util_pipe_shrink);
#endif
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
