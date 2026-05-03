/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "util.h"

#include "dialer.h"
#include "resolver.h"

#include "utils/testing.h"

#include <ev.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static const ev_tstamp TEST_WAIT_SEC = 0.128;

static struct {
	int dialreq_format_len_override;
} STUB = {
	.dialreq_format_len_override = -1,
};

struct test_watchdog {
	bool fired;
};

/*
 * Stubs for symbols in util.c that are outside the scope of these tests.
 * neosocksd_version() is provided by version.c (compiled separately).
 * The functions below are only reachable via loadlibs/unloadlibs, which the
 * test runner never calls.
 */

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

static void reset_stub_state(void)
{
	STUB.dialreq_format_len_override = -1;
}

static void
watchdog_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	struct test_watchdog *const watchdog = watcher->data;

	(void)revents;
	watchdog->fired = true;
	ev_break(loop, EVBREAK_ONE);
}

static bool wait_until(
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

static struct dialreq make_domain_req(const char *restrict name)
{
	struct dialreq req = { 0 };
	const size_t len = strlen(name);

	T_CHECK(len <= UINT8_MAX);
	req.addr.type = ATYP_DOMAIN;
	req.addr.port = UINT16_C(443);
	req.addr.domain.len = (uint_least8_t)len;
	memcpy(req.addr.domain.name, name, len);
	return req;
}

static struct conn_cache_entry *find_cache_entry(const int fd)
{
	for (int i = 0; i < CONN_CACHE_CAPACITY; i++) {
		if (conn_cache.entries[i].fd == fd) {
			return &conn_cache.entries[i];
		}
	}
	return NULL;
}

static bool conn_cache_is_empty(void *data)
{
	(void)data;
	return conn_cache.len == 0;
}

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

T_DECLARE_CASE(util_conn_cache_put_get_roundtrip)
{
	int sv[2] = { -1, -1 };
	char byte = 'n';
	struct dialreq req = make_domain_req("alpha.example");
	struct ev_loop *loop = ev_loop_new(0);

	T_CHECK(loop != NULL);
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	reset_stub_state();
	loadlibs();

	conn_cache_put(loop, sv[0], &req);
	T_EXPECT_EQ(conn_cache.len, (size_t)1);
	T_EXPECT_EQ(conn_cache_get(loop, &req), sv[0]);
	T_EXPECT_EQ(conn_cache.len, (size_t)0);
	T_EXPECT_EQ(
		(ssize_t)write(sv[1], &byte, sizeof(byte)),
		(ssize_t)sizeof(byte));
	T_EXPECT_EQ(
		(ssize_t)read(sv[0], &byte, sizeof(byte)),
		(ssize_t)sizeof(byte));

	ev_loop_destroy(loop);
	(void)close(sv[0]);
	(void)close(sv[1]);
}

T_DECLARE_CASE(util_conn_cache_idle_close)
{
	int sv[2] = { -1, -1 };
	struct dialreq req = make_domain_req("idle.example");
	struct ev_loop *loop = ev_loop_new(0);

	T_CHECK(loop != NULL);
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	reset_stub_state();
	loadlibs();

	conn_cache_put(loop, sv[0], &req);
	T_EXPECT_EQ(conn_cache.len, (size_t)1);
	T_EXPECT(find_cache_entry(sv[0]) != NULL);
	T_CHECK(close(sv[1]) == 0);
	sv[1] = -1;
	T_EXPECT(wait_until(loop, conn_cache_is_empty, NULL, TEST_WAIT_SEC));
	errno = 0;
	T_EXPECT(fcntl(sv[0], F_GETFD) == -1);
	T_EXPECT_EQ(errno, EBADF);
	sv[0] = -1;

	ev_loop_destroy(loop);
}

T_DECLARE_CASE(util_conn_cache_expire_closes_fd)
{
	int sv[2] = { -1, -1 };
	struct dialreq req = make_domain_req("expire.example");
	struct ev_loop *loop = ev_loop_new(0);
	struct conn_cache_entry *entry;

	T_CHECK(loop != NULL);
	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	reset_stub_state();
	loadlibs();

	conn_cache_put(loop, sv[0], &req);
	entry = find_cache_entry(sv[0]);
	T_CHECK(entry != NULL);
	ev_timer_stop(loop, &entry->w_expire);
	ev_timer_set(&entry->w_expire, 0.001, 0.0);
	ev_timer_start(loop, &entry->w_expire);
	T_EXPECT(wait_until(loop, conn_cache_is_empty, NULL, TEST_WAIT_SEC));
	errno = 0;
	T_EXPECT(fcntl(sv[0], F_GETFD) == -1);
	T_EXPECT_EQ(errno, EBADF);
	sv[0] = -1;

	ev_loop_destroy(loop);
	(void)close(sv[1]);
}

T_DECLARE_CASE(util_conn_cache_discard_paths)
{
	int sv_full[2] = { -1, -1 };
	int sv_long[2] = { -1, -1 };
	struct dialreq req = make_domain_req("discard.example");
	struct ev_loop *loop = ev_loop_new(0);

	T_CHECK(loop != NULL);
	reset_stub_state();
	loadlibs();

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv_full) == 0);
	conn_cache.len = CONN_CACHE_CAPACITY;
	conn_cache_put(loop, sv_full[0], &req);
	errno = 0;
	T_EXPECT(fcntl(sv_full[0], F_GETFD) == -1);
	T_EXPECT_EQ(errno, EBADF);
	T_EXPECT_EQ(conn_cache.len, (size_t)CONN_CACHE_CAPACITY);
	T_CHECK(close(sv_full[1]) == 0);
	loadlibs();

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv_long) == 0);
	STUB.dialreq_format_len_override = 256;
	conn_cache_put(loop, sv_long[0], &req);
	errno = 0;
	T_EXPECT(fcntl(sv_long[0], F_GETFD) == -1);
	T_EXPECT_EQ(errno, EBADF);
	T_EXPECT_EQ(conn_cache.len, (size_t)0);
	T_CHECK(close(sv_long[1]) == 0);

	ev_loop_destroy(loop);
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
	T_RUN_CASE(t, util_conn_cache_put_get_roundtrip);
	T_RUN_CASE(t, util_conn_cache_idle_close);
	T_RUN_CASE(t, util_conn_cache_expire_closes_fd);
	T_RUN_CASE(t, util_conn_cache_discard_paths);
#if WITH_SPLICE
	T_RUN_CASE(t, util_pipe_new_close);
	T_RUN_CASE(t, util_pipe_shrink);
#endif
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
