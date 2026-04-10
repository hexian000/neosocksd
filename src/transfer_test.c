/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "transfer.h"

#include "os/socket.h"
#include "utils/testing.h"

#include <ev.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if WITH_SPLICE
struct pipe_cache pipe_cache = {
	.cap = PIPE_MAXCACHED,
	.len = 0,
};

bool pipe_new(struct splice_pipe *restrict pipe)
{
	pipe->fd[0] = -1;
	pipe->fd[1] = -1;
	pipe->cap = 0;
	pipe->len = 0;
	return false;
}

void pipe_close(struct splice_pipe *restrict pipe)
{
	UNUSED(pipe);
}
#endif

struct state_trace {
	enum transfer_state states[8];
	size_t len;
};

struct transfer_cb_ctx {
	struct transfer *t;
	struct state_trace *trace;
};

struct test_watchdog {
	bool fired;
};

static void transfer_state_cb(struct ev_loop *loop, void *data)
{
	struct transfer_cb_ctx *ctx = data;

	UNUSED(loop);
	if (ctx->trace->len <
	    sizeof(ctx->trace->states) / sizeof(ctx->trace->states[0])) {
		ctx->trace->states[ctx->trace->len++] = ctx->t->state;
	}
}

static void
watchdog_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	struct test_watchdog *const watchdog = watcher->data;

	UNUSED(revents);
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

static void make_socketpair(int *restrict left_fd, int *restrict right_fd)
{
	int sv[2] = { -1, -1 };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	*left_fd = sv[0];
	*right_fd = sv[1];
}

static void set_nonblock(const int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);

	T_CHECK(flags >= 0);
	T_CHECK(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
}

static bool transfer_finished(void *data)
{
	const struct transfer *t = data;
	return t->state == XFER_FINISHED;
}

T_DECLARE_CASE(test_transfer_moves_payload_and_finishes_on_eof)
{
	static const char payload[] = "neosocksd-transfer-payload";
	int src_write = -1, src_read = -1;
	int dst_write = -1, dst_read = -1;
	struct ev_loop *loop = EV_DEFAULT;
	uintmax_t bytes = 0;
	struct state_trace trace = { 0 };
	struct transfer t;
	struct transfer_cb_ctx cb_ctx = {
		.t = &t,
		.trace = &trace,
	};
	struct transfer_state_cb cb = {
		.func = transfer_state_cb,
		.data = &cb_ctx,
	};
	char out[sizeof(payload)] = { 0 };
	size_t got = 0;

	make_socketpair(&src_write, &src_read);
	make_socketpair(&dst_write, &dst_read);
	set_nonblock(src_read);
	set_nonblock(dst_write);

	transfer_init(&t, &cb, src_read, dst_write, &bytes, true, false);
	T_CHECK(send(src_write, payload, sizeof(payload), 0) ==
		(ssize_t)sizeof(payload));
	T_CHECK(shutdown(src_write, SHUT_WR) == 0);
	transfer_start(loop, &t);

	T_EXPECT(test_wait_until(loop, transfer_finished, &t, 0.5));
	while (got < sizeof(out)) {
		const ssize_t n =
			recv(dst_read, out + got, sizeof(out) - got, 0);
		if (n <= 0) {
			break;
		}
		got += (size_t)n;
	}

	T_EXPECT_EQ(bytes, sizeof(payload));
	T_EXPECT_EQ(got, sizeof(payload));
	T_EXPECT_MEMEQ(out, payload, sizeof(payload));
	T_EXPECT(trace.len > 0);
	T_EXPECT_EQ(trace.states[trace.len - 1], XFER_FINISHED);

	CLOSE_FD(src_write);
	CLOSE_FD(src_read);
	CLOSE_FD(dst_write);
	CLOSE_FD(dst_read);
}

T_DECLARE_CASE(test_transfer_stop_marks_finished)
{
	int src_write = -1, src_read = -1;
	int dst_write = -1, dst_read = -1;
	struct ev_loop *loop = EV_DEFAULT;
	uintmax_t bytes = 0;
	struct state_trace trace = { 0 };
	struct transfer t;
	struct transfer_cb_ctx cb_ctx = {
		.t = &t,
		.trace = &trace,
	};
	struct transfer_state_cb cb = {
		.func = transfer_state_cb,
		.data = &cb_ctx,
	};

	make_socketpair(&src_write, &src_read);
	make_socketpair(&dst_write, &dst_read);
	set_nonblock(src_read);
	set_nonblock(dst_write);

	transfer_init(&t, &cb, src_read, dst_write, &bytes, false, false);
	transfer_start(loop, &t);
	transfer_stop(loop, &t);

	T_EXPECT_EQ(t.state, XFER_FINISHED);

	CLOSE_FD(src_write);
	CLOSE_FD(src_read);
	CLOSE_FD(dst_write);
	CLOSE_FD(dst_read);
}

int main(void)
{
	T_DECLARE_CTX(t);

	T_RUN_CASE(t, test_transfer_moves_payload_and_finishes_on_eof);
	T_RUN_CASE(t, test_transfer_stop_marks_finished);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
