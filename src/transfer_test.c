/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "transfer.h"

#include "os/socket.h"
#include "util.h"
#include "utils/testing.h"

#include <ev.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct test_xfer_state {
#if WITH_THREADS
	atomic_size_t num_sessions;
	atomic_uintmax_t byt_up;
	atomic_uintmax_t byt_down;
#else
	size_t num_sessions;
	uintmax_t byt_up;
	uintmax_t byt_down;
#endif
};

#if WITH_SPLICE
static struct {
	int pipe_new_calls;
	int pipe_close_calls;
} PIPE_STUB = { 0 };

/* Stubs for splice pipe utilities — transfer_test always passes use_splice=false
 * so these are never called, but the linker requires them. */
struct pipe_cache pipe_cache = { 0 };

bool pipe_new(struct splice_pipe *restrict pipe)
{
	PIPE_STUB.pipe_new_calls++;
	if (pipe2(pipe->fd, O_NONBLOCK | O_CLOEXEC) != 0) {
		return false;
	}
	pipe->cap = 65536;
	pipe->len = 0;
	return true;
}

void pipe_close(struct splice_pipe *restrict pipe)
{
	PIPE_STUB.pipe_close_calls++;
	CLOSE_FD(pipe->fd[0]);
	CLOSE_FD(pipe->fd[1]);
	pipe->fd[0] = -1;
	pipe->fd[1] = -1;
}

void pipe_shrink(const size_t count)
{
	(void)count;
}

static void reset_pipe_stub_state(void)
{
	PIPE_STUB.pipe_new_calls = 0;
	PIPE_STUB.pipe_close_calls = 0;
	pipe_cache = (struct pipe_cache){ 0 };
}
#endif

static bool xfer_finished(void *data)
{
	const struct test_xfer_state *restrict s = data;
#if WITH_THREADS
	return atomic_load_explicit(&s->num_sessions, memory_order_relaxed) ==
	       0;
#else
	return s->num_sessions == 0;
#endif
}

struct test_watchdog {
	bool fired;
};

static void
watchdog_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	struct test_watchdog *const watchdog = watcher->data;

	UNUSED(revents);
	watchdog->fired = true;
	ev_break(loop, EVBREAK_ONE);
}

static void poll_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	UNUSED(loop);
	UNUSED(watcher);
	UNUSED(revents);
	ev_break(loop, EVBREAK_ONE);
}

static const ev_tstamp TEST_POLL_INTERVAL_SEC = 0.005;

static bool test_wait_until(
	struct ev_loop *loop, bool (*predicate)(void *), void *data,
	const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	ev_timer w_timeout;
	ev_timer w_poll;

	ev_timer_init(&w_timeout, watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	ev_timer_init(
		&w_poll, poll_cb, TEST_POLL_INTERVAL_SEC,
		TEST_POLL_INTERVAL_SEC);
	ev_timer_start(loop, &w_poll);
	while (!watchdog.fired) {
		if (predicate(data)) {
			ev_timer_stop(loop, &w_timeout);
			ev_timer_stop(loop, &w_poll);
			return true;
		}
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_timeout);
	ev_timer_stop(loop, &w_poll);
	return predicate(data);
}

static void make_socketpair(int *restrict a, int *restrict b)
{
	int sv[2] = { -1, -1 };

	T_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	*a = sv[0];
	*b = sv[1];
}

static void set_nonblock(const int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);

	T_CHECK(flags >= 0);
	T_CHECK(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
}

/*
 * Bidirectional transfer: write uplink payload from acc_peer and downlink
 * payload from dial_peer; verify both arrive at the opposite peers.
 */
T_DECLARE_CASE(test_transfer_moves_payload)
{
	static const char uplink[] = "neosocksd-uplink";
	static const char downlink[] = "downlink-data";
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct ev_loop *loop = EV_DEFAULT;
	struct test_xfer_state state = { 0 };
	char up_out[sizeof(uplink)] = { 0 };
	char dn_out[sizeof(downlink)] = { 0 };
	size_t got;

	make_socketpair(&acc_peer, &acc_fd);
	make_socketpair(&dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	/* Uplink: write from acc side and close the write end. */
	T_CHECK(send(acc_peer, uplink, sizeof(uplink), 0) ==
		(ssize_t)sizeof(uplink));
	T_CHECK(shutdown(acc_peer, SHUT_WR) == 0);
	/* Downlink: write from dial side and close the write end. */
	T_CHECK(send(dial_peer, downlink, sizeof(downlink), 0) ==
		(ssize_t)sizeof(downlink));
	T_CHECK(shutdown(dial_peer, SHUT_WR) == 0);

	state.num_sessions = 1;
	struct transfer *restrict xfer = transfer_new(loop);
	T_CHECK(xfer != NULL);

	T_CHECK(transfer_serve(
		xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &state.byt_up,
			.byt_down = &state.byt_down,
			.num_sessions = &state.num_sessions,
		}));
	/* transfer_ctx_new takes fd ownership */
	acc_fd = dial_fd = -1;

	T_EXPECT(test_wait_until(loop, xfer_finished, &state, 1.0));

	/* Uplink: acc_peer → acc_fd → dial_fd → dial_peer */
	got = 0;
	while (got < sizeof(up_out)) {
		const ssize_t n =
			recv(dial_peer, up_out + got, sizeof(up_out) - got, 0);
		if (n <= 0) {
			break;
		}
		got += (size_t)n;
	}
	T_EXPECT_EQ(got, sizeof(uplink));
	T_EXPECT_MEMEQ(up_out, uplink, sizeof(uplink));
	T_EXPECT_EQ((uintmax_t)state.byt_up, (uintmax_t)sizeof(uplink));

	/* Downlink: dial_peer → dial_fd → acc_fd → acc_peer */
	got = 0;
	while (got < sizeof(dn_out)) {
		const ssize_t n =
			recv(acc_peer, dn_out + got, sizeof(dn_out) - got, 0);
		if (n <= 0) {
			break;
		}
		got += (size_t)n;
	}
	T_EXPECT_EQ(got, sizeof(downlink));
	T_EXPECT_MEMEQ(dn_out, downlink, sizeof(downlink));
	T_EXPECT_EQ((uintmax_t)state.byt_down, (uintmax_t)sizeof(downlink));

	transfer_free(xfer);
	CLOSE_FD(acc_peer);
	CLOSE_FD(dial_peer);
}

#if WITH_SPLICE
/* The normal FINISHED path must also release splice pipes, not only the
 * cancellation path. */
T_DECLARE_CASE(test_transfer_splice_releases_pipes_on_finish)
{
	static const char uplink[] = "splice-uplink";
	static const char downlink[] = "splice-downlink";
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct ev_loop *loop = EV_DEFAULT;
	struct test_xfer_state state = { 0 };
	char up_out[sizeof(uplink)] = { 0 };
	char dn_out[sizeof(downlink)] = { 0 };
	size_t got;

	make_socketpair(&acc_peer, &acc_fd);
	make_socketpair(&dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	reset_pipe_stub_state();
	pipe_cache.cap = 0;
	pipe_cache.len = 0;

	T_CHECK(send(acc_peer, uplink, sizeof(uplink), 0) ==
		(ssize_t)sizeof(uplink));
	T_CHECK(shutdown(acc_peer, SHUT_WR) == 0);
	T_CHECK(send(dial_peer, downlink, sizeof(downlink), 0) ==
		(ssize_t)sizeof(downlink));
	T_CHECK(shutdown(dial_peer, SHUT_WR) == 0);

	state.num_sessions = 1;
	struct transfer *restrict xfer = transfer_new(loop);
	T_CHECK(xfer != NULL);

	T_CHECK(transfer_serve(
		xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &state.byt_up,
			.byt_down = &state.byt_down,
			.use_splice = true,
			.num_sessions = &state.num_sessions,
		}));
	acc_fd = dial_fd = -1;

	T_EXPECT(test_wait_until(loop, xfer_finished, &state, 1.0));
	T_EXPECT_EQ(PIPE_STUB.pipe_new_calls, 2);
	T_EXPECT_EQ(PIPE_STUB.pipe_close_calls, 2);

	got = 0;
	while (got < sizeof(up_out)) {
		const ssize_t n =
			recv(dial_peer, up_out + got, sizeof(up_out) - got, 0);
		if (n <= 0) {
			break;
		}
		got += (size_t)n;
	}
	T_EXPECT_EQ(got, sizeof(uplink));
	T_EXPECT_MEMEQ(up_out, uplink, sizeof(uplink));
	T_EXPECT_EQ((uintmax_t)state.byt_up, (uintmax_t)sizeof(uplink));

	got = 0;
	while (got < sizeof(dn_out)) {
		const ssize_t n =
			recv(acc_peer, dn_out + got, sizeof(dn_out) - got, 0);
		if (n <= 0) {
			break;
		}
		got += (size_t)n;
	}
	T_EXPECT_EQ(got, sizeof(downlink));
	T_EXPECT_MEMEQ(dn_out, downlink, sizeof(downlink));
	T_EXPECT_EQ((uintmax_t)state.byt_down, (uintmax_t)sizeof(downlink));

	transfer_free(xfer);
	CLOSE_FD(acc_peer);
	CLOSE_FD(dial_peer);
}
#endif

/*
 * Cancel must suppress the on_finished callback but still clean up all
 * internal resources.  transfer_free() joins the xfer thread and drains
 * main_disp, so after it returns, no callback will arrive.
 */
T_DECLARE_CASE(test_transfer_ctx_cancel_no_callback)
{
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct ev_loop *loop = EV_DEFAULT;
	struct test_xfer_state state = { 0 };

	make_socketpair(&acc_peer, &acc_fd);
	make_socketpair(&dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	state.num_sessions = 1;
	struct transfer *restrict xfer = transfer_new(loop);
	T_CHECK(xfer != NULL);

	T_CHECK(transfer_serve(
		xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &state.byt_up,
			.byt_down = &state.byt_down,
			.num_sessions = &state.num_sessions,
		}));
	acc_fd = dial_fd = -1;

	/*
	 * transfer_free joins the xfer thread; in-flight transfers are
	 * cancelled and their num_sessions decrements execute before return.
	 */
	transfer_free(xfer);
	T_EXPECT_EQ(state.num_sessions, (size_t)0);

	CLOSE_FD(acc_peer);
	CLOSE_FD(dial_peer);
}

/*
 * If the uplink destination has no reader, writes fail immediately.
 * The transfer must detect the error and call on_finished.
 */
T_DECLARE_CASE(test_transfer_dst_error_finishes)
{
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct ev_loop *loop = EV_DEFAULT;
	struct test_xfer_state state = { 0 };

	/* Prevent SIGPIPE when writing to a socket with no reader. */
	(void)signal(SIGPIPE, SIG_IGN);

	make_socketpair(&acc_peer, &acc_fd);
	make_socketpair(&dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	T_CHECK(send(acc_peer, "x", 1, 0) == 1);
	T_CHECK(shutdown(acc_peer, SHUT_WR) == 0);
	/* Close the read end of the uplink destination. */
	CLOSE_FD(dial_peer);

	state.num_sessions = 1;
	struct transfer *restrict xfer = transfer_new(loop);
	T_CHECK(xfer != NULL);

	T_CHECK(transfer_serve(
		xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &state.byt_up,
			.byt_down = &state.byt_down,
			.num_sessions = &state.num_sessions,
		}));
	acc_fd = dial_fd = -1;

	T_EXPECT(test_wait_until(loop, xfer_finished, &state, 1.0));

	transfer_free(xfer);
	CLOSE_FD(acc_peer);
}

/*
 * Pre-fill the uplink send buffer to exercise the EV_WRITE / backpressure
 * code path; verify the payload still arrives after the buffer is drained.
 */
T_DECLARE_CASE(test_transfer_backpressure_completes)
{
	static const char fill[] = "backpressure-fill";
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct ev_loop *loop = EV_DEFAULT;
	struct test_xfer_state state = { 0 };
	char drain[4096];

	make_socketpair(&acc_peer, &acc_fd);
	make_socketpair(&dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);
	set_nonblock(dial_peer);

	/* Fill the dial_fd → dial_peer send buffer to create uplink backpressure. */
	size_t fill_bytes = 0;
	while (send(dial_fd, fill, sizeof(fill), MSG_DONTWAIT) > 0) {
		fill_bytes += sizeof(fill);
	}

	/* One-byte uplink payload; no downlink data. */
	T_CHECK(send(acc_peer, "y", 1, 0) == 1);
	T_CHECK(shutdown(acc_peer, SHUT_WR) == 0);
	T_CHECK(shutdown(dial_peer, SHUT_WR) == 0);

	state.num_sessions = 1;
	struct transfer *restrict xfer = transfer_new(loop);
	T_CHECK(xfer != NULL);

	T_CHECK(transfer_serve(
		xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &state.byt_up,
			.byt_down = &state.byt_down,
			.num_sessions = &state.num_sessions,
		}));
	acc_fd = dial_fd = -1;

	/* Drain exactly the pre-filled bytes to relieve backpressure without
	 * racing against the xfer thread writing the payload byte. */
	{
		size_t remaining = fill_bytes;
		while (remaining > 0) {
			const size_t ask = remaining < sizeof(drain) ?
						   remaining :
						   sizeof(drain);
			const ssize_t n = recv(dial_peer, drain, ask, 0);
			if (n <= 0) {
				break;
			}
			remaining -= (size_t)n;
		}
	}

	/* Transfer should complete after backpressure is relieved. */
	T_EXPECT(test_wait_until(loop, xfer_finished, &state, 1.0));

	/* The one-byte payload must have arrived at dial_peer. */
	char out = 0;
	T_EXPECT_EQ(recv(dial_peer, &out, 1, MSG_DONTWAIT), (ssize_t)1);
	T_EXPECT_EQ(out, 'y');
	T_EXPECT_EQ((uintmax_t)state.byt_up, (uintmax_t)1);

	transfer_free(xfer);
	CLOSE_FD(acc_peer);
	CLOSE_FD(dial_peer);
}

int main(void)
{
	T_DECLARE_CTX(t);

	T_RUN_CASE(t, test_transfer_moves_payload);
	T_RUN_CASE(t, test_transfer_splice_releases_pipes_on_finish);
	T_RUN_CASE(t, test_transfer_ctx_cancel_no_callback);
	T_RUN_CASE(t, test_transfer_dst_error_finishes);
	T_RUN_CASE(t, test_transfer_backpressure_completes);
	return T_RESULT(t) ? EXIT_SUCCESS : EXIT_FAILURE;
}
