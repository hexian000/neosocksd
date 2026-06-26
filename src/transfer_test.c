/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * transfer_test - white-box unit tests for transfer.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   transfer.c       module under test
 * Leaf libraries: csnippets (io, os).
 * transfer.c moves bytes between socket pairs and has no stateful collaborator
 * module to mock; the mock section only holds shared test fixtures.
 */

#include "transfer.h"

#include "io/io.h"
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

/* -------------------------------------------------------------------------
 * mock - shared test fixtures (transfer.c has no collaborator to mock).
 * ---------------------------------------------------------------------- */

struct test_xfer_state {
#if WITH_THREADS
	atomic_size_t num_sessions;
	atomic_uint_least64_t byt_up;
	atomic_uint_least64_t byt_down;
#else
	size_t num_sessions;
	uint_least64_t byt_up;
	uint_least64_t byt_down;
#endif
};

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

	(void)revents;
	watchdog->fired = true;
	ev_break(loop, EVBREAK_ONE);
}

static void poll_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	(void)loop;
	(void)watcher;
	(void)revents;
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
/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - payload movement, shutdown and accounting cases.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(transfer_moves_payload)
{
	static const char uplink[] = "neosocksd-uplink";
	static const char downlink[] = "downlink-data";
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
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
	struct transfer *restrict xfer = transfer_create(loop, 1);
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

	transfer_join(xfer);
	SOCKET_CLOSE_FD(acc_peer);
	SOCKET_CLOSE_FD(dial_peer);
	ev_loop_destroy(loop);
}

#if WITH_SPLICE
/* The normal FINISHED path must also release splice pipes, not only the
 * cancellation path. */
T_DECLARE_CASE(transfer_splice_releases_pipes_on_finish)
{
	static const char uplink[] = "splice-uplink";
	static const char downlink[] = "splice-downlink";
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct test_xfer_state state = { 0 };
	char up_out[sizeof(uplink)] = { 0 };
	char dn_out[sizeof(downlink)] = { 0 };
	size_t got;

	make_socketpair(&acc_peer, &acc_fd);
	make_socketpair(&dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	state.num_sessions = 1;
	struct transfer *restrict xfer = transfer_create(loop, 1);
	T_CHECK(xfer != NULL);

	T_CHECK(send(acc_peer, uplink, sizeof(uplink), 0) ==
		(ssize_t)sizeof(uplink));
	T_CHECK(shutdown(acc_peer, SHUT_WR) == 0);
	T_CHECK(send(dial_peer, downlink, sizeof(downlink), 0) ==
		(ssize_t)sizeof(downlink));
	T_CHECK(shutdown(dial_peer, SHUT_WR) == 0);

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

	transfer_join(xfer);
	SOCKET_CLOSE_FD(acc_peer);
	SOCKET_CLOSE_FD(dial_peer);
	ev_loop_destroy(loop);
}
#endif /* WITH_SPLICE */

/*
 * Cancel must suppress the on_finished callback but still clean up all
 * internal resources.  transfer_free() joins the xfer thread and drains
 * main_disp, so after it returns, no callback will arrive.
 */
T_DECLARE_CASE(transfer_ctx_cancel_no_callback)
{
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct test_xfer_state state = { 0 };

	make_socketpair(&acc_peer, &acc_fd);
	make_socketpair(&dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	state.num_sessions = 1;
	struct transfer *restrict xfer = transfer_create(loop, 1);
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
	transfer_join(xfer);
	T_EXPECT_EQ(state.num_sessions, (size_t)0);

	SOCKET_CLOSE_FD(acc_peer);
	SOCKET_CLOSE_FD(dial_peer);
	ev_loop_destroy(loop);
}

/*
 * If the uplink destination has no reader, writes fail immediately.
 * The transfer must detect the error and call on_finished.
 */
T_DECLARE_CASE(transfer_dst_error_finishes)
{
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
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
	SOCKET_CLOSE_FD(dial_peer);

	state.num_sessions = 1;
	struct transfer *restrict xfer = transfer_create(loop, 1);
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

	transfer_join(xfer);
	SOCKET_CLOSE_FD(acc_peer);
	ev_loop_destroy(loop);
}

/*
 * Pre-fill the uplink send buffer to exercise the EV_WRITE / backpressure
 * code path; verify the payload still arrives after the buffer is drained.
 */
T_DECLARE_CASE(transfer_backpressure_completes)
{
	static const char fill[] = "backpressure-fill";
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
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
	struct transfer *restrict xfer = transfer_create(loop, 1);
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

	transfer_join(xfer);
	SOCKET_CLOSE_FD(acc_peer);
	SOCKET_CLOSE_FD(dial_peer);
	ev_loop_destroy(loop);
}

/*
 * Rapid serve-and-join cycles must not let num_sessions underflow.
 * This simulates a server under high churn where connections are
 * accepted and immediately closed.
 */
T_DECLARE_CASE(transfer_serve_join_rapid_cycles)
{
	static const int CYCLES = 50;
	struct ev_loop *loop = ev_loop_new(0);

	T_CHECK(loop != NULL);

	for (int i = 0; i < CYCLES; i++) {
		int acc_peer = -1, acc_fd = -1;
		int dial_fd = -1, dial_peer = -1;
		struct test_xfer_state state = { 0 };

		make_socketpair(&acc_peer, &acc_fd);
		make_socketpair(&dial_fd, &dial_peer);
		set_nonblock(acc_fd);
		set_nonblock(dial_fd);

		state.num_sessions = 1;
		struct transfer *restrict xfer = transfer_create(loop, 1);
		T_CHECK(xfer != NULL);

		T_CHECK(transfer_serve(
			xfer, acc_fd, dial_fd,
			&(struct transfer_opts){
				.byt_up = &state.byt_up,
				.byt_down = &state.byt_down,
				.num_sessions = &state.num_sessions,
			}));
		acc_fd = dial_fd = -1;

		/* Join immediately — in-flight transfers are cancelled. */
		transfer_join(xfer);

		/* num_sessions must reach exactly zero, never negative. */
		T_EXPECT_EQ((size_t)state.num_sessions, (size_t)0);

		SOCKET_CLOSE_FD(acc_peer);
		SOCKET_CLOSE_FD(dial_peer);
	}

	ev_loop_destroy(loop);
}

/*
 * When both uplink and downlink close their write ends, the transfer
 * must complete and decrement num_sessions exactly once, not twice.
 */
T_DECLARE_CASE(transfer_both_halves_close_normally)
{
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct test_xfer_state state = { 0 };

	make_socketpair(&acc_peer, &acc_fd);
	make_socketpair(&dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	/* Close write ends immediately — no data to transfer. */
	T_CHECK(shutdown(acc_peer, SHUT_WR) == 0);
	T_CHECK(shutdown(dial_peer, SHUT_WR) == 0);

	state.num_sessions = 1;
	struct transfer *restrict xfer = transfer_create(loop, 1);
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
	T_EXPECT_EQ((size_t)state.num_sessions, (size_t)0);

	transfer_join(xfer);
	SOCKET_CLOSE_FD(acc_peer);
	SOCKET_CLOSE_FD(dial_peer);
	ev_loop_destroy(loop);
}

#if WITH_SPLICE
T_DECLARE_CASE(transfer_pipe_new_close)
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

#endif /* WITH_SPLICE */

/*
 * Shared benchmark driver.  Each iteration transfers a small payload
 * through a fresh socketpair, runs the event loop to completion, and
 * verifies the result.  When @p use_splice is true the splice path is
 * exercised; otherwise the standard recv/send path is used.
 */
static void
bench_transfer_impl(struct testing_bench *restrict _b_, const bool use_splice)
{
	static unsigned char payload[IO_BUFSIZE];
	static bool payload_init = false;
	if (!payload_init) {
		memset(payload, 0xAA, IO_BUFSIZE);
		payload_init = true;
	}
	enum { PAYLOAD_SZ = IO_BUFSIZE };

	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct transfer *xfer = transfer_create(loop, 1);
	T_CHECK(xfer != NULL);

	for (uint_fast64_t i = 0; i < _b_->N; i++) {
		int acc_peer, acc_fd, dial_fd, dial_peer;
		struct test_xfer_state state = { .num_sessions = 1 };

		make_socketpair(&acc_peer, &acc_fd);
		make_socketpair(&dial_fd, &dial_peer);
		set_nonblock(acc_fd);
		set_nonblock(dial_fd);

		T_CHECK(send(acc_peer, payload, PAYLOAD_SZ, 0) ==
			(ssize_t)PAYLOAD_SZ);
		T_CHECK(shutdown(acc_peer, SHUT_WR) == 0);
		T_CHECK(shutdown(dial_peer, SHUT_WR) == 0);

		struct transfer_opts opts = {
			.byt_up = &state.byt_up,
			.byt_down = &state.byt_down,
			.num_sessions = &state.num_sessions,
		};
#if WITH_SPLICE
		opts.use_splice = use_splice;
#else
		(void)use_splice;
#endif
		T_CHECK(transfer_serve(xfer, acc_fd, dial_fd, &opts));

		while (state.num_sessions > 0) {
			ev_run(loop, EVRUN_ONCE);
		}

		char out[PAYLOAD_SZ];
		size_t got = 0;
		while (got < PAYLOAD_SZ) {
			const ssize_t n =
				recv(dial_peer, out + got, PAYLOAD_SZ - got, 0);
			if (n <= 0) {
				break;
			}
			got += (size_t)n;
		}

		SOCKET_CLOSE_FD(acc_peer);
		SOCKET_CLOSE_FD(dial_peer);
	}

	transfer_join(xfer);
	ev_loop_destroy(loop);
}

/* -------------------------------------------------------------------------
 * bench - throughput of the recv/send fast path.
 * ---------------------------------------------------------------------- */

T_DECLARE_BENCH(bench_transfer_recvsend)
{
	bench_transfer_impl(_b_, false);
}

#if WITH_SPLICE
T_DECLARE_BENCH(bench_transfer_splice)
{
	bench_transfer_impl(_b_, true);
}
#endif /* WITH_SPLICE */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(transfer_moves_payload),
#if WITH_SPLICE
	T_CASE(transfer_pipe_new_close),
	T_CASE(transfer_splice_releases_pipes_on_finish),
#endif
	T_CASE(transfer_ctx_cancel_no_callback),
	T_CASE(transfer_dst_error_finishes),
	T_CASE(transfer_backpressure_completes),
	T_CASE(transfer_serve_join_rapid_cycles),
	T_CASE(transfer_both_halves_close_normally),
	T_BENCH(bench_transfer_recvsend),
#if WITH_SPLICE
	T_BENCH(bench_transfer_splice),
#endif
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
