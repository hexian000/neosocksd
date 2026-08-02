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
#include "utils/testing.h"

#include <ev.h>

#if WITH_SPLICE
#include <dirent.h>
#endif
#include <fcntl.h>
#include <signal.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

/* Poll interval for test_wait_until: short enough that a completed transfer is
 * observed promptly, long enough not to spin. */
#define WAIT_POLL_INTERVAL 0.001 /* 1 ms */

/* Wakes ev_run(EVRUN_ONCE) each tick so test_wait_until re-checks its
 * predicate; it does no work itself. */
static void poll_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	(void)loop;
	(void)watcher;
	(void)revents;
}

/* Wait until predicate holds. With threads the transfer runs on a worker's
 * private loop (transfer_create discards the caller's loop) and has no way to
 * wake this loop, so a short repeating timer polls the predicate; without
 * threads the transfer runs inline during ev_run and the same poll is a
 * harmless backstop. The watchdog bounds a hung test. */
static bool test_wait_until(
	struct ev_loop *loop, bool (*predicate)(void *), void *data,
	const ev_tstamp timeout_sec)
{
	struct test_watchdog watchdog = { 0 };
	ev_timer w_timeout;

	ev_timer_init(&w_timeout, watchdog_cb, timeout_sec, 0.0);
	w_timeout.data = &watchdog;
	ev_timer_start(loop, &w_timeout);
	ev_timer w_poll;
	ev_timer_init(&w_poll, poll_cb, WAIT_POLL_INTERVAL, WAIT_POLL_INTERVAL);
	ev_timer_start(loop, &w_poll);
	while (!watchdog.fired && !predicate(data)) {
		ev_run(loop, EVRUN_ONCE);
	}
	ev_timer_stop(loop, &w_poll);
	ev_timer_stop(loop, &w_timeout);
	return predicate(data);
}

#if WITH_SPLICE
/* Count the process's open file descriptors via /proc/self/fd. With the loop,
 * worker and socketpairs all torn down at both measurement points, a splice
 * pipe left unreleased shows up as a nonzero delta. The opendir fd is present
 * in every count, so it cancels out. */
static int count_open_fds(void)
{
	DIR *const dir = opendir("/proc/self/fd");
	T_CHECK(dir != NULL);
	int count = 0;
	for (const struct dirent *ent = readdir(dir); ent != NULL;
	     ent = readdir(dir)) {
		if (ent->d_name[0] == '.') {
			continue;
		}
		count++;
	}
	T_CHECK(closedir(dir) == 0);
	return count;
}
#endif /* WITH_SPLICE */

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
	/* transfer_serve takes fd ownership */
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

	transfer_join(xfer);
	/* byt_up/byt_down are written by the worker with relaxed atomics; only
	 * transfer_join establishes the happens-before to read them safely */
	T_EXPECT_EQ((uintmax_t)state.byt_up, (uintmax_t)sizeof(uplink));
	T_EXPECT_EQ((uintmax_t)state.byt_down, (uintmax_t)sizeof(downlink));
	socket_close(acc_peer);
	socket_close(dial_peer);
	ev_loop_destroy(loop);
}

#if WITH_SPLICE
/* The normal FINISHED path must also release splice pipes, not only the
 * cancellation path. */
T_DECLARE_CASE(transfer_splice_releases_pipes_on_finish)
{
	const int fds_before = count_open_fds();
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

	transfer_join(xfer);
	/* byt_up/byt_down are written by the worker with relaxed atomics; only
	 * transfer_join establishes the happens-before to read them safely */
	T_EXPECT_EQ((uintmax_t)state.byt_up, (uintmax_t)sizeof(uplink));
	T_EXPECT_EQ((uintmax_t)state.byt_down, (uintmax_t)sizeof(downlink));
	socket_close(acc_peer);
	socket_close(dial_peer);
	ev_loop_destroy(loop);
	/* Every fd opened by this case is closed again: the splice pipes were
	 * released on the normal-completion path. */
	T_EXPECT_EQ(count_open_fds(), fds_before);
}

/*
 * The splice cancellation path must also release its pipes: drive the
 * shutdown-cancel teardown (transfer_join with the session still active) with
 * use_splice, so release_ctx's pipe-closing branch runs, and confirm no fd
 * leaks.
 */
T_DECLARE_CASE(transfer_splice_ctx_cancel_releases_pipes)
{
	const int fds_before = count_open_fds();
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
			.use_splice = true,
			.num_sessions = &state.num_sessions,
		}));
	acc_fd = dial_fd = -1;

	/*
	 * transfer_join runs the worker's queued start task (creating the
	 * pipes) before cancelling the still-active session, so release_ctx
	 * closes the pipes on the shutdown path.
	 */
	transfer_join(xfer);
	T_EXPECT_EQ((size_t)state.num_sessions, (size_t)0);

	socket_close(acc_peer);
	socket_close(dial_peer);
	ev_loop_destroy(loop);
	T_EXPECT_EQ(count_open_fds(), fds_before);
}
#endif /* WITH_SPLICE */

/*
 * Cancel must suppress the on_finished callback but still clean up all
 * internal resources.  transfer_join() joins the xfer thread, so after it
 * returns, no callback will arrive.
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
	 * transfer_join joins the xfer thread; in-flight transfers are
	 * cancelled and their num_sessions decrements execute before return.
	 */
	transfer_join(xfer);
	T_EXPECT_EQ(state.num_sessions, (size_t)0);

	socket_close(acc_peer);
	socket_close(dial_peer);
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
	socket_close(dial_peer);

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
	socket_close(acc_peer);
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
	for (;;) {
		const ssize_t n =
			send(dial_fd, fill, sizeof(fill), MSG_DONTWAIT);
		if (n <= 0) {
			break;
		}
		fill_bytes += (size_t)n;
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

	transfer_join(xfer);
	/* byt_up is written by the worker with relaxed atomics; only
	 * transfer_join establishes the happens-before to read it safely */
	T_EXPECT_EQ((uintmax_t)state.byt_up, (uintmax_t)1);
	socket_close(acc_peer);
	socket_close(dial_peer);
	ev_loop_destroy(loop);
}

/*
 * A payload larger than XFER_BUFSIZE while the destination is blocked drives
 * xfer_recv()'s receive buffer to saturation, exercising its `cap == 0`
 * early-return (receive-side backpressure), distinct from the send-side
 * backpressure covered above.
 */
T_DECLARE_CASE(transfer_recv_buffer_saturates_completes)
{
	/* a multiple of XFER_BUFSIZE so the payload always overflows one recv
	 * buffer and drives the xfer_recv cap == 0 early-return, tracking the
	 * real buffer size instead of a hardcoded copy */
	enum { PAYLOAD_SZ = 2 * XFER_BUFSIZE };
	static unsigned char payload[PAYLOAD_SZ];
	static const char fill[] = "recv-saturate-fill";
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct test_xfer_state state = { 0 };
	char drain[4096];

	for (size_t i = 0; i < PAYLOAD_SZ; i++) {
		payload[i] = (unsigned char)(i & 0xff);
	}

	make_socketpair(&acc_peer, &acc_fd);
	make_socketpair(&dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);
	set_nonblock(dial_peer);

	/* Block the downstream so the xfer cannot drain its receive buffer. */
	size_t fill_bytes = 0;
	for (;;) {
		const ssize_t n =
			send(dial_fd, fill, sizeof(fill), MSG_DONTWAIT);
		if (n <= 0) {
			break;
		}
		fill_bytes += (size_t)n;
	}

	/* Buffer the whole (> XFER_BUFSIZE) payload on the accepted side; with
	 * the downstream blocked, the xfer fills its buffer and hits cap == 0. */
	T_CHECK(send(acc_peer, payload, PAYLOAD_SZ, 0) == (ssize_t)PAYLOAD_SZ);
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

	/* Relieve backpressure by draining the pre-fill bytes; the xfer then
	 * forwards the whole payload. */
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

	T_EXPECT(test_wait_until(loop, xfer_finished, &state, 2.0));

	/* All payload bytes must have arrived at dial_peer. */
	size_t got = 0;
	while (got < PAYLOAD_SZ) {
		const ssize_t n =
			recv(dial_peer, drain, sizeof(drain), MSG_DONTWAIT);
		if (n <= 0) {
			break;
		}
		got += (size_t)n;
	}
	T_EXPECT_EQ((uintmax_t)got, (uintmax_t)PAYLOAD_SZ);

	transfer_join(xfer);
	/* byt_up is written by the worker with relaxed atomics; only
	 * transfer_join establishes the happens-before to read it safely */
	T_EXPECT_EQ((uintmax_t)state.byt_up, (uintmax_t)PAYLOAD_SZ);
	socket_close(acc_peer);
	socket_close(dial_peer);
	ev_loop_destroy(loop);
}

/*
 * With more than one worker, transfers are round-robin distributed across
 * per-worker loops/active-lists. Run several concurrent transfers through a
 * multi-worker engine and verify each completes with correct byte accounting,
 * exercising the distribution path and per-worker state independence that a
 * single-worker engine never reaches.
 */
T_DECLARE_CASE(transfer_multi_worker_all_complete)
{
	enum { NWORKERS = 4, NCONN = 8 };
	static const char uplink[] = "multi-worker-uplink";
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);
	struct test_xfer_state state = { 0 };
	int acc_peer[NCONN], dial_peer[NCONN];

	state.num_sessions = NCONN;
	struct transfer *restrict xfer = transfer_create(loop, NWORKERS);
	T_CHECK(xfer != NULL);

	for (int i = 0; i < NCONN; i++) {
		int acc_fd = -1, dial_fd = -1;
		make_socketpair(&acc_peer[i], &acc_fd);
		make_socketpair(&dial_fd, &dial_peer[i]);
		set_nonblock(acc_fd);
		set_nonblock(dial_fd);

		T_CHECK(send(acc_peer[i], uplink, sizeof(uplink), 0) ==
			(ssize_t)sizeof(uplink));
		T_CHECK(shutdown(acc_peer[i], SHUT_WR) == 0);
		T_CHECK(shutdown(dial_peer[i], SHUT_WR) == 0);

		T_CHECK(transfer_serve(
			xfer, acc_fd, dial_fd,
			&(struct transfer_opts){
				.byt_up = &state.byt_up,
				.byt_down = &state.byt_down,
				.num_sessions = &state.num_sessions,
			}));
	}

	T_EXPECT(test_wait_until(loop, xfer_finished, &state, 2.0));

	for (int i = 0; i < NCONN; i++) {
		char out[sizeof(uplink)] = { 0 };
		size_t got = 0;
		while (got < sizeof(out)) {
			const ssize_t n = recv(
				dial_peer[i], out + got, sizeof(out) - got, 0);
			if (n <= 0) {
				break;
			}
			got += (size_t)n;
		}
		T_EXPECT_EQ(got, sizeof(uplink));
		T_EXPECT_MEMEQ(out, uplink, sizeof(uplink));
	}

	transfer_join(xfer);
	/* byt_up is written by the workers with relaxed atomics; only
	 * transfer_join establishes the happens-before to read it safely */
	T_EXPECT_EQ(
		(uintmax_t)state.byt_up, (uintmax_t)(NCONN * sizeof(uplink)));
	for (int i = 0; i < NCONN; i++) {
		socket_close(acc_peer[i]);
		socket_close(dial_peer[i]);
	}
	ev_loop_destroy(loop);
}

/*
 * A client that abandons its connection must leave num_sessions at exactly
 * zero, never underflowed. The decrement runs on two distinct teardown paths
 * depending on when the client abandons relative to the transfer, so both are
 * driven explicitly rather than sampled by repeating one cycle and hoping the
 * scheduler varies the interleaving.
 */
T_DECLARE_CASE(transfer_serve_join_rapid_cycles)
{
	struct ev_loop *loop = ev_loop_new(0);
	T_CHECK(loop != NULL);

	/* false: join with the session still active, so transfer_join cancels
	 *        it (shutdown-cancel decrement).
	 * true:  close both write ends and let the session finish on its own
	 *        first, so join finds nothing to cancel (normal-completion
	 *        decrement, then a no-op join). */
	for (int finish_first = 0; finish_first <= 1; finish_first++) {
		int acc_peer = -1, acc_fd = -1;
		int dial_fd = -1, dial_peer = -1;
		struct test_xfer_state state = { 0 };

		make_socketpair(&acc_peer, &acc_fd);
		make_socketpair(&dial_fd, &dial_peer);
		set_nonblock(acc_fd);
		set_nonblock(dial_fd);

		if (finish_first) {
			T_CHECK(shutdown(acc_peer, SHUT_WR) == 0);
			T_CHECK(shutdown(dial_peer, SHUT_WR) == 0);
		}

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

		if (finish_first) {
			T_EXPECT(test_wait_until(
				loop, xfer_finished, &state, 1.0));
		}

		transfer_join(xfer);

		/* num_sessions must reach exactly zero, never negative. */
		T_EXPECT_EQ((size_t)state.num_sessions, (size_t)0);

		socket_close(acc_peer);
		socket_close(dial_peer);
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
	socket_close(acc_peer);
	socket_close(dial_peer);
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

	T_BENCH_LOOP () {
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

		T_CHECK(test_wait_until(loop, xfer_finished, &state, 1.0));

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
		T_CHECK(got == (size_t)PAYLOAD_SZ);

		socket_close(acc_peer);
		socket_close(dial_peer);
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
	T_CASE(transfer_splice_ctx_cancel_releases_pipes),
#endif
	T_CASE(transfer_ctx_cancel_no_callback),
	T_CASE(transfer_dst_error_finishes),
	T_CASE(transfer_backpressure_completes),
	T_CASE(transfer_recv_buffer_saturates_completes),
	T_CASE(transfer_multi_worker_all_complete),
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
