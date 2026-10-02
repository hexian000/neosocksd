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
#if WITH_THREADS
#include "sync/dispatcher.h"
#include "sync/task.h"
#endif
#include "utils/testing.h"

#include <ev.h>

#if WITH_SPLICE
#include <dirent.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mock - shared test fixtures (transfer.c has no collaborator to mock).
 * ---------------------------------------------------------------------- */

struct test_xfer_state {
	xfer_session_counter num_sessions;
	xfer_counter byt_up;
	xfer_counter byt_down;
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

#if WITH_THREADS
/* Shutdown-race harness: while armed, an in-loop
 * dispatcher_tick leaves the worker's queue untouched, as one that ran just
 * before a start task was enqueued would, and ev_break disarms it at the loop
 * exit -- so the drain under test is the only one that runs. */
static atomic_bool skip_tick;

void test_dispatcher_tick(struct dispatcher *d)
{
	if (atomic_load(&skip_tick)) {
		return;
	}
	dispatcher_tick(d);
}

void test_ev_break(struct ev_loop *loop, const int how)
{
	atomic_store(&skip_tick, false);
	ev_break(loop, how);
}

/* Queue-full harness: while armed, the next start task is refused as a worker
 * dispatch queue at capacity refuses it. One-shot, so an arm is consumed by
 * the transfer_serve it targets and never leaks into a later call. */
static atomic_bool fail_invoke;

bool test_dispatcher_invoke(struct dispatcher *d, const struct task task)
{
	if (atomic_exchange(&fail_invoke, false)) {
		return false;
	}
	return dispatcher_invoke(d, task);
}
#endif /* WITH_THREADS */

#if WITH_SPLICE
/* Pipe-failure harness: the next pipe2_failures calls fail with EMFILE, as
 * pipe2 does once the process is out of descriptors. Armed before
 * transfer_serve and read back after transfer_join, both of which order it
 * against the worker thread that consumes it. */
static int pipe2_failures;

int test_pipe2(int fd[2], const int flags)
{
	if (pipe2_failures > 0) {
		pipe2_failures--;
		errno = EMFILE;
		return -1;
	}
	return pipe2(fd, flags);
}
#endif /* WITH_SPLICE */

/* Only the selected half is observed. Configuration is installed before the
 * start task and cleared after join; progress flags cross threads atomically. */
struct io_probe_state {
	int src_fd, dst_fd;
	bool saturate;
	size_t received, recv_calls, full_recv_calls;
	bool full_attempt;
	struct ev_loop *loop;
	ev_io *watcher;
	atomic_bool blocked, write_watcher, full_buffer;
};

static struct io_probe_state io_probe = { .src_fd = -1, .dst_fd = -1 };

ssize_t test_recv(const int fd, void *buf, const size_t len, const int flags)
{
	const ssize_t n = recv(fd, buf, len, flags);
	if (fd == io_probe.src_fd) {
		io_probe.recv_calls++;
		if (n > 0) {
			io_probe.received += (size_t)n;
		}
	}
	return n;
}

ssize_t
test_send(const int fd, const void *buf, const size_t len, const int flags)
{
	const ssize_t n = send(fd, buf, len, flags);
	const int err = errno;
	if (fd != io_probe.dst_fd || n >= 0 ||
	    (err != EAGAIN && err != EWOULDBLOCK)) {
		return n;
	}
	atomic_store(&io_probe.blocked, true);
	if (io_probe.saturate && io_probe.received == XFER_BUFSIZE &&
	    len == XFER_BUFSIZE) {
		if (io_probe.full_attempt &&
		    io_probe.recv_calls == io_probe.full_recv_calls) {
			/* A second pump tried the full buffer without making a
			 * recv syscall: xfer_recv's cap == 0 return executed. */
			atomic_store(&io_probe.full_buffer, true);
		}
		io_probe.full_attempt = true;
		io_probe.full_recv_calls = io_probe.recv_calls;
	}
	/* A spurious writable notification is safe to handle while the socket
	 * remains full. Feed it on the owning loop to retry the receive side,
	 * including fragmented receives and the full-buffer early return. */
	if (io_probe.saturate && io_probe.watcher != NULL &&
	    !atomic_load(&io_probe.full_buffer)) {
		ev_feed_event(io_probe.loop, io_probe.watcher, EV_WRITE);
	}
	errno = err;
	return n;
}

void test_ev_io_start(struct ev_loop *loop, ev_io *watcher)
{
	ev_io_start(loop, watcher);
	if (watcher->fd == io_probe.dst_fd && (watcher->events & EV_WRITE)) {
		io_probe.loop = loop;
		io_probe.watcher = watcher;
		atomic_store(&io_probe.write_watcher, true);
		if (io_probe.saturate) {
			ev_feed_event(loop, watcher, EV_WRITE);
		}
	}
}

static bool send_blocked(void *data)
{
	(void)data;
	return atomic_load(&io_probe.blocked) &&
	       atomic_load(&io_probe.write_watcher);
}

static bool receive_buffer_full(void *data)
{
	(void)data;
	return send_blocked(NULL) && atomic_load(&io_probe.full_buffer);
}

enum { FIXTURE_FDS_MAX = 32 };

struct cleanup_observation {
	bool cleaned;
	size_t sessions;
	int fds[4];
};

static struct cleanup_observation *cleanup_observer;

struct test_fixture {
	struct ev_loop *loop;
	struct transfer *xfer;
	struct test_xfer_state state;
	int fds[FIXTURE_FDS_MAX];
	size_t num_fds;
	struct cleanup_observation *observation;
	bool has_sigpipe;
	struct sigaction old_sigpipe;
#if WITH_THREADS
	bool has_mask, has_sys, has_usr2;
	sigset_t oldmask;
	struct sigaction old_sys, old_usr2;
#endif
#if WITH_SPLICE
	struct splice_pipe pipe;
#endif
};

static void fixture_join(struct test_fixture *fixture)
{
	transfer_join(fixture->xfer);
	fixture->xfer = NULL;
}

static void fixture_forget_fd(struct test_fixture *fixture, const int fd)
{
	for (size_t i = 0; i < fixture->num_fds; i++) {
		if (fixture->fds[i] == fd) {
			fixture->fds[i] = -1;
			return;
		}
	}
}

static void fixture_close(struct test_fixture *fixture, const int fd)
{
	socket_close(fd);
	fixture_forget_fd(fixture, fd);
}

#if WITH_THREADS
static int take_pending(const int signo);
#endif

static void fixture_finish(struct test_fixture *fixture)
{
	/* Join before releasing the heap counters or resetting a worker's
	 * injector. The same order holds after a failed expectation. */
	fixture_join(fixture);
	io_probe = (struct io_probe_state){ .src_fd = -1, .dst_fd = -1 };
#if WITH_THREADS
	atomic_store(&skip_tick, false);
	atomic_store(&fail_invoke, false);
	if (fixture->has_mask) {
		(void)take_pending(SIGSYS);
		(void)take_pending(SIGUSR2);
	}
	if (fixture->has_sys) {
		T_CHECK(sigaction(SIGSYS, &fixture->old_sys, NULL) == 0);
		fixture->has_sys = false;
	}
	if (fixture->has_usr2) {
		T_CHECK(sigaction(SIGUSR2, &fixture->old_usr2, NULL) == 0);
		fixture->has_usr2 = false;
	}
	if (fixture->has_mask) {
		T_CHECK(pthread_sigmask(SIG_SETMASK, &fixture->oldmask, NULL) ==
			0);
		fixture->has_mask = false;
	}
#endif /* WITH_THREADS */
#if WITH_SPLICE
	pipe2_failures = 0;
	pipe_close(&fixture->pipe);
#endif
	if (fixture->has_sigpipe) {
		T_CHECK(sigaction(SIGPIPE, &fixture->old_sigpipe, NULL) == 0);
		fixture->has_sigpipe = false;
	}
	for (size_t i = 0; i < fixture->num_fds; i++) {
		if (fixture->fds[i] != -1) {
			socket_close(fixture->fds[i]);
			fixture->fds[i] = -1;
		}
	}
	if (fixture->loop != NULL) {
		ev_loop_destroy(fixture->loop);
		fixture->loop = NULL;
	}
}

static void fixture_cleanup(void *data)
{
	struct test_fixture *fixture = data;
	fixture_finish(fixture);
	if (fixture->observation != NULL) {
		fixture->observation->sessions =
			(size_t)fixture->state.num_sessions;
		fixture->observation->cleaned = true;
	}
	free(fixture);
}

T_DECLARE_SUBCASE(fixture_setup, struct test_fixture **out)
{
	struct test_fixture *fixture = calloc(1, sizeof(*fixture));
	T_EXPECT(fixture != NULL);
#if WITH_THREADS
	atomic_init(&fixture->state.num_sessions, 0);
	atomic_init(&fixture->state.byt_up, 0);
	atomic_init(&fixture->state.byt_down, 0);
#endif
#if WITH_SPLICE
	fixture->pipe.fd[0] = fixture->pipe.fd[1] = -1;
#endif
	T_CLEANUP(fixture_cleanup, fixture);
	fixture->loop = ev_loop_new(0);
	T_EXPECT(fixture->loop != NULL);
	*out = fixture;
}

static void fixture_socketpair(
	struct test_fixture *fixture, int *restrict a, int *restrict b)
{
	T_CHECK(fixture->num_fds + 2 <= FIXTURE_FDS_MAX);
	make_socketpair(a, b);
	fixture->fds[fixture->num_fds++] = *a;
	fixture->fds[fixture->num_fds++] = *b;
}

static bool fixture_serve(
	struct test_fixture *fixture, struct transfer *xfer, const int acc_fd,
	const int dial_fd, const struct transfer_opts *opts)
{
	if (!transfer_serve(xfer, acc_fd, dial_fd, opts)) {
		return false;
	}
	fixture_forget_fd(fixture, acc_fd);
	fixture_forget_fd(fixture, dial_fd);
	return true;
}

/* Accumulates the bytes one peer socket receives, plus the relayed EOF. */
struct test_relay_sink {
	int fd;
	unsigned char *data;
	size_t cap, len;
	bool eof;
};

/* test_wait_until predicate: the peer has received cap bytes. */
static bool sink_filled(void *data)
{
	struct test_relay_sink *restrict sink = data;
	while (sink->len < sink->cap) {
		const ssize_t n =
			recv(sink->fd, sink->data + sink->len,
			     sink->cap - sink->len, MSG_DONTWAIT);
		if (n <= 0) {
			break;
		}
		sink->len += (size_t)n;
	}
	return sink->len == sink->cap;
}

/* test_wait_until predicate: the peer has received the relayed EOF; whatever
 * arrives before it is accumulated. The sink must have room to spare, so a
 * zero-length recv can never be mistaken for the EOF. */
static bool sink_reached_eof(void *data)
{
	struct test_relay_sink *restrict sink = data;
	while (!sink->eof) {
		T_CHECK(sink->len < sink->cap);
		const ssize_t n =
			recv(sink->fd, sink->data + sink->len,
			     sink->cap - sink->len, MSG_DONTWAIT);
		if (n < 0) {
			break;
		}
		if (n == 0) {
			sink->eof = true;
			break;
		}
		sink->len += (size_t)n;
	}
	return sink->eof;
}

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - payload movement, shutdown and accounting cases.
 * ---------------------------------------------------------------------- */

/* Run only inside the nested runner below: abandoning this case must leave
 * no engine accessing counters and no descriptors owned by its fixture. */
T_DECLARE_CASE(fixture_intentional_failure)
{
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	fixture->observation = cleanup_observer;
	int acc_peer, acc_fd, dial_fd, dial_peer;
	fixture_socketpair(fixture, &acc_peer, &acc_fd);
	fixture_socketpair(fixture, &dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);
	memcpy(cleanup_observer->fds, fixture->fds,
	       sizeof(cleanup_observer->fds));
	const struct sigaction ignore = { .sa_handler = SIG_IGN };
	T_EXPECT(sigaction(SIGPIPE, &ignore, &fixture->old_sigpipe) == 0);
	fixture->has_sigpipe = true;
#if WITH_THREADS
	sigset_t probes;
	T_EXPECT(sigemptyset(&probes) == 0);
	T_EXPECT(sigaddset(&probes, SIGSYS) == 0);
	T_EXPECT(sigaddset(&probes, SIGUSR2) == 0);
	T_EXPECT(pthread_sigmask(SIG_BLOCK, &probes, &fixture->oldmask) == 0);
	fixture->has_mask = true;
	T_EXPECT(sigaction(SIGSYS, &ignore, &fixture->old_sys) == 0);
	fixture->has_sys = true;
	T_EXPECT(sigaction(SIGUSR2, &ignore, &fixture->old_usr2) == 0);
	fixture->has_usr2 = true;
#endif /* WITH_THREADS */
	fixture->state.num_sessions = 1;
	fixture->xfer = transfer_create(fixture->loop, 1);
	T_EXPECT(fixture->xfer != NULL);
#if WITH_THREADS
	atomic_store(&skip_tick, true);
#endif
	T_EXPECT(fixture_serve(
		fixture, fixture->xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &fixture->state.byt_up,
			.byt_down = &fixture->state.byt_down,
			.num_sessions = &fixture->state.num_sessions,
		}));
#if WITH_THREADS
	atomic_store(&fail_invoke, true);
#endif
#if WITH_SPLICE
	pipe2_failures = 3;
#endif
	T_FATAL("intentional failure to verify fixture cleanup");
}

T_DECLARE_CASE(transfer_failed_expectation_cleans_fixture)
{
	struct sigaction old_pipe, restored;
	T_EXPECT(sigaction(SIGPIPE, NULL, &old_pipe) == 0);
#if WITH_THREADS
	sigset_t oldmask, restored_mask;
	struct sigaction old_sys, old_usr2;
	T_EXPECT(pthread_sigmask(SIG_BLOCK, NULL, &oldmask) == 0);
	T_EXPECT(sigaction(SIGSYS, NULL, &old_sys) == 0);
	T_EXPECT(sigaction(SIGUSR2, NULL, &old_usr2) == 0);
#endif
	struct cleanup_observation observation = { 0 };
	cleanup_observer = &observation;
	T_DECLARE_CTX(nested);
	T_RUN_CASE(nested, fixture_intentional_failure);
	cleanup_observer = NULL;
	T_EXPECT_EQ(nested.failed, 1);
	T_EXPECT(observation.cleaned);
	T_EXPECT_EQ(observation.sessions, 0);
	T_EXPECT(sigaction(SIGPIPE, NULL, &restored) == 0);
	T_EXPECT(restored.sa_handler == old_pipe.sa_handler);
	for (size_t i = 0;
	     i < sizeof(observation.fds) / sizeof(observation.fds[0]); i++) {
		T_EXPECT_EQ(fcntl(observation.fds[i], F_GETFD), -1);
		T_EXPECT_EQ(errno, EBADF);
	}
#if WITH_THREADS
	T_EXPECT(!atomic_load(&skip_tick));
	T_EXPECT(!atomic_load(&fail_invoke));
	T_EXPECT(pthread_sigmask(SIG_BLOCK, NULL, &restored_mask) == 0);
	T_EXPECT_EQ(
		sigismember(&restored_mask, SIGSYS),
		sigismember(&oldmask, SIGSYS));
	T_EXPECT_EQ(
		sigismember(&restored_mask, SIGUSR2),
		sigismember(&oldmask, SIGUSR2));
	T_EXPECT(sigaction(SIGSYS, NULL, &restored) == 0);
	T_EXPECT(restored.sa_handler == old_sys.sa_handler);
	T_EXPECT(sigaction(SIGUSR2, NULL, &restored) == 0);
	T_EXPECT(restored.sa_handler == old_usr2.sa_handler);
#endif /* WITH_THREADS */
#if WITH_SPLICE
	T_EXPECT_EQ(pipe2_failures, 0);
#endif
}

/*
 * Bidirectional transfer: write uplink payload from acc_peer and downlink
 * payload from dial_peer; verify both arrive at the opposite peers.
 */
T_DECLARE_CASE(transfer_moves_payload)
{
	static const char uplink[] = "neosocksd-uplink";
	static const char downlink[] = "downlink-data";
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct ev_loop *loop = fixture->loop;
	T_CHECK(loop != NULL);
	struct test_xfer_state *state = &fixture->state;
	char up_out[sizeof(uplink)] = { 0 };
	char dn_out[sizeof(downlink)] = { 0 };
	size_t got;

	fixture_socketpair(fixture, &acc_peer, &acc_fd);
	fixture_socketpair(fixture, &dial_fd, &dial_peer);
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

	state->num_sessions = 1;
	fixture->xfer = transfer_create(loop, 1);
	struct transfer *restrict xfer = fixture->xfer;
	T_CHECK(xfer != NULL);

	T_CHECK(fixture_serve(
		fixture, xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &state->byt_up,
			.byt_down = &state->byt_down,
			.num_sessions = &state->num_sessions,
		}));
	/* transfer_serve takes fd ownership */
	acc_fd = dial_fd = -1;

	T_EXPECT(test_wait_until(loop, xfer_finished, state, 1.0));

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

	fixture_join(fixture);
	/* byt_up/byt_down are written by the worker with relaxed atomics; only
	 * transfer_join establishes the happens-before to read them safely */
	T_EXPECT_EQ((uintmax_t)state->byt_up, (uintmax_t)sizeof(uplink));
	T_EXPECT_EQ((uintmax_t)state->byt_down, (uintmax_t)sizeof(downlink));
	fixture_close(fixture, acc_peer);
	fixture_close(fixture, dial_peer);
	fixture_finish(fixture);
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
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct ev_loop *loop = fixture->loop;
	T_CHECK(loop != NULL);
	struct test_xfer_state *state = &fixture->state;
	char up_out[sizeof(uplink)] = { 0 };
	char dn_out[sizeof(downlink)] = { 0 };
	size_t got;

	fixture_socketpair(fixture, &acc_peer, &acc_fd);
	fixture_socketpair(fixture, &dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	state->num_sessions = 1;
	fixture->xfer = transfer_create(loop, 1);
	struct transfer *restrict xfer = fixture->xfer;
	T_CHECK(xfer != NULL);

	T_CHECK(send(acc_peer, uplink, sizeof(uplink), 0) ==
		(ssize_t)sizeof(uplink));
	T_CHECK(shutdown(acc_peer, SHUT_WR) == 0);
	T_CHECK(send(dial_peer, downlink, sizeof(downlink), 0) ==
		(ssize_t)sizeof(downlink));
	T_CHECK(shutdown(dial_peer, SHUT_WR) == 0);

	T_CHECK(fixture_serve(
		fixture, xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &state->byt_up,
			.byt_down = &state->byt_down,
			.use_splice = true,
			.num_sessions = &state->num_sessions,
		}));
	acc_fd = dial_fd = -1;

	T_EXPECT(test_wait_until(loop, xfer_finished, state, 1.0));

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

	fixture_join(fixture);
	/* byt_up/byt_down are written by the worker with relaxed atomics; only
	 * transfer_join establishes the happens-before to read them safely */
	T_EXPECT_EQ((uintmax_t)state->byt_up, (uintmax_t)sizeof(uplink));
	T_EXPECT_EQ((uintmax_t)state->byt_down, (uintmax_t)sizeof(downlink));
	fixture_close(fixture, acc_peer);
	fixture_close(fixture, dial_peer);
	fixture_finish(fixture);
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
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct ev_loop *loop = fixture->loop;
	T_CHECK(loop != NULL);
	struct test_xfer_state *state = &fixture->state;

	fixture_socketpair(fixture, &acc_peer, &acc_fd);
	fixture_socketpair(fixture, &dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	state->num_sessions = 1;
	fixture->xfer = transfer_create(loop, 1);
	struct transfer *restrict xfer = fixture->xfer;
	T_CHECK(xfer != NULL);

	T_CHECK(fixture_serve(
		fixture, xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &state->byt_up,
			.byt_down = &state->byt_down,
			.use_splice = true,
			.num_sessions = &state->num_sessions,
		}));
	acc_fd = dial_fd = -1;

	/*
	 * transfer_join runs the worker's queued start task (creating the
	 * pipes) before cancelling the still-active session, so release_ctx
	 * closes the pipes on the shutdown path.
	 */
	fixture_join(fixture);
	T_EXPECT_EQ((size_t)state->num_sessions, (size_t)0);

	fixture_close(fixture, acc_peer);
	fixture_close(fixture, dial_peer);
	fixture_finish(fixture);
	T_EXPECT_EQ(count_open_fds(), fds_before);
}

/*
 * A use_splice session whose splice pipes cannot be created must fall back to
 * the recv/send path rather than splice through an fd of -1: both halves still
 * relay their payload and are released with no pipe to close.
 */
T_DECLARE_CASE(transfer_splice_pipe_failure_falls_back)
{
	const int fds_before = count_open_fds();
	static const char uplink[] = "fallback-uplink";
	static const char downlink[] = "fallback-downlink";
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct ev_loop *loop = fixture->loop;
	T_CHECK(loop != NULL);
	struct test_xfer_state *state = &fixture->state;
	/* one byte of slack, so sink_reached_eof always has room to read into */
	unsigned char up_out[sizeof(uplink) + 1] = { 0 };
	unsigned char dn_out[sizeof(downlink) + 1] = { 0 };

	fixture_socketpair(fixture, &acc_peer, &acc_fd);
	fixture_socketpair(fixture, &dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	T_CHECK(send(acc_peer, uplink, sizeof(uplink), 0) ==
		(ssize_t)sizeof(uplink));
	T_CHECK(shutdown(acc_peer, SHUT_WR) == 0);
	T_CHECK(send(dial_peer, downlink, sizeof(downlink), 0) ==
		(ssize_t)sizeof(downlink));
	T_CHECK(shutdown(dial_peer, SHUT_WR) == 0);

	state->num_sessions = 1;
	fixture->xfer = transfer_create(loop, 1);
	struct transfer *restrict xfer = fixture->xfer;
	T_CHECK(xfer != NULL);

	/* one failure per half: neither gets a pipe */
	pipe2_failures = 2;
	T_CHECK(fixture_serve(
		fixture, xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &state->byt_up,
			.byt_down = &state->byt_down,
			.use_splice = true,
			.num_sessions = &state->num_sessions,
		}));
	acc_fd = dial_fd = -1;

	T_EXPECT(test_wait_until(loop, xfer_finished, state, 1.0));

	struct test_relay_sink up_sink = {
		.fd = dial_peer,
		.data = up_out,
		.cap = sizeof(up_out),
	};
	T_EXPECT(sink_reached_eof(&up_sink));
	T_EXPECT_EQ(up_sink.len, sizeof(uplink));
	T_EXPECT_MEMEQ(up_sink.data, uplink, sizeof(uplink));
	struct test_relay_sink dn_sink = {
		.fd = acc_peer,
		.data = dn_out,
		.cap = sizeof(dn_out),
	};
	T_EXPECT(sink_reached_eof(&dn_sink));
	T_EXPECT_EQ(dn_sink.len, sizeof(downlink));
	T_EXPECT_MEMEQ(dn_sink.data, downlink, sizeof(downlink));

	fixture_join(fixture);
	/* both arms were consumed, so both halves really ran without a pipe */
	T_EXPECT_EQ(pipe2_failures, 0);
	/* byt_up/byt_down are written by the worker with relaxed atomics; only
	 * transfer_join establishes the happens-before to read them safely */
	T_EXPECT_EQ((uintmax_t)state->byt_up, (uintmax_t)sizeof(uplink));
	T_EXPECT_EQ((uintmax_t)state->byt_down, (uintmax_t)sizeof(downlink));
	pipe2_failures = 0;
	fixture_close(fixture, acc_peer);
	fixture_close(fixture, dial_peer);
	fixture_finish(fixture);
	T_EXPECT_EQ(count_open_fds(), fds_before);
}
#endif /* WITH_SPLICE */

/*
 * transfer_join() must cancel a session that is still active and release all
 * of its resources, so its num_sessions decrement has run by the time
 * transfer_join() returns.
 */
T_DECLARE_CASE(transfer_join_cancels_active_session)
{
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct ev_loop *loop = fixture->loop;
	T_CHECK(loop != NULL);
	struct test_xfer_state *state = &fixture->state;

	fixture_socketpair(fixture, &acc_peer, &acc_fd);
	fixture_socketpair(fixture, &dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	state->num_sessions = 1;
	fixture->xfer = transfer_create(loop, 1);
	struct transfer *restrict xfer = fixture->xfer;
	T_CHECK(xfer != NULL);

	T_CHECK(fixture_serve(
		fixture, xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &state->byt_up,
			.byt_down = &state->byt_down,
			.num_sessions = &state->num_sessions,
		}));
	acc_fd = dial_fd = -1;

	/*
	 * transfer_join joins the xfer thread; in-flight transfers are
	 * cancelled and their num_sessions decrements execute before return.
	 */
	fixture_join(fixture);
	T_EXPECT_EQ(state->num_sessions, (size_t)0);

	fixture_close(fixture, acc_peer);
	fixture_close(fixture, dial_peer);
	fixture_finish(fixture);
}

#if WITH_THREADS
/*
 * transfer_join may set the stop flag between a worker's last dispatcher_tick
 * and the load that breaks its loop, leaving a start task in the dispatch
 * queue the loop never revisits. The worker must still run it and cancel it,
 * so neither the session's descriptors nor its num_sessions decrement are
 * discarded along with the queue.
 */
T_DECLARE_CASE(transfer_join_drains_queued_start)
{
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct ev_loop *loop = fixture->loop;
	T_CHECK(loop != NULL);
	struct test_xfer_state *state = &fixture->state;

	fixture_socketpair(fixture, &acc_peer, &acc_fd);
	fixture_socketpair(fixture, &dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	state->num_sessions = 1;
	fixture->xfer = transfer_create(loop, 1);
	struct transfer *restrict xfer = fixture->xfer;
	T_CHECK(xfer != NULL);

	atomic_store(&skip_tick, true);
	T_CHECK(fixture_serve(
		fixture, xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &state->byt_up,
			.byt_down = &state->byt_down,
			.num_sessions = &state->num_sessions,
		}));
	acc_fd = dial_fd = -1;

	fixture_join(fixture);
	/* the harness stayed armed until the loop exit, so no in-loop tick can
	 * have run the task -- it really was still queued there */
	T_EXPECT(!atomic_load(&skip_tick));
	T_EXPECT_EQ((size_t)state->num_sessions, (size_t)0);

	fixture_close(fixture, acc_peer);
	fixture_close(fixture, dial_peer);
	fixture_finish(fixture);
}

/*
 * A worker dispatch queue at capacity refuses the start task. transfer_serve
 * must then report failure without taking the session: num_sessions is left
 * for the caller to roll back, and both fds stay open for the caller to close
 * -- or, as here, to serve again once the queue has room.
 */
T_DECLARE_CASE(transfer_serve_queue_full_keeps_fds)
{
	static const char uplink[] = "queue-full-uplink";
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct ev_loop *loop = fixture->loop;
	T_CHECK(loop != NULL);
	struct test_xfer_state *state = &fixture->state;
	/* one byte of slack, so sink_reached_eof always has room to read into */
	unsigned char up_out[sizeof(uplink) + 1] = { 0 };

	fixture_socketpair(fixture, &acc_peer, &acc_fd);
	fixture_socketpair(fixture, &dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	state->num_sessions = 1;
	fixture->xfer = transfer_create(loop, 1);
	struct transfer *restrict xfer = fixture->xfer;
	T_CHECK(xfer != NULL);
	const struct transfer_opts opts = {
		.byt_up = &state->byt_up,
		.byt_down = &state->byt_down,
		.num_sessions = &state->num_sessions,
	};

	atomic_store(&fail_invoke, true);
	T_EXPECT(!fixture_serve(fixture, xfer, acc_fd, dial_fd, &opts));
	/* the refusal came from the dispatch queue, not an earlier failure */
	T_EXPECT(!atomic_load(&fail_invoke));
	T_EXPECT_EQ((size_t)state->num_sessions, (size_t)1);
	/* neither fd was closed */
	T_CHECK(fcntl(acc_fd, F_GETFD) != -1);
	T_CHECK(fcntl(dial_fd, F_GETFD) != -1);

	/* the same pair still serves a session once the queue accepts it */
	T_CHECK(send(acc_peer, uplink, sizeof(uplink), 0) ==
		(ssize_t)sizeof(uplink));
	T_CHECK(shutdown(acc_peer, SHUT_WR) == 0);
	T_CHECK(shutdown(dial_peer, SHUT_WR) == 0);
	T_CHECK(fixture_serve(fixture, xfer, acc_fd, dial_fd, &opts));
	acc_fd = dial_fd = -1;

	T_EXPECT(test_wait_until(loop, xfer_finished, state, 1.0));
	struct test_relay_sink up_sink = {
		.fd = dial_peer,
		.data = up_out,
		.cap = sizeof(up_out),
	};
	T_EXPECT(sink_reached_eof(&up_sink));
	T_EXPECT_EQ(up_sink.len, sizeof(uplink));
	T_EXPECT_MEMEQ(up_sink.data, uplink, sizeof(uplink));

	fixture_join(fixture);
	fixture_close(fixture, acc_peer);
	fixture_close(fixture, dial_peer);
	fixture_finish(fixture);
}
#endif /* WITH_THREADS */

/*
 * If the uplink destination has no reader, writes fail immediately.
 * The transfer must detect the error and finish the session, decrementing
 * num_sessions.
 */
T_DECLARE_CASE(transfer_dst_error_finishes)
{
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct ev_loop *loop = fixture->loop;
	T_CHECK(loop != NULL);
	struct test_xfer_state *state = &fixture->state;

	/* Prevent SIGPIPE when writing to a socket with no reader. */
	const struct sigaction ignore = { .sa_handler = SIG_IGN };
	T_EXPECT(sigaction(SIGPIPE, &ignore, &fixture->old_sigpipe) == 0);
	fixture->has_sigpipe = true;

	fixture_socketpair(fixture, &acc_peer, &acc_fd);
	fixture_socketpair(fixture, &dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	T_CHECK(send(acc_peer, "x", 1, 0) == 1);
	T_CHECK(shutdown(acc_peer, SHUT_WR) == 0);
	/* Close the read end of the uplink destination. */
	fixture_close(fixture, dial_peer);

	state->num_sessions = 1;
	fixture->xfer = transfer_create(loop, 1);
	struct transfer *restrict xfer = fixture->xfer;
	T_CHECK(xfer != NULL);

	T_CHECK(fixture_serve(
		fixture, xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &state->byt_up,
			.byt_down = &state->byt_down,
			.num_sessions = &state->num_sessions,
		}));
	acc_fd = dial_fd = -1;

	T_EXPECT(test_wait_until(loop, xfer_finished, state, 1.0));

	fixture_join(fixture);
	fixture_close(fixture, acc_peer);
	fixture_finish(fixture);
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
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct ev_loop *loop = fixture->loop;
	T_CHECK(loop != NULL);
	struct test_xfer_state *state = &fixture->state;
	char drain[4096];

	fixture_socketpair(fixture, &acc_peer, &acc_fd);
	fixture_socketpair(fixture, &dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);
	set_nonblock(dial_peer);
	io_probe.src_fd = acc_fd;
	io_probe.dst_fd = dial_fd;

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

	state->num_sessions = 1;
	fixture->xfer = transfer_create(loop, 1);
	struct transfer *restrict xfer = fixture->xfer;
	T_CHECK(xfer != NULL);

	T_CHECK(fixture_serve(
		fixture, xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &state->byt_up,
			.byt_down = &state->byt_down,
			.num_sessions = &state->num_sessions,
		}));
	acc_fd = dial_fd = -1;

	T_EXPECT(test_wait_until(loop, send_blocked, NULL, 1.0));
	T_EXPECT(!xfer_finished(state));

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
	T_EXPECT(test_wait_until(loop, xfer_finished, state, 1.0));

	/* The one-byte payload must have arrived at dial_peer. */
	char out = 0;
	T_EXPECT_EQ(recv(dial_peer, &out, 1, MSG_DONTWAIT), (ssize_t)1);
	T_EXPECT_EQ(out, 'y');

	fixture_join(fixture);
	/* byt_up is written by the worker with relaxed atomics; only
	 * transfer_join establishes the happens-before to read it safely */
	T_EXPECT_EQ((uintmax_t)state->byt_up, (uintmax_t)1);
	fixture_close(fixture, acc_peer);
	fixture_close(fixture, dial_peer);
	fixture_finish(fixture);
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
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct ev_loop *loop = fixture->loop;
	T_CHECK(loop != NULL);
	struct test_xfer_state *state = &fixture->state;
	char drain[4096];

	for (size_t i = 0; i < PAYLOAD_SZ; i++) {
		payload[i] = (unsigned char)(i & 0xff);
	}

	fixture_socketpair(fixture, &acc_peer, &acc_fd);
	fixture_socketpair(fixture, &dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);
	set_nonblock(dial_peer);
	io_probe.src_fd = acc_fd;
	io_probe.dst_fd = dial_fd;
	io_probe.saturate = true;

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

	state->num_sessions = 1;
	fixture->xfer = transfer_create(loop, 1);
	struct transfer *restrict xfer = fixture->xfer;
	T_CHECK(xfer != NULL);

	T_CHECK(fixture_serve(
		fixture, xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &state->byt_up,
			.byt_down = &state->byt_down,
			.num_sessions = &state->num_sessions,
		}));
	acc_fd = dial_fd = -1;

	T_EXPECT(test_wait_until(loop, receive_buffer_full, NULL, 1.0));
	T_EXPECT(!xfer_finished(state));

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

	T_EXPECT(test_wait_until(loop, xfer_finished, state, 2.0));

	/* All payload bytes must have arrived at dial_peer. */
	unsigned char received[PAYLOAD_SZ];
	size_t got = 0;
	while (got < PAYLOAD_SZ) {
		const ssize_t n =
			recv(dial_peer, received + got, PAYLOAD_SZ - got,
			     MSG_DONTWAIT);
		if (n <= 0) {
			break;
		}
		got += (size_t)n;
	}
	T_EXPECT_EQ((uintmax_t)got, (uintmax_t)PAYLOAD_SZ);
	T_EXPECT_MEMEQ(received, payload, PAYLOAD_SZ);

	fixture_join(fixture);
	/* byt_up is written by the worker with relaxed atomics; only
	 * transfer_join establishes the happens-before to read it safely */
	T_EXPECT_EQ((uintmax_t)state->byt_up, (uintmax_t)PAYLOAD_SZ);
	fixture_close(fixture, acc_peer);
	fixture_close(fixture, dial_peer);
	fixture_finish(fixture);
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
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct ev_loop *loop = fixture->loop;
	T_CHECK(loop != NULL);
	struct test_xfer_state *state = &fixture->state;
	int acc_peer[NCONN], dial_peer[NCONN];

	state->num_sessions = NCONN;
	fixture->xfer = transfer_create(loop, NWORKERS);
	struct transfer *restrict xfer = fixture->xfer;
	T_CHECK(xfer != NULL);

	for (int i = 0; i < NCONN; i++) {
		int acc_fd = -1, dial_fd = -1;
		fixture_socketpair(fixture, &acc_peer[i], &acc_fd);
		fixture_socketpair(fixture, &dial_fd, &dial_peer[i]);
		set_nonblock(acc_fd);
		set_nonblock(dial_fd);

		T_CHECK(send(acc_peer[i], uplink, sizeof(uplink), 0) ==
			(ssize_t)sizeof(uplink));
		T_CHECK(shutdown(acc_peer[i], SHUT_WR) == 0);
		T_CHECK(shutdown(dial_peer[i], SHUT_WR) == 0);

		T_CHECK(fixture_serve(
			fixture, xfer, acc_fd, dial_fd,
			&(struct transfer_opts){
				.byt_up = &state->byt_up,
				.byt_down = &state->byt_down,
				.num_sessions = &state->num_sessions,
			}));
	}

	T_EXPECT(test_wait_until(loop, xfer_finished, state, 2.0));

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

	fixture_join(fixture);
	/* byt_up is written by the workers with relaxed atomics; only
	 * transfer_join establishes the happens-before to read it safely */
	T_EXPECT_EQ(
		(uintmax_t)state->byt_up, (uintmax_t)(NCONN * sizeof(uplink)));
	for (int i = 0; i < NCONN; i++) {
		fixture_close(fixture, acc_peer[i]);
		fixture_close(fixture, dial_peer[i]);
	}
	fixture_finish(fixture);
}

#if WITH_THREADS
/* Written by the probe handler on whichever thread the kernel delivers to,
 * read by the test thread while that worker is still running. */
static atomic_int caught_signo;

static void sigprobe_handler(const int signo)
{
	atomic_store_explicit(&caught_signo, signo, memory_order_relaxed);
}

static bool sigprobe_caught(void *data)
{
	(void)data;
	return atomic_load_explicit(&caught_signo, memory_order_relaxed) != 0;
}

/* Accept @p signo if it is pending, so restoring the mask cannot deliver a
 * leftover probe to the rest of the run. Returns 0 if none was pending. */
static int take_pending(const int signo)
{
	sigset_t pending, one;
	int taken = 0;

	T_CHECK(sigpending(&pending) == 0);
	if (sigismember(&pending, signo) != 1) {
		return 0;
	}
	T_CHECK(sigemptyset(&one) == 0);
	T_CHECK(sigaddset(&one, signo) == 0);
	T_CHECK(sigwait(&one, &taken) == 0);
	return taken;
}

/*
 * A worker must not block the synchronously generated signals: POSIX leaves
 * such a signal undefined when it is generated while blocked, and Linux
 * resolves that by resetting the disposition to SIG_DFL, discarding the crash
 * handler's report. The asynchronous ones must stay blocked, so the main
 * thread's loop owns them alone.
 *
 * Probe the worker's live mask through the kernel: a process-directed signal
 * goes to a thread that does not block it, and this thread blocks both probes.
 * SIGUSR2 stands in for the asynchronous class -- it is queued first and is the
 * lower-numbered of the two, so a worker that failed to block it would dequeue
 * it before SIGSYS.
 */
T_DECLARE_CASE(transfer_worker_sigmask_keeps_faults_deliverable)
{
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct ev_loop *loop = fixture->loop;
	T_CHECK(loop != NULL);

	sigset_t probes;
	T_CHECK(sigemptyset(&probes) == 0);
	T_CHECK(sigaddset(&probes, SIGSYS) == 0);
	T_CHECK(sigaddset(&probes, SIGUSR2) == 0);
	T_CHECK(pthread_sigmask(SIG_BLOCK, &probes, &fixture->oldmask) == 0);
	fixture->has_mask = true;

	struct sigaction act = { .sa_handler = sigprobe_handler };
	T_CHECK(sigemptyset(&act.sa_mask) == 0);
	T_CHECK(sigaction(SIGSYS, &act, &fixture->old_sys) == 0);
	fixture->has_sys = true;
	T_CHECK(sigaction(SIGUSR2, &act, &fixture->old_usr2) == 0);
	fixture->has_usr2 = true;
	atomic_store_explicit(&caught_signo, 0, memory_order_relaxed);

	fixture->xfer = transfer_create(loop, 1);
	struct transfer *restrict xfer = fixture->xfer;
	T_CHECK(xfer != NULL);
	T_CHECK(kill(getpid(), SIGUSR2) == 0);
	T_CHECK(kill(getpid(), SIGSYS) == 0);

	const bool caught = test_wait_until(loop, sigprobe_caught, NULL, 2.0);
	const int signo =
		atomic_load_explicit(&caught_signo, memory_order_relaxed);
	sigset_t pending;
	T_CHECK(sigpending(&pending) == 0);
	const int usr2_pending = sigismember(&pending, SIGUSR2);

	fixture_join(fixture);

	const int took_usr2 = take_pending(SIGUSR2);
	const int took_sys = take_pending(SIGSYS);
	T_CHECK(sigaction(SIGSYS, &fixture->old_sys, NULL) == 0);
	fixture->has_sys = false;
	T_CHECK(sigaction(SIGUSR2, &fixture->old_usr2, NULL) == 0);
	fixture->has_usr2 = false;
	T_CHECK(pthread_sigmask(SIG_SETMASK, &fixture->oldmask, NULL) == 0);
	fixture->has_mask = false;
	fixture_finish(fixture);

	/* the worker took the fault-class probe... */
	T_EXPECT(caught);
	T_EXPECT_EQ(signo, SIGSYS);
	T_EXPECT_EQ(took_sys, 0);
	/* ...and left the asynchronous one blocked and pending */
	T_EXPECT_EQ(usr2_pending, 1);
	T_EXPECT_EQ(took_usr2, SIGUSR2);
}
#endif /* WITH_THREADS */

/*
 * A client that abandons its connection must leave num_sessions at exactly
 * zero, never underflowed. The decrement runs on two distinct teardown paths
 * depending on when the client abandons relative to the transfer, so both are
 * driven explicitly rather than sampled by repeating one cycle and hoping the
 * scheduler varies the interleaving.
 */
T_DECLARE_CASE(transfer_serve_join_rapid_cycles)
{
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct ev_loop *loop = fixture->loop;
	T_CHECK(loop != NULL);

	/* false: join with the session still active, so transfer_join cancels
	 *        it (shutdown-cancel decrement).
	 * true:  close both write ends and let the session finish on its own
	 *        first, so join finds nothing to cancel (normal-completion
	 *        decrement, then a no-op join). */
	for (int finish_first = 0; finish_first <= 1; finish_first++) {
		int acc_peer = -1, acc_fd = -1;
		int dial_fd = -1, dial_peer = -1;
		struct test_xfer_state *state = &fixture->state;

		fixture_socketpair(fixture, &acc_peer, &acc_fd);
		fixture_socketpair(fixture, &dial_fd, &dial_peer);
		set_nonblock(acc_fd);
		set_nonblock(dial_fd);

		if (finish_first) {
			T_CHECK(shutdown(acc_peer, SHUT_WR) == 0);
			T_CHECK(shutdown(dial_peer, SHUT_WR) == 0);
		}

		state->num_sessions = 1;
		fixture->xfer = transfer_create(loop, 1);
		struct transfer *restrict xfer = fixture->xfer;
		T_CHECK(xfer != NULL);

		T_CHECK(fixture_serve(
			fixture, xfer, acc_fd, dial_fd,
			&(struct transfer_opts){
				.byt_up = &state->byt_up,
				.byt_down = &state->byt_down,
				.num_sessions = &state->num_sessions,
			}));
		acc_fd = dial_fd = -1;

		if (finish_first) {
			T_EXPECT(test_wait_until(
				loop, xfer_finished, state, 1.0));
		}

		fixture_join(fixture);

		/* num_sessions must reach exactly zero, never negative. */
		T_EXPECT_EQ((size_t)state->num_sessions, (size_t)0);

		fixture_close(fixture, acc_peer);
		fixture_close(fixture, dial_peer);
	}

	fixture_finish(fixture);
}

/*
 * When both uplink and downlink close their write ends, the transfer
 * must complete and decrement num_sessions exactly once, not twice.
 */
T_DECLARE_CASE(transfer_both_halves_close_normally)
{
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct ev_loop *loop = fixture->loop;
	T_CHECK(loop != NULL);
	struct test_xfer_state *state = &fixture->state;

	fixture_socketpair(fixture, &acc_peer, &acc_fd);
	fixture_socketpair(fixture, &dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	/* Close write ends immediately — no data to transfer. */
	T_CHECK(shutdown(acc_peer, SHUT_WR) == 0);
	T_CHECK(shutdown(dial_peer, SHUT_WR) == 0);

	state->num_sessions = 1;
	fixture->xfer = transfer_create(loop, 1);
	struct transfer *restrict xfer = fixture->xfer;
	T_CHECK(xfer != NULL);

	T_CHECK(fixture_serve(
		fixture, xfer, acc_fd, dial_fd,
		&(struct transfer_opts){
			.byt_up = &state->byt_up,
			.byt_down = &state->byt_down,
			.num_sessions = &state->num_sessions,
		}));
	acc_fd = dial_fd = -1;

	T_EXPECT(test_wait_until(loop, xfer_finished, state, 1.0));
	T_EXPECT_EQ((size_t)state->num_sessions, (size_t)0);

	fixture_join(fixture);
	fixture_close(fixture, acc_peer);
	fixture_close(fixture, dial_peer);
	fixture_finish(fixture);
}

/*
 * Half-close relay: a client that shuts down only its request direction must
 * have that EOF relayed to the upstream (send_eof), while the opposite half
 * keeps moving bytes and the session stays open until both halves finish.
 */
T_DECLARE_SUBCASE(transfer_half_close_case, const bool use_splice)
{
	static const char uplink[] = "half-close-uplink";
	static const char downlink[] = "half-close-downlink";
	int acc_peer = -1, acc_fd = -1;
	int dial_fd = -1, dial_peer = -1;
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct ev_loop *loop = fixture->loop;
	T_CHECK(loop != NULL);
	struct test_xfer_state *state = &fixture->state;
	/* one byte of slack, so sink_reached_eof always has room to read into */
	unsigned char up_out[sizeof(uplink) + 1] = { 0 };
	unsigned char dn_out[sizeof(downlink)] = { 0 };

	fixture_socketpair(fixture, &acc_peer, &acc_fd);
	fixture_socketpair(fixture, &dial_fd, &dial_peer);
	set_nonblock(acc_fd);
	set_nonblock(dial_fd);

	state->num_sessions = 1;
	fixture->xfer = transfer_create(loop, 1);
	struct transfer *restrict xfer = fixture->xfer;
	T_CHECK(xfer != NULL);

	struct transfer_opts opts = {
		.byt_up = &state->byt_up,
		.byt_down = &state->byt_down,
		.num_sessions = &state->num_sessions,
	};
#if WITH_SPLICE
	opts.use_splice = use_splice;
#else
	(void)use_splice;
#endif
	T_CHECK(fixture_serve(fixture, xfer, acc_fd, dial_fd, &opts));
	acc_fd = dial_fd = -1;

	/* shut down the request direction only */
	T_CHECK(send(acc_peer, uplink, sizeof(uplink), 0) ==
		(ssize_t)sizeof(uplink));
	T_CHECK(shutdown(acc_peer, SHUT_WR) == 0);

	struct test_relay_sink up_sink = {
		.fd = dial_peer,
		.data = up_out,
		.cap = sizeof(up_out),
	};
	T_EXPECT(test_wait_until(loop, sink_reached_eof, &up_sink, 1.0));
	T_EXPECT_EQ(up_sink.len, sizeof(uplink));
	T_EXPECT_MEMEQ(up_sink.data, uplink, sizeof(uplink));
	/* only the uplink half finished; the session is still serving */
	T_EXPECT_EQ((size_t)state->num_sessions, (size_t)1);

	/* the response direction still relays after the half-close */
	T_CHECK(send(dial_peer, downlink, sizeof(downlink), 0) ==
		(ssize_t)sizeof(downlink));
	struct test_relay_sink dn_sink = {
		.fd = acc_peer,
		.data = dn_out,
		.cap = sizeof(dn_out),
	};
	T_EXPECT(test_wait_until(loop, sink_filled, &dn_sink, 1.0));
	T_EXPECT_MEMEQ(dn_sink.data, downlink, sizeof(downlink));
	T_EXPECT_EQ((size_t)state->num_sessions, (size_t)1);

	/* the second half-close completes the session */
	T_CHECK(shutdown(dial_peer, SHUT_WR) == 0);
	T_EXPECT(test_wait_until(loop, xfer_finished, state, 1.0));
	T_EXPECT_EQ(
		recv(acc_peer, dn_out, sizeof(dn_out), MSG_DONTWAIT),
		(ssize_t)0);

	fixture_join(fixture);
	/* byt_up/byt_down are written by the worker with relaxed atomics; only
	 * transfer_join establishes the happens-before to read them safely */
	T_EXPECT_EQ((uintmax_t)state->byt_up, (uintmax_t)sizeof(uplink));
	T_EXPECT_EQ((uintmax_t)state->byt_down, (uintmax_t)sizeof(downlink));
	fixture_close(fixture, acc_peer);
	fixture_close(fixture, dial_peer);
	fixture_finish(fixture);
}

T_DECLARE_CASE(transfer_half_close_relays_eof)
{
	T_CALL_SUBCASE(transfer_half_close_case, false);
}

#if WITH_SPLICE
T_DECLARE_CASE(transfer_splice_half_close_relays_eof)
{
	T_CALL_SUBCASE(transfer_half_close_case, true);
}
#endif /* WITH_SPLICE */

#if WITH_SPLICE
T_DECLARE_CASE(transfer_pipe_new_close)
{
	struct test_fixture *fixture = NULL;
	T_CALL_SUBCASE(fixture_setup, &fixture);
	struct splice_pipe *p = &fixture->pipe;
	T_EXPECT(pipe_new(p));
	T_EXPECT(p->fd[0] >= 0);
	T_EXPECT(p->fd[1] >= 0);
	T_EXPECT(p->cap > 0);

	unsigned char buf[1] = { 0x42 };
	T_EXPECT_EQ((ssize_t)write(p->fd[1], buf, 1), (ssize_t)1);
	T_EXPECT_EQ((ssize_t)read(p->fd[0], buf, 1), (ssize_t)1);
	T_EXPECT_EQ(buf[0], 0x42);

	pipe_close(p);
	T_EXPECT_EQ(p->fd[0], -1);
	T_EXPECT_EQ(p->fd[1], -1);
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
	T_CASE(transfer_failed_expectation_cleans_fixture),
	T_CASE(transfer_moves_payload),
#if WITH_SPLICE
	T_CASE(transfer_pipe_new_close),
	T_CASE(transfer_splice_releases_pipes_on_finish),
	T_CASE(transfer_splice_ctx_cancel_releases_pipes),
	T_CASE(transfer_splice_pipe_failure_falls_back),
#endif
	T_CASE(transfer_join_cancels_active_session),
#if WITH_THREADS
	T_CASE(transfer_join_drains_queued_start),
	T_CASE(transfer_serve_queue_full_keeps_fds),
#endif
	T_CASE(transfer_dst_error_finishes),
	T_CASE(transfer_backpressure_completes),
	T_CASE(transfer_recv_buffer_saturates_completes),
	T_CASE(transfer_multi_worker_all_complete),
#if WITH_THREADS
	T_CASE(transfer_worker_sigmask_keeps_faults_deliverable),
#endif
	T_CASE(transfer_serve_join_rapid_cycles),
	T_CASE(transfer_both_halves_close_normally),
	T_CASE(transfer_half_close_relays_eof),
#if WITH_SPLICE
	T_CASE(transfer_splice_half_close_relays_eof),
#endif
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
