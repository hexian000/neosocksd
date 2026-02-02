/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file transfer.c
 * @brief Implementation of non-blocking data transfer helpers.
 *
 * The core logic is driven by an `ev_io` watcher and a small state machine.
 * Data is copied from a source file descriptor to a destination file
 * descriptor using `recv(2)`/`send(2)` with an intermediate buffer. When
 * compiled with `WITH_SPLICE` and enabled at runtime, a pipe and `splice(2)`
 * are used to reduce user-space copies.
 */

#include "transfer.h"

#include "conf.h"
#include "sockutil.h"
#include "util.h"

#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>
#if WITH_SPLICE
#include <fcntl.h>
#endif
#include <sys/socket.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define XFER_CTX_LOG_F(level, t, format, ...)                                  \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		LOG_F(level, "[fd:%d]->[fd:%d] " format, (t)->src_fd,          \
		      (t)->dst_fd, __VA_ARGS__);                               \
	} while (0)
#define XFER_CTX_LOG(level, t, message) XFER_CTX_LOG_F(level, t, "%s", message)

static const char *xfer_state_str[] = {
	[XFER_INIT] = "ESTABLISHED",
	[XFER_CONNECTED] = "TRANSFERRING",
	[XFER_LINGER] = "LINGER",
	[XFER_FINISHED] = "FINISHED",
};

/**
 * @brief Reconfigure and restart the internal watcher for the next step.
 *
 * Switches the watcher between EV_READ and EV_WRITE depending on whether
 * we need to read from the source or write to the destination.
 *
 * @param t Transfer context.
 * @param loop Event loop.
 * @param events One of EV_READ or EV_WRITE.
 */
static void update_watcher(
	struct transfer *restrict t, struct ev_loop *loop, const int events)
{
	ASSERT(events == EV_READ || events == EV_WRITE);
	ev_io *restrict watcher = &t->w_socket;
	const int ioevents = watcher->events & (EV_READ | EV_WRITE);
	if (ioevents == events) {
		return;
	}
	const int fd = (events & EV_WRITE) ? t->dst_fd : t->src_fd;
	ev_io_stop(loop, watcher);
	ev_io_set(watcher, fd, events);
	ev_io_start(loop, watcher);
}

/**
 * @brief Update optional byte counter and emit verbose logs.
 *
 * @param t Transfer context.
 * @param nbsend Number of bytes just sent to destination.
 * @param buffered Remaining buffered bytes pending send.
 */
static void update_stats(
	const struct transfer *restrict t, const size_t nbsend,
	const size_t buffered)
{
	uintmax_t *restrict byt_transferred = t->byt_transferred;
	if (byt_transferred != NULL) {
		*byt_transferred += nbsend;
	}
	if (buffered > 0) {
		XFER_CTX_LOG_F(
			VERYVERBOSE, t,
			"%zu bytes transmitted (%zu bytes buffered)", nbsend,
			buffered);
		return;
	}
	XFER_CTX_LOG_F(VERYVERBOSE, t, "%zu bytes transmitted", nbsend);
}

/**
 * @brief Transition to a new state and notify the callback.
 *
 * No-op if the state remains unchanged.
 *
 * @param t Transfer context.
 * @param loop Event loop.
 * @param state New state value.
 */
static void set_state(
	struct transfer *restrict t, struct ev_loop *loop,
	const enum transfer_state state)
{
	if (t->state == state) {
		return;
	}
	XFER_CTX_LOG_F(
		VERBOSE, t, "state changed: %s -> %s", xfer_state_str[t->state],
		xfer_state_str[state]);
	t->state = state;
	t->state_cb.func(loop, t->state_cb.data);
}

/**
 * @brief Read bytes from source fd into the internal buffer.
 *
 * @param t Transfer context.
 * @return >0 on bytes read, 0 on EAGAIN or no capacity, -1 on EOF/error.
 */
static ssize_t transfer_recv(struct transfer *restrict t)
{
	const size_t cap = t->buf.cap - t->buf.len;
	if (cap == 0) {
		return 0;
	}
	const int fd = t->src_fd;
	unsigned char *data = t->buf.data + t->buf.len;
	const ssize_t nrecv = recv(fd, data, cap, 0);
	if (nrecv < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return 0;
		}
		XFER_CTX_LOG_F(DEBUG, t, "recv: (%d) %s", err, strerror(err));
		return -1;
	}
	if (nrecv == 0) {
		XFER_CTX_LOG(VERYVERBOSE, t, "recv: EOF");
		return -1;
	}
	t->buf.len += (size_t)nrecv;
	return nrecv;
}

/**
 * @brief Send buffered bytes from the internal buffer to destination fd.
 *
 * @param t Transfer context.
 * @return >0 on bytes sent, 0 on EAGAIN or no data, -1 on fatal error.
 */
static ssize_t transfer_send(struct transfer *restrict t)
{
	const size_t len = t->buf.len - t->pos;
	if (len == 0) {
		return 0;
	}
	const int fd = t->dst_fd;
	const unsigned char *data = t->buf.data + t->pos;
	const ssize_t nsend = send(fd, data, len, 0);
	if (nsend < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return 0;
		}
		XFER_CTX_LOG_F(DEBUG, t, "send: (%d) %s", err, strerror(err));
		return -1;
	}
	if (nsend == 0) {
		return 0;
	}
	t->pos += (size_t)nsend;
	if (t->pos == t->buf.len) {
		t->pos = t->buf.len = 0;
	}
	return nsend;
}

static void send_eof(struct transfer *restrict t)
{
	if (shutdown(t->dst_fd, SHUT_WR) != 0) {
		const int err = errno;
		XFER_CTX_LOG_F(
			WARNING, t, "shutdown: (%d) %s", err, strerror(err));
		return;
	}
	XFER_CTX_LOG(VERYVERBOSE, t, "shutdown: send operations disabled");
}

/**
 * @brief libev callback that drives the transfer state machine.
 *
 * Reads from the source when possible and writes to the destination when
 * there is buffered data. Handles state transitions on EOF or errors.
 */
static void transfer_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);

	struct transfer *restrict t = watcher->data;
	enum transfer_state state = t->state;
	size_t nbsend = 0;
	while (state <= XFER_LINGER) {
		ssize_t nrecv = 0;
		if (state <= XFER_CONNECTED) {
			nrecv = transfer_recv(t);
			if (nrecv < 0) {
				state = XFER_LINGER;
			}
		}
		ssize_t nsend = transfer_send(t);
		if (nsend < 0) {
			state = XFER_FINISHED;
		} else {
			nbsend += (size_t)nsend;
		}
		if (nrecv <= 0 && nsend <= 0) {
			/* no progress */
			break;
		}
	}
	if (nbsend > 0) {
		update_stats(t, nbsend, t->buf.len);
	}

	const bool has_data = (t->pos < t->buf.len);
	switch (state) {
	case XFER_INIT:
		state = XFER_CONNECTED;
		/* fallthrough */
	case XFER_CONNECTED: {
		if (has_data) {
			update_watcher(t, loop, EV_WRITE);
		} else {
			update_watcher(t, loop, EV_READ);
		}
	} break;
	case XFER_LINGER:
		if (has_data) {
			update_watcher(t, loop, EV_WRITE);
			break;
		}
		send_eof(t);
		state = XFER_FINISHED;
		/* fallthrough */
	case XFER_FINISHED:
		ev_io_stop(loop, &t->w_socket);
		break;
	default:
		FAILMSGF("unexpected state: %d", state);
	}
	set_state(t, loop, state);
}

#if WITH_SPLICE

/**
 * @brief Drain from `fd` into the pipe using `splice(2)`.
 * @return >0 on bytes spliced, 0 on EAGAIN or full pipe, -1 on EOF/error.
 */
static ssize_t splice_drain(struct transfer *restrict t, const int fd)
{
	struct splice_pipe *restrict pipe = &t->pipe;
	ASSERT(pipe->len <= pipe->cap);
	const size_t cap = pipe->cap - pipe->len;
	if (cap == 0) {
		return 0;
	}
	const ssize_t nrecv =
		splice(fd, NULL, pipe->fd[1], NULL, cap, SPLICE_F_NONBLOCK);
	if (nrecv < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return 0;
		}
		XFER_CTX_LOG_F(
			DEBUG, t, "pipe: recv (%d) %s", err, strerror(err));
		return -1;
	}
	if (nrecv == 0) {
		XFER_CTX_LOG(VERYVERBOSE, t, "pipe: recv EOF");
		return -1;
	}
	pipe->len += (size_t)nrecv;
	return nrecv;
}

/**
 * @brief Pump from the pipe into `fd` using `splice(2)`.
 * @return >0 on bytes spliced out, 0 on EAGAIN or empty pipe, -1 on error.
 */
static ssize_t splice_pump(struct transfer *restrict t, const int fd)
{
	struct splice_pipe *restrict pipe = &t->pipe;
	const size_t len = pipe->len;
	if (len == 0) {
		return 0;
	}
	const ssize_t nsend =
		splice(pipe->fd[0], NULL, fd, NULL, len, SPLICE_F_NONBLOCK);
	if (nsend < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return 0;
		}
		XFER_CTX_LOG_F(
			DEBUG, t, "pipe: send (%d) %s", err, strerror(err));
		return -1;
	}
	pipe->len -= (size_t)nsend;
	return nsend;
}

/**
 * @brief libev callback variant that uses a splice pipe for zero-copy.
 */
static void pipe_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);

	struct transfer *restrict t = watcher->data;
	enum transfer_state state = t->state;
	size_t nbsend = 0;
	while (state <= XFER_LINGER) {
		ssize_t nrecv = 0;
		if (state <= XFER_CONNECTED) {
			nrecv = splice_drain(t, t->src_fd);
			if (nrecv < 0) {
				state = XFER_LINGER;
			}
		}
		ssize_t nsend = splice_pump(t, t->dst_fd);
		if (nsend < 0) {
			state = XFER_FINISHED;
		} else {
			nbsend += (size_t)nsend;
		}
		if (t->pipe.len > 0 || (nrecv <= 0 && nsend <= 0)) {
			break;
		}
	}
	const bool has_work = (nbsend > 0);
	if (has_work) {
		update_stats(t, nbsend, t->pipe.len);
	}

	const bool has_data = (t->pipe.len > 0);
	switch (state) {
	case XFER_INIT:
		state = XFER_CONNECTED;
		/* fallthrough */
	case XFER_CONNECTED: {
		if (has_data) {
			update_watcher(t, loop, EV_WRITE);
		} else if (!has_work) {
			update_watcher(t, loop, EV_READ);
		}
	} break;
	case XFER_LINGER:
		if (has_data) {
			update_watcher(t, loop, EV_WRITE);
			break;
		}
		send_eof(t);
		state = XFER_FINISHED;
		/* fallthrough */
	case XFER_FINISHED:
		ev_io_stop(loop, &t->w_socket);
		break;
	default:
		FAILMSGF("unexpected state: %d", state);
	}
	set_state(t, loop, state);
}
#endif

void transfer_init(
	struct transfer *restrict t, const struct transfer_state_cb *callback,
	const int src_fd, const int dst_fd, uintmax_t *byt_transferred)
{
	t->state = XFER_INIT;
	t->src_fd = src_fd;
	t->dst_fd = dst_fd;
	ev_io_init(&t->w_socket, transfer_cb, src_fd, EV_READ);
	ev_set_priority(&t->w_socket, EV_MINPRI);
	t->w_socket.data = t;
	t->state_cb = *callback;
	t->byt_transferred = byt_transferred;

#if WITH_SPLICE
	t->pipe = (struct splice_pipe){
		.fd = { -1, -1 },
		.cap = 0,
		.len = 0,
	};
#endif
	t->pos = 0;
	BUF_INIT(t->buf, 0);
}

#if WITH_SPLICE
static bool pipe_get(struct splice_pipe *restrict pipe)
{
	if (pipe_cache.len == 0) {
		return pipe_new(pipe);
	}
	*pipe = pipe_cache.pipes[--pipe_cache.len];
	return true;
}

static void pipe_put(struct splice_pipe *restrict pipe)
{
	if (pipe->len > 0 || pipe_cache.len == pipe_cache.cap) {
		pipe_close(pipe);
		return;
	}
	pipe_cache.pipes[pipe_cache.len++] = *pipe;
}
#endif

void transfer_start(struct ev_loop *restrict loop, struct transfer *restrict t)
{
#if WITH_SPLICE
	if (G.conf->pipe) {
		struct splice_pipe pipe;
		if (pipe_get(&pipe)) {
			ev_set_cb(&t->w_socket, pipe_cb);
			t->pipe = pipe;
		}
	}
#endif
	ev_io_start(loop, &t->w_socket);
}

void transfer_stop(struct ev_loop *loop, struct transfer *restrict t)
{
	ev_io_stop(loop, &t->w_socket);
#if WITH_SPLICE
	if (t->pipe.fd[0] != -1) {
		pipe_put(&t->pipe);
	}
#endif
	t->state = XFER_FINISHED;
	XFER_CTX_LOG(VERBOSE, t, "stop");
}
