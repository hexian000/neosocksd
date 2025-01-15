/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

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
		LOG_F(level, "%d -> %d: " format, (t)->src_fd, (t)->dst_fd,    \
		      __VA_ARGS__);                                            \
	} while (0)
#define XFER_CTX_LOG(level, t, message) XFER_CTX_LOG_F(level, t, "%s", message)

static void update_watcher(
	struct transfer *restrict t, struct ev_loop *loop, const int events)
{
	ASSERT(events == EV_READ || events == EV_WRITE);
	struct ev_io *restrict watcher = &t->w_socket;
	const int ioevents = watcher->events & (EV_READ | EV_WRITE);
	if (ioevents == events) {
		return;
	}
	const int fd = (events & EV_WRITE) ? t->dst_fd : t->src_fd;
	ev_io_stop(loop, watcher);
	ev_io_set(watcher, fd, events);
	ev_io_start(loop, watcher);
}

static void update_stats(
	struct transfer *restrict t, const size_t nbsend, const size_t buffered)
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
	XFER_CTX_LOG_F(
		VERYVERBOSE, t, "%zu bytes transmitted", nbsend, buffered);
}

static void set_state(
	struct transfer *restrict t, struct ev_loop *loop,
	const enum transfer_state state)
{
	if (t->state == state) {
		return;
	}
	XFER_CTX_LOG_F(VERBOSE, t, "state %d changed to %d", t->state, state);
	t->state = state;
	t->state_cb.func(loop, t->state_cb.data);
}

static ssize_t transfer_recv(struct transfer *restrict t)
{
	const int fd = t->src_fd;
	const size_t cap = t->buf.cap - t->buf.len;
	if (cap == 0) {
		return 0;
	}
	unsigned char *data = t->buf.data + t->buf.len;
	const ssize_t nrecv = recv(fd, data, cap, 0);
	if (nrecv < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return 0;
		}
		LOGD_F("recv: fd=%d %s", fd, strerror(err));
		return -1;
	}
	if (nrecv == 0) {
		LOGV_F("recv: fd=%d EOF", fd);
		return -1;
	}
	t->buf.len += (size_t)nrecv;
	return nrecv;
}

static ssize_t transfer_send(struct transfer *restrict t)
{
	const int fd = t->dst_fd;
	const size_t len = t->buf.len - t->pos;
	if (len == 0) {
		return 0;
	}
	const unsigned char *data = t->buf.data + t->pos;
	const ssize_t nsend = send(fd, data, len, 0);
	if (nsend < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return 0;
		}
		LOGD_F("send: fd=%d %s", fd, strerror(err));
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

static void
transfer_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
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
	const bool has_work = (nbsend > 0);
	if (has_work) {
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
		} else if (!has_work) {
			update_watcher(t, loop, EV_READ);
		}
	} break;
	case XFER_LINGER:
		if (has_data) {
			update_watcher(t, loop, EV_WRITE);
			break;
		}
		state = XFER_FINISHED;
		/* fallthrough */
	case XFER_FINISHED:
		ev_io_stop(loop, &t->w_socket);
		break;
	default:
		FAIL();
	}
	set_state(t, loop, state);
}

#if WITH_SPLICE
static ssize_t splice_drain(struct splice_pipe *restrict pipe, const int fd)
{
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
		LOGD_F("pipe: recv fd=%d %s", fd, strerror(err));
		return -1;
	}
	if (nrecv == 0) {
		LOGV_F("pipe: recv fd=%d EOF", fd);
		return -1;
	}
	pipe->len += (size_t)nrecv;
	return nrecv;
}

static ssize_t splice_pump(struct splice_pipe *restrict pipe, const int fd)
{
	size_t len = pipe->len;
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
		LOGD_F("pipe: send fd=%d %s", fd, strerror(err));
		return -1;
	}
	pipe->len -= (size_t)nsend;
	return nsend;
}

static void pipe_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);

	struct transfer *restrict t = watcher->data;
	enum transfer_state state = t->state;
	size_t nbsend = 0;
	while (state <= XFER_LINGER) {
		ssize_t nrecv = 0;
		if (state <= XFER_CONNECTED) {
			nrecv = splice_drain(&t->pipe, t->src_fd);
			if (nrecv < 0) {
				state = XFER_LINGER;
			}
		}
		ssize_t nsend = splice_pump(&t->pipe, t->dst_fd);
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
		state = XFER_FINISHED;
		/* fallthrough */
	case XFER_FINISHED:
		ev_io_stop(loop, &t->w_socket);
		break;
	default:
		FAIL();
	}
	set_state(t, loop, state);
}
#endif

void transfer_init(
	struct transfer *restrict t, const struct event_cb *cb,
	const int src_fd, const int dst_fd, uintmax_t *byt_transferred)
{
	t->state = XFER_INIT;
	t->src_fd = src_fd;
	t->dst_fd = dst_fd;
	struct ev_io *restrict w_socket = &t->w_socket;
	ev_io_init(w_socket, transfer_cb, src_fd, EV_READ);
	ev_set_priority(w_socket, EV_MINPRI);
	w_socket->data = t;
	t->state_cb = *cb;
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

void transfer_start(struct ev_loop *loop, struct transfer *restrict t)
{
	XFER_CTX_LOG(VERBOSE, t, "start");
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
