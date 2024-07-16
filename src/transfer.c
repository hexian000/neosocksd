/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
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
#include <sys/types.h>

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
		LOG_F(level, "%d -> %d: " format, t->w_recv.fd, t->w_send.fd,  \
		      __VA_ARGS__);                                            \
	} while (0)
#define XFER_CTX_LOG(level, t, message) XFER_CTX_LOG_F(level, t, "%s", message)

static void ev_io_set_active(
	struct ev_loop *loop, struct ev_io *restrict watcher, const bool active)
{
	if (!!ev_is_active(watcher) == active) {
		return;
	}
	if (active) {
		ev_io_start(loop, watcher);
	} else {
		ev_io_stop(loop, watcher);
	}
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
		LOGD_F("pipe: recv fd=%d EOF", fd);
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
#endif

static ssize_t transfer_recv(struct transfer *restrict t)
{
	const int fd = t->w_recv.fd;
#if WITH_SPLICE
	if (t->pipe.fd[1] != -1) {
		return splice_drain(&t->pipe, fd);
	}
#endif

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
		LOGD_F("recv: fd=%d EOF", fd);
		return -1;
	}
	t->buf.len += (size_t)nrecv;
	return nrecv;
}

static ssize_t transfer_send(struct transfer *restrict t)
{
	const int fd = t->w_send.fd;
#if WITH_SPLICE
	if (t->pipe.fd[0] != -1) {
		return splice_pump(&t->pipe, fd);
	}
#endif

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
	if (nbsend > 0) {
		uintmax_t *restrict byt_transferred = t->byt_transferred;
		if (byt_transferred != NULL) {
			*byt_transferred += nbsend;
		}
		XFER_CTX_LOG_F(
			VERYVERBOSE, t,
			"%zu bytes transmitted (%zu bytes in buffer)", nbsend,
			t->buf.len);
	}

	const bool can_recv = (t->buf.len < t->buf.cap);
	const bool can_send = (t->pos < t->buf.len);
	switch (state) {
	case XFER_INIT:
		state = XFER_CONNECTED;
		/* fallthrough */
	case XFER_CONNECTED: {
		ev_io_set_active(loop, &t->w_recv, can_recv);
		ev_io_set_active(loop, &t->w_send, can_send);
	} break;
	case XFER_LINGER:
		if (can_send) {
			ev_io_set_active(loop, &t->w_recv, false);
			ev_io_set_active(loop, &t->w_send, true);
			break;
		}
		state = XFER_FINISHED;
		/* fallthrough */
	case XFER_FINISHED:
		ev_io_stop(loop, &t->w_recv);
		ev_io_stop(loop, &t->w_send);
		break;
	default:
		FAIL();
	}
	if (t->state != state) {
		XFER_CTX_LOG_F(
			VERBOSE, t, "state changed %d to %d", t->state, state);
		t->state = state;
		t->state_cb.cb(loop, t->state_cb.ctx);
		return;
	}
}

void transfer_init(
	struct transfer *restrict t, const struct event_cb cb, const int src_fd,
	const int dst_fd, uintmax_t *byt_transferred)
{
	t->state = XFER_INIT;
	struct ev_io *restrict w_recv = &t->w_recv;
	ev_io_init(w_recv, transfer_cb, src_fd, EV_READ);
	w_recv->data = t;
	struct ev_io *restrict w_send = &t->w_send;
	ev_io_init(w_send, transfer_cb, dst_fd, EV_WRITE);
	w_send->data = t;
	t->state_cb = cb;
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

void transfer_start(struct ev_loop *loop, struct transfer *restrict t)
{
	XFER_CTX_LOG(DEBUG, t, "start");
#if WITH_SPLICE
	if (G.conf->pipe) {
		if (!pipe_get(&t->pipe)) {
			t->pipe = (struct splice_pipe){
				.fd = { -1, -1 },
				.cap = 0,
				.len = 0,
			};
		}
	}
#endif
	ev_io_start(loop, &t->w_recv);
}

void transfer_stop(struct ev_loop *loop, struct transfer *restrict t)
{
	ev_io_stop(loop, &t->w_recv);
	ev_io_stop(loop, &t->w_send);
#if WITH_SPLICE
	pipe_put(&t->pipe);
#endif
	t->state = XFER_FINISHED;
	XFER_CTX_LOG(DEBUG, t, "stop");
}
