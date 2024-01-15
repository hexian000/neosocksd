/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "transfer.h"
#include "sockutil.h"

#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>
#include <sys/socket.h>
#include <unistd.h>

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

static ssize_t transfer_recv(struct transfer *restrict t)
{
	if (t->buf.len > 0) {
		return 0;
	}
	const int fd = t->w_recv.fd;
	const ssize_t nrecv = recv(fd, t->buf.data, t->buf.cap, 0);
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
	t->buf.len = nrecv;
	return nrecv;
}

static ssize_t transfer_send(struct transfer *restrict t)
{
	if (t->buf.len == 0) {
		return 0;
	}
	const int fd = t->w_send.fd;
	const unsigned char *data = t->buf.data + t->pos;
	const size_t len = t->buf.len - t->pos;
	const ssize_t nsend = send(fd, data, len, 0);
	if (nsend < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return 0;
		}
		LOGD_F("recv: fd=%d %s", fd, strerror(err));
		return -1;
	}
	if (nsend == 0) {
		return 0;
	}
	t->pos += nsend;
	if (t->pos == t->buf.len) {
		t->pos = t->buf.len = 0;
	}
	return nsend;
}

static void
transfer_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	if (revents & EV_ERROR) {
		const int err = errno;
		LOGE_F("transfer error: %s", strerror(err));
		return;
	}

	struct transfer *restrict t = watcher->data;
	enum transfer_state state = t->state;
	size_t nbsend = 0;
	while (XFER_CONNECTED <= state && state <= XFER_LINGER) {
		ssize_t nrecv = 0;
		if (state == XFER_CONNECTED) {
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
	{
		uintmax_t *restrict byt_transferred = t->byt_transferred;
		if (byt_transferred != NULL) {
			*byt_transferred += nbsend;
		}
	}

	switch (state) {
	case XFER_INIT:
		state = XFER_CONNECTED;
		/* fallthrough */
	case XFER_CONNECTED: {
		const bool has_data = (t->buf.len > 0);
		ev_io_set_active(loop, &t->w_recv, !has_data);
		ev_io_set_active(loop, &t->w_send, has_data);
	} break;
	case XFER_LINGER:
		if (t->buf.len > 0) {
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
	t->pos = 0;
	BUF_INIT(t->buf, 0);
}

void transfer_start(struct ev_loop *loop, struct transfer *restrict t)
{
	XFER_CTX_LOG(DEBUG, t, "start");
	ev_io_start(loop, &t->w_recv);
}

void transfer_stop(struct ev_loop *loop, struct transfer *restrict t)
{
	ev_io_stop(loop, &t->w_recv);
	ev_io_stop(loop, &t->w_send);
	t->state = XFER_FINISHED;
	XFER_CTX_LOG(DEBUG, t, "stop");
}
