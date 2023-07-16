#include "transfer.h"
#include "utils/buffer.h"
#include "utils/check.h"
#include "utils/slog.h"
#include "util.h"

#include <ev.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static void ev_set_active(
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

static bool transfer_recv(struct transfer *restrict t)
{
	bool ok = true;
	if (t->state != XFER_CONNECTED) {
		return ok;
	}
	size_t nbrecv = 0;
	const int fd = t->w_recv.fd;
	unsigned char *data = t->buf.data + t->buf.len;
	size_t cap = t->buf.cap - t->buf.len;
	while (cap > 0) {
		const ssize_t nrecv = recv(fd, data, cap, 0);
		if (nrecv < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGD_F("recv: fd=%d %s", fd, strerror(err));
			ok = false;
			break;
		} else if (nrecv == 0) {
			LOGV_F("recv: fd=%d EOF", fd);
			ok = false;
			break;
		}
		data += nrecv;
		cap -= nrecv;
		nbrecv += nrecv;
	}
	t->buf.len += nbrecv;
	return ok;
}

static bool transfer_send(struct transfer *restrict t)
{
	size_t nbsend = 0;
	const int fd = t->w_send.fd;
	while (t->buf.len > 0) {
		const unsigned char *data = t->buf.data + nbsend;
		const size_t len = t->buf.len - nbsend;
		const ssize_t nsend = send(fd, data, len, 0);
		if (nsend < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGD_F("recv: fd=%d %s", fd, strerror(err));
			return false;
		} else if (nsend == 0) {
			break;
		}
		nbsend += nsend;
	}
	BUF_CONSUME(t->buf, nbsend);
	(*t->byt_transferred) += nbsend;
	return true;
}

static void transfer_state_cb(
	struct ev_loop *loop, struct ev_watcher *watcher, const int revents)
{
	UNUSED(revents);
	struct transfer *restrict t = watcher->data;
	t->state_cb.cb(loop, t->state_cb.ctx);
}

static void
transfer_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	if (revents & EV_ERROR) {
		const int err = errno;
		LOGE_F("transfer error: %s", strerror(err));
		return;
	}

	struct transfer *restrict t = (struct transfer *)watcher->data;
	enum transfer_state state = t->state;
	if (state < XFER_LINGER) {
		if (!transfer_recv(t)) {
			state = XFER_LINGER;
		}
	}
	if (state < XFER_CLOSED) {
		if (!transfer_send(t)) {
			state = XFER_CLOSED;
		}
	}

	switch (state) {
	case XFER_INIT:
		state = XFER_CONNECTED;
		/* fallthrough */
	case XFER_CONNECTED: {
		const bool has_data = t->buf.len > 0;
		ev_set_active(loop, &t->w_recv, !has_data);
		ev_set_active(loop, &t->w_send, has_data);
	} break;
	case XFER_LINGER:
		if (t->buf.len > 0) {
			ev_set_active(loop, &t->w_recv, false);
			ev_set_active(loop, &t->w_send, true);
			break;
		}
		state = XFER_CLOSED;
		/* fallthrough */
	case XFER_CLOSED:
		transfer_stop(loop, t);
		break;
	default:
		FAIL();
	}
	if (t->state != state) {
		t->state = state;
		ev_feed_event(loop, &t->w_state, EV_CUSTOM);
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
	struct ev_watcher *restrict w_state = &t->w_state;
	ev_init(w_state, transfer_state_cb);
	w_state->data = t;
	t->state_cb = cb;
	t->byt_transferred = byt_transferred;
	BUF_INIT(t->buf, XFER_BUFSIZE);
}

void transfer_start(struct ev_loop *loop, struct transfer *restrict t)
{
	ev_io_start(loop, &t->w_recv);
}

void transfer_stop(struct ev_loop *loop, struct transfer *restrict t)
{
	ev_io_stop(loop, &t->w_recv);
	ev_io_stop(loop, &t->w_send);
}
