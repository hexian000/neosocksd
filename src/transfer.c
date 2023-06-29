#include "transfer.h"
#include "utils/buffer.h"
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

static size_t xfer_num_active = 0;
static uintmax_t xfer_bytes = 0;

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

static size_t transfer_recv(struct transfer *restrict t)
{
	if (t->state != XFER_CONNECTED) {
		return 0;
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
			t->state = XFER_LINGER;
			break;
		} else if (nrecv == 0) {
			LOGV_F("recv: fd=%d EOF", fd);
			t->state = XFER_LINGER;
			break;
		}
		data += nrecv;
		cap -= nrecv;
		nbrecv += nrecv;
	}
	t->buf.len += nbrecv;
	return nbrecv;
}

static size_t transfer_send(struct transfer *restrict t)
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
			t->state = XFER_CLOSED;
			return 0;
		} else if (nsend == 0) {
			break;
		}
		nbsend += nsend;
	}
	buf_consume(&t->buf, nbsend);
	xfer_bytes += nbsend;
	return nbsend;
}

static void transfer_done_cb(
	struct ev_loop *loop, struct ev_watcher *watcher, const int revents)
{
	UNUSED(revents);
	struct transfer *restrict t = watcher->data;
	t->done_cb.cb(loop, t->done_cb.ctx);
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
	if (t->state == XFER_CONNECTED) {
		(void)transfer_recv(t);
	}
	if (t->state < XFER_CLOSED) {
		(void)transfer_send(t);
	}

	switch (t->state) {
	case XFER_INIT:
		t->state = XFER_CONNECTED;
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
		t->state = XFER_CLOSED;
		/* fallthrough */
	case XFER_CLOSED:
		transfer_stop(loop, t);
		ev_feed_event(loop, &t->w_done, EV_CUSTOM);
		return;
	}
}

void transfer_init(
	struct transfer *restrict t, const struct event_cb cb, const int src_fd,
	const int dst_fd)
{
	t->state = XFER_INIT;
	struct ev_io *restrict w_recv = &t->w_recv;
	ev_io_init(w_recv, transfer_cb, src_fd, EV_READ);
	w_recv->data = t;
	struct ev_io *restrict w_send = &t->w_send;
	ev_io_init(w_send, transfer_cb, dst_fd, EV_WRITE);
	w_send->data = t;
	struct ev_watcher *restrict w_done = &t->w_done;
	ev_init(w_done, transfer_done_cb);
	w_done->data = t;
	t->done_cb = cb;
	buf_init(&t->buf, XFER_BUFSIZE);
}

void transfer_start(struct ev_loop *loop, struct transfer *restrict t)
{
	struct ev_io *restrict w_recv = &t->w_recv;
	struct ev_io *restrict w_send = &t->w_send;
	if (!ev_is_active(w_recv) && !ev_is_active(w_send)) {
		xfer_num_active++;
		LOGD_F("transfer: fd=%d -> fd=%d", w_recv->fd, w_send->fd);
	}
	ev_io_start(loop, w_send);
}

void transfer_stop(struct ev_loop *loop, struct transfer *restrict t)
{
	struct ev_io *restrict w_recv = &t->w_recv;
	struct ev_io *restrict w_send = &t->w_send;
	if (ev_is_active(w_recv) || ev_is_active(w_send)) {
		xfer_num_active--;
	}
	ev_io_stop(loop, w_recv);
	ev_io_stop(loop, w_send);
}

size_t transfer_get_active(void)
{
	return xfer_num_active;
}

uintmax_t transfer_get_bytes(void)
{
	return xfer_bytes;
}
