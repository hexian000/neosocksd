/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef TRANSFER_H
#define TRANSFER_H

#include "util.h"
#include "utils/buffer.h"

#include <ev.h>
#include <stdbool.h>
#include <stddef.h>

#define XFER_BUFSIZE ((size_t)16384)

enum transfer_state {
	XFER_INIT,
	XFER_CONNECTED,
	XFER_LINGER,
	XFER_CLOSED,
};

struct transfer {
	enum transfer_state state;
	struct ev_io w_recv, w_send;
	struct ev_watcher w_done;
	struct event_cb done_cb;
	struct {
		BUFFER_HDR;
		unsigned char data[XFER_BUFSIZE];
	} buf;
};

void transfer_init(
	struct transfer *t, struct event_cb cb, int src_fd, int dst_fd);

void transfer_start(struct ev_loop *loop, struct transfer *t);

void transfer_stop(struct ev_loop *loop, struct transfer *t);

size_t transfer_get_active(void);

size_t transfer_get_bytes(void);

#endif /* TRANSFER_H */
