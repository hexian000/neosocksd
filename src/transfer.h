/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef TRANSFER_H
#define TRANSFER_H

#include "util.h"

#include "io/io.h"
#include "utils/buffer.h"

#include <ev.h>

#include <stddef.h>
#include <stdint.h>

enum transfer_state {
	XFER_INIT,
	XFER_CONNECTED,
	XFER_LINGER,
	XFER_FINISHED,
};

struct transfer_state_cb {
	void (*func)(struct ev_loop *loop, void *data);
	void *data;
};

struct transfer {
	enum transfer_state state;
	int src_fd, dst_fd;
	ev_io w_socket;
	struct transfer_state_cb state_cb;
	uintmax_t *byt_transferred;
#if WITH_SPLICE
	struct splice_pipe pipe;
#endif
	size_t pos;
	struct {
		BUFFER_HDR;
		unsigned char data[IO_BUFSIZE];
	} buf;
};

void transfer_init(
	struct transfer *t, const struct transfer_state_cb *callback,
	int src_fd, int dst_fd, uintmax_t *byt_transferred);

void transfer_start(struct ev_loop *loop, struct transfer *t);

void transfer_stop(struct ev_loop *loop, struct transfer *t);

#endif /* TRANSFER_H */
