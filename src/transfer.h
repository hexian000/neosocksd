/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file transfer.h
 * @brief Non-blocking data transfer helpers built on libev.
 *
 * Provides a small state machine and an `ev_io` watcher to shuttle bytes
 * between a source file descriptor and a destination file descriptor in a
 * non-blocking fashion. Statistics can be optionally reported through a shared
 * counter. When available and enabled at build/runtime, `splice(2)` may be
 * used to reduce copies.
 */

#ifndef TRANSFER_H
#define TRANSFER_H

#include "util.h"

#include "io/io.h"
#include "utils/buffer.h"

#include <ev.h>

#include <stddef.h>
#include <stdint.h>

enum transfer_state {
	/**< Initial state before any I/O is performed. */
	XFER_INIT,
	/**< I/O loop is active and data is being transferred. */
	XFER_CONNECTED,
	/**< Read side hit EOF or error; draining any buffered data. */
	XFER_LINGER,
	/**< Transfer is done; watcher has been stopped. */
	XFER_FINISHED,
};

/**
 * @brief Callback invoked when a transfer state change occurs.
 */
struct transfer_state_cb {
	/** Callback function. */
	void (*func)(struct ev_loop *loop, void *data);
	/** Opaque user data passed back to the callback. */
	void *data;
};

/**
 * @brief Transfer context and buffers for non-blocking copy between fds.
 */
struct transfer {
	enum transfer_state state; /**< Current state of the state machine. */
	int src_fd, dst_fd; /**< Source and destination file descriptors. */
	ev_io w_socket; /**< libev watcher driving the transfer. */
	struct transfer_state_cb state_cb; /**< State change callback. */
	uintmax_t *byt_transferred; /**< Optional cumulative byte counter. */
#if WITH_SPLICE
	struct splice_pipe pipe; /**< Kernel pipe for `splice(2)` fast-path. */
#endif
	size_t pos; /**< Current read buffer send position. */
	struct {
		BUFFER_HDR;
		unsigned char data[IO_BUFSIZE]; /**< I/O buffer storage. */
	} buf;
};

/**
 * @brief Initialize a transfer context.
 *
 * The transfer is initialized in ::XFER_INIT state and is ready to be started
 * with transfer_start(). The watcher is configured to initially listen for
 * readability on `src_fd`.
 *
 * @param t Transfer context to initialize.
 * @param callback Callback invoked on state changes.
 * @param src_fd Source file descriptor to read from (non-blocking).
 * @param dst_fd Destination file descriptor to write to (non-blocking).
 * @param byt_transferred Optional pointer to a counter to accumulate the
 *        number of bytes successfully sent. May be NULL.
 */
void transfer_init(
	struct transfer *t, const struct transfer_state_cb *callback,
	int src_fd, int dst_fd, uintmax_t *byt_transferred);

/**
 * @brief Start the transfer by starting its watcher on the given loop.
 *
 * @param loop Event loop.
 * @param t Transfer context previously initialized with transfer_init().
 */
void transfer_start(struct ev_loop *loop, struct transfer *t);

/**
 * @brief Stop the transfer watcher and finalize state.
 *
 * Safe to call multiple times. When built with splice support, this will also
 * release the internal pipe back to the cache.
 *
 * @param loop Event loop.
 * @param t Transfer context.
 */
void transfer_stop(struct ev_loop *loop, struct transfer *t);

#endif /* TRANSFER_H */
