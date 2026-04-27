/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file transfer.h
 * @brief Bidirectional non-blocking data transfer, optionally on a dedicated
 * thread.
 *
 * When WITH_THREADS is enabled, `struct transfer` owns an I/O thread and
 * dispatch infrastructure; transfers run on that thread.  When disabled,
 * transfers are registered as I/O watchers on the caller-supplied ev_loop.
 * `struct transfer_ctx` is the per-connection bidirectional transfer object
 * in both modes.
 *
 * Lifecycle:
 *   transfer_new()  →  transfer_serve() × N  →  transfer_free()
 */

#ifndef TRANSFER_H
#define TRANSFER_H

#include <ev.h>

#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stdint.h>

struct transfer;

/**
 * @brief Create the transfer engine.
 *
 * When WITH_THREADS is enabled, starts a dedicated I/O thread.
 *
 * @param loop Main event loop (must outlive the returned engine; used directly
 *             when threads are disabled, stored for reference otherwise).
 * @return Heap-allocated engine, or NULL on allocation / thread failure.
 */
struct transfer *transfer_new(struct ev_loop *loop);

/**
 * @brief Stop the engine and free all resources. NULL-safe.
 *
 * When WITH_THREADS is enabled, signals the I/O thread to stop, cancels
 * all in-flight transfers, joins the thread, and releases all resources.
 * When disabled, cancels all in-flight transfers and frees the engine.
 * Any pending num_sessions decrements are executed before this returns.
 *
 * @param xfer Engine returned by transfer_new().
 */
void transfer_free(struct transfer *xfer);

/* Options passed to transfer_start(). */
struct transfer_opts {
#if WITH_SPLICE
	bool use_splice;
#endif
#if WITH_THREADS
	atomic_size_t *num_sessions;
	atomic_uintmax_t *byt_up;
	atomic_uintmax_t *byt_down;
#else
	size_t *num_sessions;
	uintmax_t *byt_up;
	uintmax_t *byt_down;
#endif
};

/**
 * @brief Serve a bidirectional transfer between two connected sockets.
 *
 * Takes ownership of `acc_fd` and `dial_fd`; the caller must set both to -1
 * immediately after a successful call.  The transfer is self-owned: it is
 * freed internally once both halves finish, at which point *num_sessions is
 * decremented atomically.
 *
 * @param xfer Engine.
 * @param acc_fd Accepted (client-side) file descriptor.
 * @param dial_fd Dialed (upstream-side) file descriptor.
 * @param opts Transfer options (byte counters, splice hint, session counter).
 * @return true on success, false on OOM (fds are NOT closed).
 */
bool transfer_serve(
	struct transfer *xfer, int acc_fd, int dial_fd,
	const struct transfer_opts *opts);

#endif /* TRANSFER_H */
