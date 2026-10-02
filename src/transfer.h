/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file transfer.h
 * @brief Bidirectional non-blocking data transfer, optionally on dedicated
 * I/O threads.
 *
 * When WITH_THREADS is enabled, `struct transfer` owns I/O threads and
 * dispatch infrastructure; transfers run on those threads.  When disabled,
 * transfers are registered as I/O watchers on the caller-supplied ev_loop.
 * `struct transfer_ctx` is the per-connection bidirectional transfer object
 * in both modes.
 *
 * Lifecycle:
 *   transfer_create()  →  transfer_serve() × N  →  transfer_join()
 */

#ifndef TRANSFER_H
#define TRANSFER_H

#include <ev.h>

#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Counters shared with the stats readers: xfer_counter counts relayed bytes,
 * xfer_session_counter counts active sessions. They are atomic only where the
 * transfer runs on a dedicated I/O thread (WITH_THREADS), i.e. a different
 * thread from the reader; without threads there is no other thread to race
 * with. Defining them once here keeps every counter field and function
 * signature config-stable instead of forking their spelling on WITH_THREADS. */
#if WITH_THREADS
typedef atomic_uint_least64_t xfer_counter;
typedef atomic_size_t xfer_session_counter;
#else
typedef uint_least64_t xfer_counter;
typedef size_t xfer_session_counter;
#endif

/* Add @p n to a relay byte counter; a NULL counter is ignored. Keeps the
 * WITH_THREADS spelling of the increment in one place, next to the typedef. */
static inline void xfer_count(xfer_counter *restrict byt, const size_t n)
{
	if (byt == NULL) {
		return;
	}
#if WITH_THREADS
	atomic_fetch_add_explicit(byt, (uint_least64_t)n, memory_order_relaxed);
#else
	*byt += (uint_least64_t)n;
#endif
}

/* Per-half recv buffer size. Exposed as the single source of truth so a
 * white-box test can size a payload relative to it instead of duplicating the
 * literal. */
#define XFER_BUFSIZE 16384

#if WITH_SPLICE

struct splice_pipe {
	int fd[2];
	size_t cap, len;
};

bool pipe_new(struct splice_pipe *pipe);

void pipe_close(struct splice_pipe *pipe);
#endif /* WITH_SPLICE */

struct transfer;

/**
 * @brief Create the transfer engine.
 *
 * When WITH_THREADS is enabled, starts @p nworkers dedicated I/O threads,
 * each with its own ev_loop and dispatcher.  Incoming connections are
 * distributed across workers in round-robin order.
 * When WITH_THREADS is disabled, @p nworkers is ignored and transfers are
 * registered as I/O watchers on the caller-supplied ev_loop.
 *
 * @param loop     Main event loop (used directly when threads are disabled;
 *                 ignored when threads are enabled, since each worker runs its
 *                 own loop).
 * @param nworkers Number of I/O worker threads to spawn (ignored when
 *                 WITH_THREADS is disabled; must be >= 1).
 * @return Heap-allocated engine, or NULL when @p nworkers is too large to
 *         size the worker array, or on allocation / thread failure.
 * @note The worker threads run with every asynchronous signal blocked and the
 *       synchronously generated ones deliverable, whatever the caller was
 *       masking; the caller's own mask is restored before returning.
 */
struct transfer *transfer_create(struct ev_loop *loop, unsigned int nworkers);

/**
 * @brief Stop the engine and free all resources. NULL-safe.
 *
 * When WITH_THREADS is enabled, signals all I/O threads to stop, cancels
 * all in-flight transfers, joins all threads, and releases all resources.
 * When disabled, cancels all in-flight transfers and frees the engine.
 * Any pending num_sessions decrements are executed before this returns.
 *
 * @param xfer Engine returned by transfer_create().
 */
void transfer_join(struct transfer *xfer);

/* Options passed to transfer_serve(). */
struct transfer_opts {
	/* Splice hint; ignored unless WITH_SPLICE. */
	bool use_splice;
	xfer_session_counter *num_sessions;
	xfer_counter *byt_up;
	xfer_counter *byt_down;
};

/**
 * @brief Serve a bidirectional transfer between two connected sockets.
 *
 * Takes ownership of `acc_fd` and `dial_fd`; the caller must set both to -1
 * immediately after a successful call.  The transfer is self-owned: it is
 * freed internally once both halves finish, at which point *num_sessions is
 * decremented (atomically when WITH_THREADS is enabled; a plain decrement
 * otherwise, where there is no other thread to race with).
 *
 * @param xfer Engine.
 * @param acc_fd Accepted (client-side) file descriptor.
 * @param dial_fd Dialed (upstream-side) file descriptor.
 * @param opts Transfer options (byte counters, splice hint, session counter).
 * @return true on success; false if the session could not be started -- out
 *     of memory, or the worker's dispatch queue is momentarily full under a
 *     burst (transfer_serve() logs which). The fds are NOT closed on failure.
 */
bool transfer_serve(
	struct transfer *xfer, int acc_fd, int dial_fd,
	const struct transfer_opts *opts);

#endif /* TRANSFER_H */
