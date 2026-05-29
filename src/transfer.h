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

#if WITH_SPLICE
#include <stdbool.h>
#include <stddef.h>

struct splice_pipe {
	int fd[2];
	size_t cap, len;
};

#if WITH_ALLOC_CACHE
#define PIPE_MAXCACHED 8

struct pipe_cache {
	size_t cap, len;
	struct splice_pipe pipes[PIPE_MAXCACHED];
};
#endif /* WITH_ALLOC_CACHE */

bool pipe_new(struct splice_pipe *pipe);

void pipe_close(struct splice_pipe *pipe);

#if WITH_ALLOC_CACHE
/**
 * @brief Shrink a splice pipe cache by closing up to @p count pipes.
 * @param cache Per-engine pipe cache to shrink (never NULL).
 * @param count Number of pipes to discard; pass SIZE_MAX to clear all.
 */
void pipe_shrink(struct pipe_cache *cache, size_t count);
#endif /* WITH_ALLOC_CACHE */
#endif

#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stdint.h>

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
 * @param loop     Main event loop (must outlive the returned engine; used
 *                 directly when threads are disabled, stored for reference
 *                 otherwise).
 * @param nworkers Number of I/O worker threads to spawn (ignored when
 *                 WITH_THREADS is disabled; must be >= 1).
 * @return Heap-allocated engine, or NULL on allocation / thread failure.
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
