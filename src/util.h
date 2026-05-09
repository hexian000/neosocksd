/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file util.h
 * @brief Public utilities, globals, and helpers.
 */

#ifndef UTIL_H
#define UTIL_H

#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct dialreq;

/**
 * @brief Compile-time length of a string literal excluding the null terminator.
 * @param s String literal.
 */
#define CONSTSTRLEN(s) (sizeof(s "") - sizeof(""))

/**
 * @brief Mark a variable as intentionally unused and silence compiler warnings.
 * @param x Variable expression to be marked unused.
 */
#define UNUSED(x) ((void)(x))

/**
 * @brief Sentinel value representing an invalid or unavailable timestamp.
 */
#define TSTAMP_NIL (-1.0)

/**
 * @brief Update a libev I/O watcher to the desired read/write event mask.
 * @param loop Event loop the watcher is attached to.
 * @param watcher I/O watcher to modify.
 * @param events Bitmask of accepted events (EV_READ | EV_WRITE).
 */
void modify_io_events(struct ev_loop *loop, struct ev_io *watcher, int events);

/**
 * @brief Validate revents against accepted mask, log EV_ERROR, and early-return.
 *
 * If `revents` contains EV_ERROR, logs the error; asserts that only
 * `(accept | EV_ERROR)` bits are present; returns from the current function
 * when none of the accepted bits are set.
 *
 * @param revents Event bits received from libev callbacks.
 * @param accept Accepted event mask (subset of EV_READ | EV_WRITE).
 */
#define CHECK_REVENTS(revents, accept)                                         \
	do {                                                                   \
		if (((revents) & EV_ERROR) != 0) {                             \
			const int err = errno;                                 \
			LOGE_F("io error: (%d) %s", err, strerror(err));       \
		}                                                              \
		ASSERT(((revents) & ((accept) | EV_ERROR)) == (revents));      \
		if (((revents) & (accept)) == 0) {                             \
			return;                                                \
		}                                                              \
	} while (0)

#if WITH_SPLICE
struct splice_pipe {
	int fd[2];
	size_t cap, len;
};

#define PIPE_MAXCACHED 8

/**
 * @brief Global cache of reusable pipes.
 */
extern struct pipe_cache {
	size_t cap, len;
	struct splice_pipe pipes[PIPE_MAXCACHED];
} pipe_cache;

bool pipe_new(struct splice_pipe *pipe);

void pipe_close(struct splice_pipe *pipe);

/**
 * @brief Shrink the splice pipe cache by closing up to `count` pipes.
 * @param count Number of pipes to discard; pass SIZE_MAX to clear all.
 */
void pipe_shrink(size_t count);
#endif

/* Returns true if err indicates a send error on a connection that should
 * simply be closed rather than retried. */
#define IS_STALECONN_ERROR(err)                                                \
	((err) == ECONNRESET || (err) == EPIPE || (err) == ECONNABORTED ||     \
	 (err) == ENOTCONN || (err) == EBADF)

/** Process-level initializations. */
void init(int argc, char *const restrict argv[]);

/** Load libraries and initialize global subsystems. */
void loadlibs(void);

/** Clean up and unload global subsystems and resources. */
void unloadlibs(void);

/* socket utilities */
void socket_bind_netdev(int fd, const char *netdev);
void socket_set_transparent(int fd, bool tproxy);

#endif /* UTIL_H */
