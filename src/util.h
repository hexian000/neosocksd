/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Public utilities, globals, and helpers. */

#ifndef UTIL_H
#define UTIL_H

#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

struct dialreq;

/* Compile-time length of a string literal excluding the null terminator. */
#define CONSTSTRLEN(s) (sizeof(s "") - sizeof(""))

/* Sentinel value representing an invalid or unavailable timestamp. */
#define TSTAMP_NIL (-1.0)

/* Validate revents against accepted mask, log EV_ERROR, and early-return when
 * none of the accepted bits are set. */
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

/* Process-level initializations. */
void init(int argc, char *const restrict argv[]);

/* Load libraries and initialize global subsystems. */
void loadlibs(void);

/* Clean up and unload global subsystems and resources. */
void unloadlibs(void);

/* Update a libev I/O watcher to the desired read/write event mask. */
void modify_io_events(
	struct ev_loop *restrict loop, ev_io *restrict watcher, int events);

/* socket utilities */
void socket_bind_netdev(int fd, const char *restrict netdev);
void socket_set_transparent(int fd, bool tproxy);

/* Best-effort forward of already-buffered client bytes to a freshly dialed
 * upstream connection, whose send buffer should be empty. A short send here
 * (backpressure or error) is treated as failure rather than queued, since
 * silently dropping these bytes would reproduce the bug this exists to fix. */
static inline bool
forward_readahead(const int fd, const void *restrict data, size_t len)
{
	const unsigned char *restrict p = data;
	while (len > 0) {
		size_t n = len;
		if (socket_send(fd, p, &n) != 0 || n == 0) {
			return false;
		}
		p += n;
		len -= n;
	}
	return true;
}

#endif /* UTIL_H */
