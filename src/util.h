/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/* Public utilities, globals, and helpers. */

#ifndef UTIL_H
#define UTIL_H

#include "transfer.h"

#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

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

/* Absolute time the time-jump sentinel is scheduled at. libev leaves an
 * ev_periodic with neither an interval nor a reschedule callback at its offset
 * forever, time jumps included, so this one can never become pending. */
#define TIMEJUMP_SENTINEL_AT 1e18

static inline void
timejump_cb(struct ev_loop *loop, ev_periodic *watcher, const int revents)
{
	(void)loop;
	(void)watcher;
	(void)revents;
	FAIL();
}

/* Let libev detect wall-clock jumps by timerfd instead of by waking the loop
 * once a minute, so an idle loop blocks indefinitely. @p sentinel must outlive
 * the loop; it never becomes pending and never keeps the loop alive. */
static inline void loop_watch_timejump(
	struct ev_loop *restrict loop, ev_periodic *restrict sentinel)
{
	/* starting any ev_periodic is what makes libev set up its timerfd */
	ev_periodic_init(
		sentinel, timejump_cb, TIMEJUMP_SENTINEL_AT, 0.0, NULL);
	ev_periodic_start(loop, sentinel);
	ev_unref(loop);
}

/* socket utilities */
void socket_bind_netdev(int fd, const char *restrict netdev);
void socket_set_transparent(int fd, bool tproxy);
#if WITH_TCP_KEEPALIVE_PARAMS
/* Override the kernel's keepalive timing on a keepalive-enabled socket. Each
 * parameter is left at the system default when it is not positive. */
void socket_set_keepalive(int fd, int idle, int intvl, int cnt);
#endif

/* Best-effort forward of already-buffered client bytes to a freshly dialed
 * upstream connection, whose send buffer should be empty. A short send here
 * (backpressure or error) is treated as failure rather than queued, since
 * silently dropping these bytes would reproduce the bug this exists to fix.
 * These bytes bypass the relay, so count them into @p byt (the uplink counter)
 * here: socket_send zeroes the length on failure, so only what reached the
 * wire is counted, including progress made before a later failure. */
static inline bool forward_readahead(
	const int fd, const void *restrict data, size_t len,
	xfer_counter *restrict byt)
{
	const unsigned char *restrict p = data;
	while (len > 0) {
		size_t n = len;
		const int err = socket_send(fd, p, &n);
		xfer_count(byt, n);
		if (err != 0 || n == 0) {
			return false;
		}
		p += n;
		len -= n;
	}
	return true;
}

#endif /* UTIL_H */
