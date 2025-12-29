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

#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct dialreq;
struct resolver;
struct ruleset;
struct server;
struct session;

/**
 * @brief Process-global state shared across subsystems.
 *
 * The instance is defined in `util.c` as `G` and holds pointers to major
 * services and singleton data structures that are initialized at startup and
 * cleaned up at shutdown.
 */
extern struct globals {
	const struct config *conf;
	struct resolver *resolver;
#if WITH_RULESET
	struct ruleset *ruleset;
#endif
	struct server *server;
	struct session *sessions;
	struct dialreq *basereq;
} G;

/**
 * @brief Compile-time length of a string literal excluding the null terminator.
 * @param s String literal.
 */
#define CONSTSTRLEN(s) (sizeof(s) - 1)

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
 * @brief Close a file descriptor and log a warning on failure.
 * @param fd File descriptor to close.
 */
#define CLOSE_FD(fd)                                                           \
	do {                                                                   \
		if (close((fd)) != 0) {                                        \
			LOGW_F("close: fd=%d %s", (fd), strerror(errno));      \
		}                                                              \
	} while (0)

struct ev_loop;
struct ev_io;

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
			LOGE_F("error event: [errno=%d] %s", err,              \
			       strerror(err));                                 \
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

#define PIPE_MAXCACHED 16

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

/** Process-level initializations. */
void init(int argc, char **argv);

/** Load libraries and initialize global subsystems. */
void loadlibs(void);

/** Clean up and unload global subsystems and resources. */
void unloadlibs(void);

/** User and group identifiers. */
struct user_ident {
	uid_t uid;
	gid_t gid;
};

/** Parse a "[user][:[group]]" spec into numeric IDs using passwd/group DBs. */
bool parse_user(struct user_ident *ident, const char *s);

/**
 * @brief Drop real and effective privileges to the specified identifiers.
 * @param ident Target user and group IDs. Unspecified fields may be -1.
 */
void drop_privileges(const struct user_ident *ident);

/**
 * @brief Daemonize the current process using the double-fork pattern.
 *
 * Optionally avoid changing directory and/or closing stdio, then drop
 * privileges if `ident` is provided. On success, the parent exits after
 * receiving a readiness message from the daemon.
 *
 * @param ident Optional identifiers to drop to after daemonizing.
 * @param nochdir Do not chdir to "/" when true.
 * @param noclose Do not redirect stdio to /dev/null when true.
 */
void daemonize(const struct user_ident *ident, bool nochdir, bool noclose);

/**
 * @brief Monotonic clock in nanoseconds.
 * @return Nanoseconds since an unspecified epoch, or -1 on error.
 */
int_least64_t clock_monotonic(void);

/**
 * @brief Per-thread CPU load since the previous call.
 * @return Fraction in [0,1] when available, or -1 when unavailable.
 */
double thread_load(void);

#endif /* UTIL_H */
