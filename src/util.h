/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTIL_H
#define UTIL_H

#include "utils/slog.h"
#include "utils/minmax.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

struct resolver;
struct ruleset;
struct session;

extern struct globals {
	const struct config *conf;
	struct resolver *resolver;
#if WITH_RULESET
	struct ruleset *ruleset;
#endif
	struct session *sessions;
} G;

#define UNUSED(x) (void)(x)

#define TSTAMP_NIL (-1.0)

typedef uintptr_t handle_t;
#define INVALID_HANDLE ((uintptr_t)NULL)
#define TO_HANDLE(p) ((handle_t)(p))
#define TO_POINTER(x) ((void *)(x))

#define CAST(type, member, ptr)                                                \
	((type *)(((unsigned char *)(ptr)) - offsetof(type, member)))

#define CLOSE_FD(fd)                                                           \
	do {                                                                   \
		if (close(fd) != 0) {                                          \
			const int close_err = errno;                           \
			LOGW_F("close: %s", strerror(close_err));              \
		}                                                              \
	} while (0)

struct ev_loop;
struct ev_io;

void modify_io_events(struct ev_loop *loop, struct ev_io *watcher, int events);

struct event_cb {
	void (*cb)(struct ev_loop *loop, void *ctx);
	void *ctx;
};

#define CHECK_EV_ERROR(revents)                                                \
	do {                                                                   \
		if ((unsigned)(revents) & (unsigned)EV_ERROR) {                \
			const int err = errno;                                 \
			LOGE_F("error event: [errno=%d] %s", err,              \
			       strerror(err));                                 \
			return;                                                \
		}                                                              \
	} while (0)

void setup(int argc, char **argv);
void init(void);

void drop_privileges(const char *user);
void daemonize(const char *user, bool nochdir, bool noclose);

#endif /* UTIL_H */
