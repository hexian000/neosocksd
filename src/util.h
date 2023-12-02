/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTIL_H
#define UTIL_H

#include "utils/arraysize.h"
#include "utils/slog.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/minmax.h"

#include <unistd.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct dialreq;
struct resolver;
struct ruleset;
struct server;
struct session;

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

#define UNUSED(x) (void)(x)

#define CONSTSTREQUAL(s, len, literal)                                         \
	((len) == (ARRAY_SIZE(literal) - 1) &&                                 \
	 strncmp((s), literal "",                                              \
		 (ARRAY_SIZE(literal) - 1) * sizeof((literal)[0])) == 0)

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

void init(int argc, char **argv);
void loadlibs(void);

void drop_privileges(const char *user);
void daemonize(const char *user, bool nochdir, bool noclose);

#endif /* UTIL_H */
