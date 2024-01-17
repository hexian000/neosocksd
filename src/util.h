/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTIL_H
#define UTIL_H

#include "utils/arraysize.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/slog.h"

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

#define TSTAMP_NIL (-1.0)

#if defined(INTPTR_MAX)
typedef intptr_t handle_type;
#else
typedef ptrdiff_t handle_type;
#endif
_Static_assert(
	sizeof(handle_type) >= sizeof(void *),
	"handle_type can't hold a pointer");

static inline handle_type handle_make(void *p)
{
	return (handle_type)p;
}

static inline void *handle_toptr(const handle_type h)
{
	return (void *)h;
}

#define INVALID_HANDLE (handle_make(NULL))

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

#define CHECK_EV_ERROR(revents, accept)                                        \
	do {                                                                   \
		if (((revents)&EV_ERROR) != 0) {                               \
			const int err = errno;                                 \
			LOGE_F("error event: [errno=%d] %s", err,              \
			       strerror(err));                                 \
			return;                                                \
		}                                                              \
		assert(((revents) & (accept)) == (revents));                   \
	} while (0)

void init(int argc, char **argv);
void loadlibs(void);

void drop_privileges(const char *user);
void daemonize(const char *user, bool nochdir, bool noclose);

#endif /* UTIL_H */
