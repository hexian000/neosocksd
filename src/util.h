/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef UTIL_H
#define UTIL_H

#include "utils/arraysize.h"
#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include <sys/types.h>
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

#define CONSTSTRLEN(s) (ARRAY_SIZE(s) - 1)

#define UNUSED(x) ((void)(x))

#define TSTAMP_NIL (-1.0)

#define CLOSE_FD(fd)                                                           \
	do {                                                                   \
		if (close(fd) != 0) {                                          \
			const int close_err = errno;                           \
			LOGW_F("close: %s", strerror(close_err));              \
		}                                                              \
	} while (0)

struct ev_loop;
struct ev_io;

struct event_cb {
	void (*func)(struct ev_loop *loop, void *data);
	void *data;
};

void modify_io_events(struct ev_loop *loop, struct ev_io *watcher, int events);

#define CHECK_REVENTS(revents, accept)                                         \
	do {                                                                   \
		if (((revents)&EV_ERROR) != 0) {                               \
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

#define PIPE_BUFSIZE 262144
#define PIPE_CACHESIZE 128

extern struct pipe_cache {
	size_t cap, len;
	struct splice_pipe pipes[PIPE_CACHESIZE];
} pipe_cache;

void pipe_close(struct splice_pipe *pipe);
bool pipe_new(struct splice_pipe *pipe);

static inline bool pipe_get(struct splice_pipe *restrict pipe)
{
	if (pipe_cache.len == 0) {
		return pipe_new(pipe);
	}
	*pipe = pipe_cache.pipes[--pipe_cache.len];
	return true;
}

static inline void pipe_put(struct splice_pipe *restrict pipe)
{
	if (pipe->cap < PIPE_BUFSIZE || pipe->len > 0 ||
	    pipe_cache.len == pipe_cache.cap) {
		pipe_close(pipe);
		return;
	}
	pipe_cache.pipes[pipe_cache.len++] = *pipe;
}

void pipe_shrink(size_t count);
#endif

void init(int argc, char **argv);
void loadlibs(void);

struct user_ident {
	uid_t uid;
	gid_t gid;
};
bool parse_user(struct user_ident *ident, const char *s);
void drop_privileges(const struct user_ident *ident);
void daemonize(const struct user_ident *ident, bool nochdir, bool noclose);

#endif /* UTIL_H */
