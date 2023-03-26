#ifndef UTIL_H
#define UTIL_H

#include "utils/slog.h"

#include <ev.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

#define UNUSED(x) (void)(x)

#define MAX(a, b) ((a) < (b) ? (b) : (a))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define CLAMP(x, a, b) ((x) < (a) ? (a) : ((b) < (x) ? (b) : (x)))

#define CHECKMSGF(cond, format, ...)                                           \
	do {                                                                   \
		if (!(cond)) {                                                 \
			LOGF_F(format, __VA_ARGS__);                           \
			exit(EXIT_FAILURE);                                    \
		}                                                              \
	} while (0)
#define CHECKMSG(cond, msg) CHECKMSGF(cond, "%s", msg)
#define CHECK(cond) CHECKMSGF(cond, "runtime check failed: %s", #cond)

#define LOGOOM() LOGE("out of memory")
#define CHECKOOM(ptr) CHECKMSG((ptr) != NULL, "out of memory")

#define FAILMSGF(format, ...) CHECKMSGF(0, format, __VA_ARGS__)
#define FAILMSG(msg) CHECKMSG(0, msg)
#define FAIL() FAILMSG("program entered an unexpected state (bug?)")

#define TSTAMP_NIL (-1.0)

struct event_cb {
	void (*cb)(struct ev_loop *loop, void *ctx);
	void *ctx;
};

#define CHECK_EV_ERROR(revents)                                                \
	do {                                                                   \
		if ((unsigned)(revents) & (unsigned)EV_ERROR) {                \
			const int err = errno;                                 \
			LOGE_F("got error event: %s", strerror(err));          \
			return;                                                \
		}                                                              \
	} while (0)

void print_bin(const void *data, const size_t n);

void drop_privileges(const char *user);

#endif /* UTIL_H */
