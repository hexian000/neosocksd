#ifndef UTIL_H
#define UTIL_H

#include "utils/slog.h"
#include "utils/minmax.h"

#include <ev.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

struct resolver;
struct ruleset;

extern struct globals {
	const struct config *conf;
	struct resolver *resolver;
	struct ruleset *ruleset;
} G;

#define UNUSED(x) (void)(x)

#define TSTAMP_NIL (-1.0)

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

void init(void);

void daemonize(void);
void drop_privileges(const char *user);

#endif /* UTIL_H */
