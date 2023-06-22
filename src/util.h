#ifndef UTIL_H
#define UTIL_H

#include "utils/slog.h"
#include "utils/minmax.h"

#include <ev.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

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
			LOGE_F("got error event: %s", strerror(err));          \
			return;                                                \
		}                                                              \
	} while (0)

/* these errors do not fail the connection */
#define IS_TEMPORARY_ERROR(err)                                                \
	((err) == EAGAIN || (err) == EWOULDBLOCK || (err) == EINTR ||          \
	 (err) == ENOMEM)

void daemonize(void);
void drop_privileges(const char *user);

void reset(char **argv);

#endif /* UTIL_H */
