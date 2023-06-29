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
			LOGE_F("error event: [errno=%d] %s", err,              \
			       strerror(err));                                 \
			return;                                                \
		}                                                              \
	} while (0)

/* Check if the error is generally "transient":
 *   In accept()/send()/recv()/sendmsg()/recvmsg()/sendmmsg()/recvmmsg(),
 * transient errors should not cause the socket to fail. The operation should
 * be retried later if the corresponding event is still available.
 */
#define IS_TRANSIENT_ERROR(err)                                                \
	((err) == EINTR || (err) == EAGAIN || (err) == EWOULDBLOCK ||          \
	 (err) == ENOBUFS || (err) == ENOMEM)

void init(void);

void daemonize(void);
void drop_privileges(const char *user);

#endif /* UTIL_H */
