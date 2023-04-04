#include "resolver.h"
#include "utils/slog.h"
#include "sockutil.h"
#include "util.h"

#include <ev.h>

#include <stdbool.h>
#include <string.h>

enum resolver_state {
	STATE_INIT,
	STATE_RESOLVE,
	STATE_DONE,
};

static bool
resolve(sockaddr_max_t *sa, const struct domain_name *name, const int family)
{
	char host[FQDN_MAX_LENGTH + 1];
	memcpy(host, name->name, name->len);
	host[name->len] = '\0';
	if (!resolve_hostname(sa, host, family)) {
		const int err = errno;
		LOGE_F("resolve: \"%s\" %s", host, strerror(err));
		return false;
	}
	return true;
}

static void
resolver_cb(struct ev_loop *loop, struct ev_watcher *watcher, const int revents)
{
	CHECK_EV_ERROR(revents);
	struct resolver *restrict r = watcher->data;
	r->done_cb.cb(loop, r->done_cb.ctx);
}

void resolver_init(
	struct resolver *restrict r, const int resolve_pf,
	const struct event_cb *cb)
{
	r->resolve_pf = resolve_pf;
	r->done_cb = *cb;
	r->state = STATE_INIT;
	struct ev_watcher *restrict watcher = &r->watcher;
	ev_init(watcher, resolver_cb);
	watcher->data = r;
}

bool resolver_start(
	struct resolver *restrict r, struct ev_loop *loop,
	const struct domain_name *name)
{
	if (!resolve(&r->addr, name, r->resolve_pf)) {
		return false;
	}
	r->state = STATE_DONE;
	ev_feed_event(loop, &r->watcher, EV_CUSTOM);
	return true;
}

void resolver_stop(struct resolver *restrict r, struct ev_loop *loop)
{
	ev_clear_pending(loop, &r->watcher);
	r->state = STATE_INIT;
}

const struct sockaddr *resolver_get(struct resolver *restrict r)
{
	if (r->state != STATE_DONE) {
		return NULL;
	}
	return &r->addr.sa;
}
