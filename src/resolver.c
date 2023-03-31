#include "resolver.h"
#include "utils/slog.h"
#include "sockutil.h"
#include "util.h"

#include <sys/socket.h>
#include <netdb.h>
#include <ev.h>

#include <string.h>

enum resolver_state {
	STATE_INIT,
	STATE_RESOLVE,
	STATE_DONE,
};

static int
resolve(sockaddr_max_t *sa, const struct domain_name *name, const int family)
{
	char host[FQDN_MAX_LENGTH + 1];
	memcpy(host, name->name, name->len);
	host[name->len] = '\0';
	struct addrinfo hints = {
		.ai_family = family,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG,
	};
	struct addrinfo *result = NULL;
	if (getaddrinfo(host, NULL, &hints, &result) != 0) {
		const int err = errno;
		LOGE_F("resolve: \"%s\" %s", host, strerror(err));
		return err;
	}
	for (const struct addrinfo *it = result; it; it = it->ai_next) {
		switch (it->ai_family) {
		case AF_INET:
			sa->in = *(struct sockaddr_in *)it->ai_addr;
			break;
		case AF_INET6:
			sa->in6 = *(struct sockaddr_in6 *)it->ai_addr;
			break;
		}
	}
	freeaddrinfo(result);
	return 0;
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
	r->err = resolve(&r->addr, name, r->resolve_pf);
	if (r->err != 0) {
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
