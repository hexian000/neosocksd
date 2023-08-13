#include "resolver.h"
#include "utils/check.h"
#include "utils/slog.h"
#include "utils/posixtime.h"
#include "util.h"
#include "sockutil.h"

#include <ev.h>
#if WITH_CARES
#include <ares.h>
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if WITH_CARES
static struct resolver {
	bool init : 1;
	ares_channel channel;
	struct ev_io w_socket;
	struct ev_timer w_timeout;
} resolver = { .init = false };
#endif

#if WITH_CARES
static void socket_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	UNUSED(loop);
	CHECK_EV_ERROR(revents);
	const int fd = watcher->fd;
	const ares_socket_t readable =
		(revents & EV_READ) ? fd : ARES_SOCKET_BAD;
	const ares_socket_t writable =
		(revents & EV_WRITE) ? fd : ARES_SOCKET_BAD;
	ares_process_fd(resolver.channel, readable, writable);
}

static void
update_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	UNUSED(revents);
	fd_set readers, writers;
	FD_ZERO(&readers);
	FD_ZERO(&writers);
	const int nfds = ares_fds(resolver.channel, &readers, &writers);
	if (nfds == 0) {
		ev_timer_stop(loop, watcher);
		return;
	}
	struct timeval tv;
	if (ares_timeout(resolver.channel, NULL, &tv) == NULL) {
		ev_timer_stop(loop, watcher);
		return;
	}
	ares_process(resolver.channel, &readers, &writers);
	watcher->repeat = tv.tv_sec * 1.0 + tv.tv_usec * 1e-6;
	ev_timer_again(loop, watcher);
}

static void
sock_state_cb(void *data, const int fd, const int readable, const int writable)
{
	const int events = (readable ? EV_READ : 0) | (writable ? EV_WRITE : 0);
	LOGD_F("ares: state fd=%d events=0x%x", fd, events);

	struct ev_loop *loop = (struct ev_loop *)data;
	if (ev_is_active(&resolver.w_socket) && resolver.w_socket.fd != fd) {
		return;
	}

	ev_io_set(&resolver.w_socket, fd, events);
	if (events) {
		ev_io_start(loop, &resolver.w_socket);
	} else {
		ev_io_stop(loop, &resolver.w_socket);
	}
}
#endif

void resolver_init(void)
{
#if WITH_CARES
	int ret = ares_library_init(ARES_LIB_INIT_ALL);
	CHECKMSGF(ret == ARES_SUCCESS, "ares: %s", ares_strerror(ret));
	struct ares_options options;
	options.timeout = 2;
	options.sock_state_cb = sock_state_cb;
	options.sock_state_cb_data = EV_DEFAULT;
	ret = ares_init_options(
		&resolver.channel, &options,
		ARES_OPT_TIMEOUT | ARES_OPT_SOCK_STATE_CB);
	CHECKMSGF(ret == ARES_SUCCESS, "ares: %s", ares_strerror(ret));
	ev_io_init(&resolver.w_socket, socket_cb, -1, 0);
	ev_timer_init(&resolver.w_timeout, update_cb, 2.0, 2.0);
	resolver.init = true;
#endif
}

void resolver_uninit(void)
{
#if WITH_CARES
	if (!resolver.init) {
		return;
	}
	ares_destroy(resolver.channel);
	ares_library_cleanup();
	resolver.init = false;
#endif
}

bool resolver_set_server(const char *nameserver)
{
#if WITH_CARES
	struct ares_addr_node svr = { .next = NULL };
	if (inet_pton(AF_INET, nameserver, &svr.addr.addr4) == 1) {
		svr.family = AF_INET;
		return true;
	} else if (inet_pton(AF_INET6, nameserver, &svr.addr.addr6) == 1) {
		svr.family = AF_INET6;
		return true;
	} else {
		LOGE_F("failed parsing address: \"%s\"", nameserver);
		return false;
	}
	const int ret = ares_set_servers(resolver.channel, &svr);
	if (ret != ARES_SUCCESS) {
		LOGE_F("ares: %s", ares_strerror(ret));
		return false;
	}
	return true;
#else
	UNUSED(nameserver);
	return false;
#endif
}

struct resolve_ctx {
	struct ev_loop *loop;
	resolver_cb cb;
	sockaddr_max_t addr;
	void *data;
};

#if WITH_CARES
static bool
find_addrinfo(sockaddr_max_t *addr, const struct ares_addrinfo_node *it)
{
	for (; it != NULL; it = it->ai_next) {
		switch (it->ai_family) {
		case AF_INET:
			CHECK(it->ai_addrlen == sizeof(struct sockaddr_in));
			addr->in = *(struct sockaddr_in *)it->ai_addr;
			break;
		case AF_INET6:
			CHECK(it->ai_addrlen == sizeof(struct sockaddr_in6));
			addr->in6 = *(struct sockaddr_in6 *)it->ai_addr;
			break;
		default:
			continue;
		}
		return true;
	}
	return false;
}

static void
addrinfo_cb(void *arg, int status, int timeouts, struct ares_addrinfo *info)
{
	struct resolve_ctx *restrict ctx = arg;
	UNUSED(timeouts);
	bool ok = false;
	if (status != ARES_SUCCESS) {
		LOGW_F("ares: %s", ares_strerror(status));
	} else if (info != NULL) {
		ok = find_addrinfo(&ctx->addr, info->nodes);
		ares_freeaddrinfo(info);
	}
	ctx->cb(ctx->loop, ok ? &ctx->addr.sa : NULL, ctx->data);
	free(ctx);
}
#endif

void resolver_do(
	struct ev_loop *loop, const char *host, int family,
	const resolver_cb cb, void *data)
{
#if WITH_CARES
	struct resolve_ctx *restrict ctx = malloc(sizeof(struct resolve_ctx));
	if (ctx == NULL) {
		LOGOOM();
		cb(loop, NULL, data);
		return;
	}
	ctx->loop = loop;
	ctx->cb = cb;
	ctx->data = data;
	const struct ares_addrinfo_hints hints = {
		.ai_family = family,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = ARES_AI_V4MAPPED | ARES_AI_ADDRCONFIG,
	};
	ares_getaddrinfo(
		resolver.channel, host, NULL, &hints, addrinfo_cb, ctx);
	if (!ev_is_active(&resolver.w_timeout)) {
		ev_timer_start(loop, &resolver.w_timeout);
	}
#else
	sockaddr_max_t addr;
	const bool ok = resolve_hostname(&addr, host, family);
	cb(loop, ok ? &addr.sa : NULL, data);
#endif
}
