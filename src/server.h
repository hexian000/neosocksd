/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SERVER_H
#define SERVER_H

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct config;
struct dialreq;
struct resolver;
struct ruleset;
struct sockaddr;
struct server;

struct server_stats {
	/* Proxy service stats */
	size_t num_halfopen;
	/* Number of active sessions */
	size_t num_sessions;
	/* Peak concurrent sessions */
	size_t num_sessions_peak;
	/* Total proxy requests processed */
	uintmax_t num_request;
	/* Successful proxy requests */
	uintmax_t num_success;
	/* Connections rejected by ruleset */
	uintmax_t num_reject_ruleset;
	/* Connections timed out before ready */
	uintmax_t num_reject_timeout;
	/* Connections failed during upstream dial */
	uintmax_t num_reject_upstream;
	/* Bytes uploaded */
	uintmax_t byt_up;
	/* Bytes downloaded */
	uintmax_t byt_down;
	/* Successful connection count (histogram index) */
	size_t num_connects;
	/* Connection latency ring buffer (ns) */
	intmax_t connect_ns[1024];

	/* Aggregated listener accept/serve stats (filled by server_stats()) */
	uintmax_t num_accept;
	uintmax_t num_serve;

	/* API server stats */
	uintmax_t num_api_request;
	uintmax_t num_api_success;

	/* Server start timestamp */
	intmax_t started;
};

/* Per-listener connection accept/serve counters */
struct listener_stats {
	/* Total connections accepted at TCP level */
	uintmax_t num_accept;
	/* Connections forwarded to handler after rate-limit check */
	uintmax_t num_serve;
};

/**
 * @brief Function pointer type for serving connections
 *
 * @param s The server instance
 * @param loop The event loop
 * @param accepted_fd File descriptor of the accepted connection
 * @param accepted_sa Peer address of the accepted connection
 */
typedef void (*serve_fn)(
	struct server *s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa);

/* The listener binds to an address and accepts incoming connections */
struct listener {
	struct server *server;
	serve_fn serve;
	ev_io w_accept;
	ev_timer w_timer;
	struct listener_stats stats;
};

/* Maximum listeners per server */
#define SERVER_LISTENERS_MAX 3

struct server {
	struct ev_loop *loop;
	struct server_stats stats;
	void *data;

	const struct config *conf;
	struct resolver *resolver;
	struct dialreq *basereq;
#if WITH_RULESET
	struct ruleset *ruleset;
#endif

	struct listener listeners[SERVER_LISTENERS_MAX];
	size_t num_listeners;
};

void server_init(struct server *restrict s, struct ev_loop *loop);

bool server_add_listener(
	struct server *restrict s, const struct sockaddr *restrict bindaddr,
	serve_fn serve);

void server_stop(struct server *restrict s);

/**
 * @brief Aggregate per-listener stats and server-level stats into @p out.
 *
 * Callers should use this instead of reading @c s->stats directly whenever
 * @c num_accept or @c num_serve are needed, as those counters live on the
 * individual listeners.
 */
void server_stats(
	const struct server *restrict s, struct server_stats *restrict out);

#endif /* SERVER_H */
