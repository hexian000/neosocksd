/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SERVER_H
#define SERVER_H

#include <ev.h>

#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct config;
struct dialreq;
struct resolver;
struct ruleset;
struct sockaddr;
struct server;
struct transfer;

struct server_stats {
	/* Proxy service stats */
	size_t num_halfopen;
	/* Number of active sessions */
	size_t num_sessions;
	/* Peak concurrent sessions */
	size_t num_sessions_peak;
	/* Total proxy requests processed */
	uint_least64_t num_request;
	/* Successful proxy requests */
	uint_least64_t num_success;
	/* Connections rejected by ruleset */
	uint_least64_t num_reject_ruleset;
	/* Connections timed out before ready */
	uint_least64_t num_reject_timeout;
	/* Connections failed during upstream dial */
	uint_least64_t num_reject_upstream;
	/* Bytes uploaded */
	uint_least64_t byt_up;
	/* Bytes downloaded */
	uint_least64_t byt_down;
	/* Successful connection count (histogram index) */
	size_t num_connects;
	/* Connection latency ring buffer (ns) */
	int_least64_t connect_ns[256];

	/* Aggregated listener accept/serve stats (filled by server_stats()) */
	uint_least64_t num_accept;
	uint_least64_t num_serve;

	/* API server stats */
	uint_least64_t num_api_request;
	uint_least64_t num_api_success;
	/* Bytes received by the API server */
	uint_least64_t api_byt_recv;
	/* Bytes sent by the API server */
	uint_least64_t api_byt_send;
	/* API client requests issued */
	uint_least64_t num_api_client_request;
	/* Bytes sent by the API client */
	uint_least64_t api_client_byt_send;
	/* Bytes received by the API client */
	uint_least64_t api_client_byt_recv;

	/* Protocol handshake overhead */
	/* Bytes received from clients during handshake */
	uint_least64_t byt_client_recv;
	/* Bytes sent to clients during handshake */
	uint_least64_t byt_client_send;
	/* Bytes sent to upstream proxies in CONNECT handshake */
	uint_least64_t byt_dial_send;
	/* Bytes received from upstream proxies in CONNECT handshake */
	uint_least64_t byt_dial_recv;

	/* Server start timestamp */
	int_least64_t started;
};

/* Per-listener connection accept/serve counters */
struct listener_stats {
	/* Total connections accepted at TCP level */
	uint_least64_t num_accept;
	/* Connections forwarded to handler after rate-limit check */
	uint_least64_t num_serve;
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

	/*
	 * Counters written by the transfer thread (or main thread when
	 * WITH_THREADS is disabled); must be accessed atomically in
	 * multi-threaded builds.  Exposed as plain values via server_stats().
	 */
#if WITH_THREADS
	atomic_size_t num_sessions;
	atomic_uint_least64_t byt_up, byt_down;
#else
	size_t num_sessions;
	uint_least64_t byt_up, byt_down;
#endif

	/* Signal watchers */
	ev_signal w_sighup;
	ev_signal w_sigint;
	ev_signal w_sigterm;

	struct config *conf;
	struct resolver *resolver;
	struct transfer *xfer;
	struct dialreq *basereq;
#if WITH_RULESET
	struct ruleset *ruleset;
#endif

	struct listener listeners[SERVER_LISTENERS_MAX];
	size_t num_listeners;
};

bool server_init(
	struct server *restrict s, struct ev_loop *loop,
	struct config *restrict conf, struct resolver *resolver,
	struct transfer *xfer, struct dialreq *basereq,
	struct ruleset *ruleset);

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
