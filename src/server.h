/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef SERVER_H
#define SERVER_H

#include "conf.h"
#include "transfer.h"

#include <ev.h>

#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
	/* Back-pointer to the "core" proxy server whose stats should be
	 * reported. In production every server is its own core, so this is
	 * self-referential (server_init sets s->data = s). It only differs when
	 * an API server and the core proxy server are separate instances (as in
	 * api_server_test.c); api_server.c reads ctx->s->data expecting the core
	 * server, so it must never be NULL. */
	void *data;

	/* Transfer-thread counters; atomic in multi-threaded builds. */
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

/**
 * @brief Increment the active-session count and return the new value (>= 1).
 *
 * The matching decrement is issued by the transfer engine (or the relay/stream
 * close path) when the session ends. Kept inline in the header, rather than in
 * server.c, so every session-start site — the protocol handlers, each
 * unit-tested against its own transfer_serve stub and linking only its own
 * module — shares one copy of the drift-prone WITH_THREADS increment ladder
 * without a link-time dependency on server.c.
 */
static inline size_t server_session_incr(struct server *restrict s)
{
#if WITH_THREADS
	return atomic_fetch_add_explicit(
		       &s->num_sessions, 1, memory_order_relaxed) +
	       1;
#else
	return ++s->num_sessions;
#endif
}

/**
 * @brief Roll back a server_session_incr() when the session failed to start
 * before it was committed to the stats (e.g. a transfer_serve OOM).
 */
static inline void server_session_rollback(struct server *restrict s)
{
#if WITH_THREADS
	atomic_fetch_sub_explicit(&s->num_sessions, 1, memory_order_relaxed);
#else
	s->num_sessions--;
#endif
}

/**
 * @brief Record a successfully started session in the peak/total stats.
 * @param cur The value returned by the paired server_session_incr().
 */
static inline void
server_session_commit(struct server *restrict s, const size_t cur)
{
	if (cur > s->stats.num_sessions_peak) {
		s->stats.num_sessions_peak = cur;
	}
	s->stats.num_success++;
}

/**
 * @brief Account a session that starts without the transfer engine — the UDP
 * ASSOCIATE relay and the HTTP proxy stream forward drive their own watchers
 * rather than handing a fd pair to transfer_serve.
 * @return New active-session count (>= 1).
 */
static inline size_t server_account_session(struct server *restrict s)
{
	const size_t cur = server_session_incr(s);
	server_session_commit(s, cur);
	return cur;
}

/**
 * @brief Start a bidirectional transfer for a connected fd pair and account
 * the new session.
 *
 * Hands @p acc_fd and @p dial_fd to the server's transfer engine. On success
 * the transfer owns both descriptors; the active-session count is incremented,
 * @c num_sessions_peak and @c num_success are updated, and the new count
 * (>= 1) is returned. On failure (transfer_serve OOM) the session-count
 * increment is rolled back and 0 is returned, leaving both descriptors open
 * for the caller to close (transfer_serve does not close them). The caller
 * owns its per-connection bookkeeping (state, timers, @c num_halfopen,
 * logging, gc_unref) in either case.
 *
 * @return New active-session count on success, or 0 if the transfer could not
 *     be started.
 */
static inline size_t server_start_session(
	struct server *restrict s, const int acc_fd, const int dial_fd)
{
	/* Increment before transfer_serve so the transfer's own decrement can
	 * never precede ours; roll back if the transfer fails to start. */
	const size_t cur = server_session_incr(s);
	if (!transfer_serve(
		    s->xfer, acc_fd, dial_fd,
		    &(struct transfer_opts){
			    .byt_up = &s->byt_up,
			    .byt_down = &s->byt_down,
#if WITH_SPLICE
			    .use_splice = s->conf->pipe,
#endif
			    .num_sessions = &s->num_sessions,
		    })) {
		server_session_rollback(s);
		return 0;
	}
	server_session_commit(s, cur);
	return cur;
}

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
 * individual listeners. The same applies to @c num_sessions, @c byt_up and
 * @c byt_down: the authoritative values are the atomic top-level fields on
 * @c struct @c server, and the identically-named members embedded in
 * @c s->stats stay zero until this function fills @p out from them.
 */
void server_stats(
	const struct server *restrict s, struct server_stats *restrict out);

#endif /* SERVER_H */
