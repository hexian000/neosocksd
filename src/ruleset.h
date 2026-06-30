/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RULESET_H
#define RULESET_H

/**
 * @file ruleset.h
 * @brief Lua-based ruleset engine: route connections, resolve domains,
 *        run RPC calls, and report runtime statistics.
 */

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ev_loop;
struct stream;
struct ruleset;
struct config;
struct dialreq;
struct resolver;
struct server;

struct ruleset_vmstats {
	/* Number of allocated Lua objects */
	size_t num_object;
	/* Total bytes allocated by Lua VM */
	size_t byt_allocated;

	/* Number of Lua coroutines currently dispatched (in-flight) */
	size_t num_thread_active;
	/* Peak concurrent dispatched Lua coroutines since start */
	size_t num_thread_peak;

	/* Total time used by ruleset in nanoseconds */
	uint_least64_t time_total;
	/* Number of completed events */
	size_t num_events;
	/* A circular buffer of recent event timestamps (ns) */
	int_least64_t event_ns[1024];
	/* A circular buffer of recent event end timestamps (ns) */
	int_least64_t event_end[1024];
};

/**
 * @brief Create a new ruleset instance with a Lua VM.
 * @param loop Event loop for asynchronous operations
 * @param conf Configuration for the ruleset
 * @param resolver DNS resolver for name resolution
 * @param basereq Base dial request prepended to all outbound connections
 * @return New ruleset instance, or NULL on failure
 */
struct ruleset *ruleset_new(
	struct ev_loop *restrict loop, struct config *restrict conf,
	struct resolver *restrict resolver, struct dialreq *restrict basereq);

/**
 * @brief Attach the proxy server instance to the ruleset.
 *
 * Must be called after the main server is started.
 *
 * @param r Ruleset instance
 * @param s Main proxy server (may be NULL to detach)
 */
void ruleset_setserver(struct ruleset *restrict r, struct server *restrict s);

/**
 * @brief Replace the base dial request used for outbound connections.
 *
 * The ruleset does not take ownership of @p basereq.
 *
 * @param r Ruleset instance
 * @param basereq Base dial request prepended to all outbound connections
 */
void ruleset_setbasereq(
	struct ruleset *restrict r, struct dialreq *restrict basereq);

/**
 * @brief Free a ruleset instance. NULL-safe.
 * @param r Ruleset instance to free
 */
void ruleset_free(struct ruleset *restrict r);

/**
 * @brief Get the last error message from the ruleset.
 *
 * The returned string is valid until the next ruleset operation.
 *
 * @param r Ruleset instance
 * @param len Optional output for message length
 * @return Error message string, or "(nil)" if no error
 */
const char *
ruleset_geterror(const struct ruleset *restrict r, size_t *restrict len);

/**
 * @brief Execute Lua code synchronously (blocks until completion).
 * @param r Ruleset instance
 * @param code Stream containing Lua script code
 * @return true on success, false on error
 */
bool ruleset_invoke(struct ruleset *restrict r, struct stream *code);

/**
 * @brief Opaque structure representing asynchronous ruleset operation state
 */
struct ruleset_state;

/**
 * @brief Cancel an ongoing asynchronous ruleset operation. Idempotent.
 * @param loop Event loop
 * @param state Operation state to cancel
 */
void ruleset_cancel(struct ev_loop *loop, struct ruleset_state *restrict state);

/** @brief Callback structure for asynchronous ruleset operations */
struct ruleset_callback {
	ev_watcher w_finish;
	union {
		struct {
			struct dialreq *req;
		} request;
		struct {
			const char *result;
			size_t resultlen;
		} rpcall;
	};
	/**
	 * @brief Commit a connected upstream for await.forward().
	 *
	 * Takes ownership of @p fd, sends the success response, and starts the
	 * transfer. May free the session. NULL if forwarding is unsupported.
	 */
	void (*forward)(
		struct ev_loop *loop, struct ruleset_callback *cb, int fd);
};

/**
 * @brief Execute remote procedure call asynchronously.
 * @param r Ruleset instance
 * @param state Output for operation state (for cancellation)
 * @param code Stream containing Lua RPC code
 * @param callback Callback structure for result notification
 * @return true if operation started successfully, false on immediate error
 */
bool ruleset_rpcall(
	struct ruleset *restrict r, struct ruleset_state **state,
	struct stream *code, struct ruleset_callback *callback);

/**
 * @brief Update or load a Lua module without restarting the server.
 * @param r Ruleset instance
 * @param modname Module name to update, or NULL for main ruleset
 * @param chunkname Chunk name for debugging (stack traces)
 * @param code Stream containing Lua code
 * @return true on success, false on error
 */
bool ruleset_update(
	struct ruleset *restrict r, const char *restrict modname,
	const char *restrict chunkname, struct stream *code);

/**
 * @brief Load and execute Lua code from a file.
 * @param r Ruleset instance
 * @param filename Path to Lua file
 * @return true on success, false on error
 */
bool ruleset_loadfile(struct ruleset *restrict r, const char *restrict filename);

/**
 * @brief Load config from a Lua file into the ruleset.
 *
 * Executes the file in "config" mode, extracts fields into the C config
 * struct, and optionally sets the ruleset module from the returned table.
 *
 * @param r Ruleset instance
 * @param filename Path to Lua file
 * @return true on success, false on error
 */
bool ruleset_loadconfig(
	struct ruleset *restrict r, const char *restrict filename);

/**
 * @brief Report whether the Lua global `ruleset` is set
 *
 * @param r Ruleset instance
 * @return true if `_G.ruleset` is non-nil, false otherwise
 */
bool ruleset_isvalid(struct ruleset *restrict r);

/**
 * @brief Trigger a full Lua garbage collection cycle.
 * @param r Ruleset instance
 * @return true on success, false on error
 */
bool ruleset_gc(struct ruleset *restrict r);

/**
 * @brief Invoke ruleset.resolve() for a domain name request asynchronously.
 * @param r Ruleset instance
 * @param state Output for operation state (for cancellation)
 * @param request Domain name and port (e.g., "www.example.org:80")
 * @param username SOCKS authentication username (may be NULL)
 * @param password SOCKS authentication password (may be NULL)
 * @param callback Callback structure for result notification
 * @return true if operation started successfully, false on immediate error
 */
bool ruleset_resolve(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback);

/**
 * @brief Invoke ruleset.route() for an IPv4 address asynchronously.
 * @param r Ruleset instance
 * @param state Output for operation state (for cancellation)
 * @param request IPv4 address and port (e.g., "192.168.1.1:80")
 * @param username SOCKS authentication username (may be NULL)
 * @param password SOCKS authentication password (may be NULL)
 * @param callback Callback structure for result notification
 * @return true if operation started successfully, false on immediate error
 */
bool ruleset_route(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback);

/**
 * @brief Invoke ruleset.route6() for an IPv6 address asynchronously.
 * @param r Ruleset instance
 * @param state Output for operation state (for cancellation)
 * @param request IPv6 address and port (e.g., "[2001:db8::1]:80")
 * @param username SOCKS authentication username (may be NULL)
 * @param password SOCKS authentication password (may be NULL)
 * @param callback Callback structure for result notification
 * @return true if operation started successfully, false on immediate error
 */
bool ruleset_route6(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, const char *restrict username,
	const char *restrict password, struct ruleset_callback *callback);

/**
 * @brief Get Lua VM memory and coroutine statistics.
 * @param r Ruleset instance
 * @param s Output for statistics
 */
void ruleset_vmstats(
	const struct ruleset *restrict r, struct ruleset_vmstats *restrict s);

/**
 * @brief Invoke ruleset.stats() and return the result string.
 * @param r Ruleset instance
 * @param dt Time delta since last call
 * @param query Optional filter query (may be NULL)
 * @param len Output for result length
 * @return Statistics string, or NULL on error
 */
const char *ruleset_stats(
	struct ruleset *restrict r, double dt, const char *restrict query,
	size_t *len);

/**
 * @brief Invoke ruleset.metrics() for Prometheus output.
 * @param r Ruleset instance
 * @param len Output for result length
 * @return Metrics string, or NULL if the callback is absent or on error
 */
const char *ruleset_metrics(struct ruleset *restrict r, size_t *len);

/**
 * @brief Invoke ruleset.healthy() to check service health.
 * @param r Ruleset instance
 * @param len Output for message length
 * @return NULL if healthy (callback absent, or returns nil/empty); otherwise the
 * unhealthy reason string (also returned if the callback raises an error)
 */
const char *ruleset_healthy(struct ruleset *restrict r, size_t *len);

#endif /* RULESET_H */
