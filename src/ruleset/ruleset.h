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
struct io_stream;
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

	/* Number of completed events */
	size_t num_events;
	/* A circular buffer of recent per-event elapsed times (ns) */
	int_least64_t event_ns[1024];
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
 * A stored error object that is not a string is rendered through its
 * `__tostring`, and the rendering replaces the object as the stored last
 * error. Rendering runs protected: a `__tostring` that raises or exhausts
 * memory degrades to a placeholder instead of escaping.
 *
 * The ruleset anchors the returned string, which is therefore valid at least
 * until the next ruleset operation on @p r -- the same lifetime the
 * ruleset_stats() family's results have. Consume or copy it before returning
 * to the event loop; never free it.
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
bool ruleset_invoke(struct ruleset *restrict r, struct io_stream *code);

/**
 * @brief Opaque structure representing asynchronous ruleset operation state
 *
 * The asynchronous starters -- ruleset_rpcall(), ruleset_resolve(),
 * ruleset_route(), ruleset_route6() and ruleset_dispatch() -- share one
 * out-parameter contract for the caller-owned slot they publish into:
 *
 * - The caller must set the slot to NULL before the call. A start that fails
 *   before publishing leaves it untouched, so NULL is the only "nothing was
 *   published" marker.
 * - A false return does not mean nothing was published: the state goes into
 *   the slot before the last fallible startup steps. The caller must pass a
 *   non-NULL slot to ruleset_cancel() and reset it to NULL, or a later Lua
 *   garbage collection completes the orphaned state and feeds w_finish into a
 *   context that no longer expects it.
 * - A true return leaves the live state in the slot while the routine is
 *   pending, or NULL if the routine already ran to completion (its w_finish
 *   event is then already fed).
 * - The ruleset resets the slot to NULL when the routine completes; nothing
 *   else does, so a non-NULL slot always names a state the caller still owes a
 *   ruleset_cancel() on teardown.
 */
struct ruleset_state;

/**
 * @brief Cancel an ongoing asynchronous ruleset operation. Idempotent.
 * @param loop Event loop
 * @param state Operation state to cancel
 *
 * @note This reaches the operation only while it is still pending. When it has
 * already completed, state_complete() has fed the callback's w_finish event and
 * detached the caller's ruleset_state (setting it to NULL), so this becomes a
 * no-op and cannot undo the pending event. A consumer that tears down a context
 * embedding the ruleset_callback must therefore also clear that pending event
 * and dispose of the delivered payload -- for the request flow use
 * ruleset_request_cancel().
 */
void ruleset_cancel(struct ev_loop *loop, struct ruleset_state *restrict state);

/** @brief Callback structure for asynchronous ruleset operations */
struct ruleset_callback {
	ev_watcher w_finish;
	/* request.req and rpcall.result are both the first union member and
	 * thus share offset 0; ruleset_state_gc relies on this to clear either
	 * arm through rpcall.result. Keep them first if this union changes. */
	union {
		struct {
			/* the resolved request; the consumer (forward.c/socks.c)
			 * takes ownership and must dialreq_free() it */
			struct dialreq *req;
		} request;
		struct {
			/* malloc'd marshalled result; the consumer (api_server.c)
			 * takes ownership and must free() it. NULL on failure. */
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
 * @brief Finalize a request-flow ruleset_callback on consumer teardown.
 *
 * Handles the completed-but-undispatched window ruleset_cancel() cannot: if the
 * request completed and its w_finish event is still pending, drop that event so
 * it cannot fire into the context being destroyed, and dialreq_free() the
 * delivered request that the consumer will now never take ownership of. A no-op
 * while the operation is still pending or already dispatched.
 */
void ruleset_request_cancel(
	struct ev_loop *loop, struct ruleset_callback *restrict cb);

/**
 * @brief Execute remote procedure call asynchronously.
 * @param r Ruleset instance
 * @param state Caller-owned state slot, NULL-initialised by the caller;
 *        see struct ruleset_state for its full contract
 * @param code Stream containing Lua RPC code
 * @param callback Callback structure for result notification
 * @return true if operation started successfully, false on immediate error
 *     -- which may still have published @p state
 */
bool ruleset_rpcall(
	struct ruleset *restrict r, struct ruleset_state **state,
	struct io_stream *code, struct ruleset_callback *callback);

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
	const char *restrict chunkname, struct io_stream *code);

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
 * @brief Reload the boot config into the ruleset of a running server.
 *
 * Like ruleset_loadconfig(), but the config is already live: the load is
 * refused, leaving the config and the installed ruleset unchanged, when the
 * result would fail the startup checks, change a setting the server applies
 * only at startup, or require authentication with no ruleset installed.
 *
 * @param r Ruleset instance
 * @param filename Path to Lua file
 * @return true on success, false on error
 */
bool ruleset_reloadconfig(
	struct ruleset *restrict r, const char *restrict filename);

/**
 * @brief Report whether the Lua global `ruleset` is a loaded table
 *
 * The lookup honours `_G`'s metatable, as a ruleset hook dispatch does, and
 * runs protected.
 *
 * @param r Ruleset instance
 * @return true if `_G.ruleset` is a table, false otherwise (including when it
 *     is set to a non-nil non-table value, or when looking it up raises)
 */
bool ruleset_isvalid(struct ruleset *restrict r);

/**
 * @brief Trigger a full Lua garbage collection cycle.
 * @param r Ruleset instance
 * @return true on success, false on error
 */
bool ruleset_gc(struct ruleset *restrict r);

/**
 * @brief Proxy credentials supplied with a request.
 *
 * Each field is the exact bytes received, which may be any octet sequence
 * including null bytes, so the length is authoritative and the bytes are not
 * null-terminated. A field the protocol did not supply is NULL with a zero
 * length and reaches the ruleset as nil.
 */
struct ruleset_credentials {
	const char *username;
	size_t username_len;
	const char *password;
	size_t password_len;
};

/**
 * @brief Invoke ruleset.resolve() for an untyped-address request
 *        asynchronously.
 *
 * HTTP CONNECT carries no address type on the wire, so every CONNECT request
 * reaches here.
 *
 * @param r Ruleset instance
 * @param state Caller-owned state slot, NULL-initialised by the caller;
 *        see struct ruleset_state for its full contract
 * @param request Host and port (e.g., "www.example.org:80"); the host is the
 *        one the client named and may be an IP literal. Null-terminated, so a
 *        front end refuses a name carrying a null byte rather than handing on
 *        the bytes before it
 * @param creds Proxy credentials, borrowed for the call (NULL if none)
 * @param callback Callback structure for result notification
 * @return true if operation started successfully, false on immediate error
 *     -- which may still have published @p state
 */
bool ruleset_resolve(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request,
	const struct ruleset_credentials *restrict creds,
	struct ruleset_callback *callback);

/**
 * @brief Invoke ruleset.route() for an IPv4 address asynchronously.
 *
 * Reached only for a protocol-typed address; a literal the client sent as text
 * reaches ruleset_resolve().
 *
 * @param r Ruleset instance
 * @param state Caller-owned state slot, NULL-initialised by the caller;
 *        see struct ruleset_state for its full contract
 * @param request IPv4 address and port, rendered from the parsed address
 *        (e.g., "192.168.1.1:80")
 * @param creds Proxy credentials, borrowed for the call (NULL if none)
 * @param callback Callback structure for result notification
 * @return true if operation started successfully, false on immediate error
 *     -- which may still have published @p state
 */
bool ruleset_route(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request,
	const struct ruleset_credentials *restrict creds,
	struct ruleset_callback *callback);

/**
 * @brief Invoke ruleset.route6() for an IPv6 address asynchronously.
 *
 * Reached only for a protocol-typed address; a literal the client sent as text
 * reaches ruleset_resolve().
 *
 * @param r Ruleset instance
 * @param state Caller-owned state slot, NULL-initialised by the caller;
 *        see struct ruleset_state for its full contract
 * @param request IPv6 address and port, rendered from the parsed address with
 *        the address bracketed (e.g., "[2001:db8::1]:80")
 * @param creds Proxy credentials, borrowed for the call (NULL if none)
 * @param callback Callback structure for result notification
 * @return true if operation started successfully, false on immediate error
 *     -- which may still have published @p state
 */
bool ruleset_route6(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request,
	const struct ruleset_credentials *restrict creds,
	struct ruleset_callback *callback);

/**
 * @brief Route a request to the entry point matching its address type.
 *
 * Dispatches to ruleset_route() (ATYP_INET), ruleset_route6() (ATYP_INET6),
 * or ruleset_resolve() (ATYP_DOMAIN).
 * @param r Ruleset instance
 * @param state Caller-owned state slot, NULL-initialised by the caller;
 *        see struct ruleset_state for its full contract
 * @param request Address and port matching @p atype
 * @param atype Address type (an enum dialaddr_type value) selecting the
 *        entry point
 * @param creds Proxy credentials, borrowed for the call (NULL if none)
 * @param callback Callback structure for result notification
 * @return true if operation started successfully, false on immediate error
 *     -- which may still have published @p state
 */
bool ruleset_dispatch(
	struct ruleset *restrict r, struct ruleset_state **state,
	const char *restrict request, int atype,
	const struct ruleset_credentials *restrict creds,
	struct ruleset_callback *callback);

/**
 * @brief Get Lua VM memory and coroutine statistics.
 * @param r Ruleset instance
 * @param s Output for statistics
 */
void ruleset_vmstats(
	const struct ruleset *restrict r, struct ruleset_vmstats *restrict s);

/**
 * @brief Invoke ruleset.stats() and return the result string.
 *
 * The result is a Lua-owned string, valid until the next ruleset operation on
 * @p r -- any call re-entering the Lua VM, including the ruleset.tick() hook
 * the event loop drives. Consume or copy it before returning to the loop;
 * never free it.
 *
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
 *
 * The result is a Lua-owned string, valid until the next ruleset operation on
 * @p r -- any call re-entering the Lua VM, including the ruleset.tick() hook
 * the event loop drives. Consume or copy it before returning to the loop;
 * never free it.
 *
 * @param r Ruleset instance
 * @param len Output for result length
 * @return Metrics string, or NULL if the callback is absent or on error
 */
const char *ruleset_metrics(struct ruleset *restrict r, size_t *len);

/**
 * @brief Invoke ruleset.healthy() to check service health.
 *
 * The result is a Lua-owned string, valid until the next ruleset operation on
 * @p r -- any call re-entering the Lua VM, including the ruleset.tick() hook
 * the event loop drives. Consume or copy it before returning to the loop;
 * never free it.
 *
 * @param r Ruleset instance
 * @param len Output for message length
 * @return NULL if healthy (callback absent, or returns nil/empty); otherwise the
 * unhealthy reason string, which is ruleset_geterror()'s message when the
 * callback itself raised
 */
const char *ruleset_healthy(struct ruleset *restrict r, size_t *len);

#endif /* RULESET_H */
