/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RULESET_H
#define RULESET_H

/**
 * @file ruleset.h
 * @brief Lua-based ruleset engine
 *
 * This module provides a Lua-based scripting engine that allows dynamic
 * configuration and control of proxy routing behavior. The ruleset engine
 * can process connection requests, resolve domain names, route connections
 * through proxy chains, and provide runtime statistics.
 */

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ev_loop;
struct stream;
struct ruleset;
struct dialreq;

struct ruleset_vmstats {
	size_t num_object; /**< Number of allocated Lua objects */
	size_t byt_allocated; /**< Total bytes allocated by Lua VM */

	uintmax_t time_total; /**< Total time used by ruleset in nanoseconds */
	size_t num_events; /**< Number of completed events */
	int_least64_t event_ns[1024]; /**< A circular buffer of recent events */
	int_least64_t event_end[1024]; /**< A circular buffer of recent events */
};

/**
 * @brief Create a new ruleset instance
 *
 * Initializes a new Lua-based ruleset engine with the specified event loop.
 * The ruleset includes a Lua virtual machine with built-in libraries and
 * memory tracking capabilities.
 *
 * @param loop Event loop for asynchronous operations
 * @return New ruleset instance, or NULL on failure
 */
struct ruleset *ruleset_new(struct ev_loop *loop);

/**
 * @brief Free a ruleset instance
 *
 * Releases all resources associated with the ruleset, including the
 * Lua virtual machine and any pending operations.
 *
 * @param r Ruleset instance to free (may be NULL)
 */
void ruleset_free(struct ruleset *r);

/**
 * @brief Get the last error message from the ruleset
 *
 * Retrieves the most recent error message from Lua script execution.
 * The returned string is valid until the next ruleset operation.
 *
 * @param r Ruleset instance
 * @param len Optional output parameter for message length
 * @return Error message string, or "(nil)" if no error
 */
const char *ruleset_geterror(const struct ruleset *r, size_t *len);

/**
 * @brief Execute Lua code synchronously
 *
 * Runs the provided Lua script in the ruleset environment. This is a
 * synchronous operation that blocks until completion.
 *
 * @param r Ruleset instance
 * @param code Stream containing Lua script code
 * @return true on success, false on error
 */
bool ruleset_invoke(struct ruleset *r, struct stream *code);

/**
 * @brief Opaque structure representing asynchronous ruleset operation state
 */
struct ruleset_state;

/**
 * @brief Cancel an ongoing asynchronous ruleset operation
 *
 * Cancels a pending asynchronous operation and cleans up associated
 * resources. Safe to call even if the operation has already completed.
 *
 * @param loop Event loop
 * @param state Operation state to cancel
 */
void ruleset_cancel(struct ev_loop *loop, struct ruleset_state *state);

/**
 * @brief Callback structure for asynchronous ruleset operations
 *
 * Contains the result of an asynchronous ruleset operation and event
 * handling data. The callback is invoked when the operation completes.
 */
struct ruleset_callback {
	ev_watcher w_finish;
	bool ok;
	union {
		struct {
			struct dialreq *req;
		} request;
		struct {
			const char *result;
			size_t resultlen;
		} rpcall;
	};
};

/**
 * @brief Execute remote procedure call asynchronously
 *
 * Performs an asynchronous RPC call using the provided Lua code.
 * The callback will be invoked when the operation completes.
 *
 * @param r Ruleset instance
 * @param state Output parameter for operation state (for cancellation)
 * @param code Stream containing Lua RPC code
 * @param callback Callback structure for result notification
 * @return true if operation started successfully, false on immediate error
 */
bool ruleset_rpcall(
	struct ruleset *r, struct ruleset_state **state, struct stream *code,
	struct ruleset_callback *callback);

/**
 * @brief Update or load a Lua module
 *
 * Loads new Lua code and updates the specified module or the main ruleset.
 * This allows for dynamic updates without restarting the server.
 *
 * @param r Ruleset instance
 * @param modname Module name to update, or NULL for main ruleset
 * @param chunkname Chunk name for debugging (stack traces)
 * @param code Stream containing Lua code
 * @return true on success, false on error
 */
bool ruleset_update(
	struct ruleset *r, const char *modname, const char *chunkname,
	struct stream *code);

/**
 * @brief Load ruleset from file
 *
 * Loads and executes Lua code from the specified file to initialize
 * or update the ruleset.
 *
 * @param r Ruleset instance
 * @param filename Path to Lua file
 * @return true on success, false on error
 */
bool ruleset_loadfile(struct ruleset *r, const char *filename);

/**
 * @brief Trigger garbage collection
 *
 * Forces the Lua garbage collector to run, freeing unused memory.
 * This can be useful for memory management in long-running processes.
 *
 * @param r Ruleset instance
 * @return true on success, false on error
 */
bool ruleset_gc(struct ruleset *r);

/**
 * @brief Resolve domain name asynchronously
 *
 * Calls the ruleset.resolve() function to process a domain name request.
 * Used for SOCKS5 hostname requests, SOCKS4A, and HTTP CONNECT with domains.
 *
 * @param r Ruleset instance
 * @param state Output parameter for operation state (for cancellation)
 * @param request Domain name and port (e.g., "www.example.org:80")
 * @param username SOCKS authentication username (may be NULL)
 * @param password SOCKS authentication password (may be NULL)
 * @param callback Callback structure for result notification
 * @return true if operation started successfully, false on immediate error
 */
bool ruleset_resolve(
	struct ruleset *r, struct ruleset_state **state, const char *request,
	const char *username, const char *password,
	struct ruleset_callback *callback);

/**
 * @brief Route IPv4 address asynchronously
 *
 * Calls the ruleset.route() function to determine routing for an IPv4 address.
 * Used for direct IP connections through the proxy.
 *
 * @param r Ruleset instance
 * @param state Output parameter for operation state (for cancellation)
 * @param request IPv4 address and port (e.g., "192.168.1.1:80")
 * @param username SOCKS authentication username (may be NULL)
 * @param password SOCKS authentication password (may be NULL)
 * @param callback Callback structure for result notification
 * @return true if operation started successfully, false on immediate error
 */
bool ruleset_route(
	struct ruleset *r, struct ruleset_state **state, const char *request,
	const char *username, const char *password,
	struct ruleset_callback *callback);

/**
 * @brief Route IPv6 address asynchronously
 *
 * Calls the ruleset.route6() function to determine routing for an IPv6 address.
 * Used for direct IPv6 connections through the proxy.
 *
 * @param r Ruleset instance
 * @param state Output parameter for operation state (for cancellation)
 * @param request IPv6 address and port (e.g., "[2001:db8::1]:80")
 * @param username SOCKS authentication username (may be NULL)
 * @param password SOCKS authentication password (may be NULL)
 * @param callback Callback structure for result notification
 * @return true if operation started successfully, false on immediate error
 */
bool ruleset_route6(
	struct ruleset *r, struct ruleset_state **state, const char *request,
	const char *username, const char *password,
	struct ruleset_callback *callback);

/**
 * @brief Get virtual machine statistics
 *
 * Retrieves current memory usage statistics for the Lua virtual machine.
 *
 * @param r Ruleset instance
 * @param s Output parameter for statistics
 */
void ruleset_vmstats(const struct ruleset *r, struct ruleset_vmstats *s);

/**
 * @brief Get ruleset statistics
 *
 * Calls the ruleset.stats() function to generate runtime statistics.
 * The statistics can include performance metrics, connection counts,
 * or any custom data defined in the Lua ruleset.
 *
 * @param r Ruleset instance
 * @param dt Time delta since last statistics call
 * @param query Optional query parameter for specific statistics
 * @param len Output parameter for result length
 * @return Statistics string, or NULL on error
 */
const char *
ruleset_stats(struct ruleset *r, double dt, const char *query, size_t *len);

#endif /* RULESET_H */
