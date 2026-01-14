/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RESOLVER_H
#define RESOLVER_H

/**
 * @file resolver.h
 * @brief DNS resolver interface
 *
 * This module provides a DNS resolution service integrated with libev event
 * loop. It supports both asynchronous and synchronous DNS resolution depending
 * on build configuration, and maintains statistics about resolution requests.
 *
 * Usage:
 *   1. Call resolver_init() once at program startup
 *   2. Create resolver instance with resolver_new()
 *   3. Start DNS queries with resolve_do()
 *   4. Optionally cancel pending queries with resolve_cancel()
 *   5. Free resolver with resolver_free()
 *   6. Call resolver_cleanup() at program shutdown
 */

#include "util.h"

#include <stdint.h>

struct ev_loop;
struct config;

/** Opaque resolver instance handle */
struct resolver;
/** Opaque DNS query handle */
struct resolve_query;

/**
 * @brief DNS resolver statistics
 *
 * Contains counters for tracking resolver performance and success rates.
 * All counters are monotonically increasing and never reset.
 */
struct resolver_stats {
	uintmax_t num_query;
	uintmax_t num_success;
};

/**
 * @brief Initialize the global resolver subsystem
 *
 * Must be called once before using any resolver functions.
 * Initializes any required libraries for DNS resolution.
 */
void resolver_init(void);

/**
 * @brief Cleanup the global resolver subsystem
 *
 * Should be called during program shutdown to free global resources.
 */
void resolver_cleanup(void);

/**
 * @brief Create a new resolver instance
 *
 * Creates a resolver that will use the provided event loop for scheduling.
 * The resolver does not take ownership of the event loop.
 *
 * @param loop Event loop to integrate with (must remain valid)
 * @param conf Configuration containing nameserver settings (may be NULL)
 * @return New resolver instance or NULL on allocation failure
 *
 * @note The caller is responsible for freeing with resolver_free()
 */
struct resolver *resolver_new(struct ev_loop *loop, const struct config *conf);

/**
 * @brief Get resolver statistics
 *
 * @param r Resolver instance
 * @return Pointer to statistics structure (valid until resolver is freed)
 */
const struct resolver_stats *resolver_stats(const struct resolver *r);

/**
 * @brief Free a resolver instance
 *
 * Cancels all pending queries implicitly. Pending query callbacks will
 * NOT be invoked. Frees all associated resources.
 *
 * @param r Resolver instance (safe to pass NULL)
 */
void resolver_free(struct resolver *r);

struct sockaddr;

/**
 * @brief Callback structure for DNS resolution completion
 *
 * Called when a DNS query completes, either successfully or with an error.
 * The callback is always invoked from within the event loop context.
 */
struct resolve_cb {
	/**
	 * @brief Completion callback function
	 *
	 * Called exactly once when resolution completes or fails.
	 * The callback must not call resolve_cancel() on the same query.
	 *
	 * @param q The completed query (freed automatically after return)
	 * @param loop Event loop where the query was processed
	 * @param data User data passed during query initiation
	 * @param sa Resolved socket address, or NULL on:
	 *           - DNS resolution failure
	 *           - No addresses found for the requested family
	 *           - Internal error (logged)
	 */
	void (*func)(
		struct resolve_query *q, struct ev_loop *loop, void *data,
		const struct sockaddr *sa);
	void *data; /**< User data passed to callback (not freed by resolver) */
};

/**
 * @brief Start a DNS resolution
 *
 * Initiates a DNS query for the given hostname and service. The callback
 * will be invoked when resolution completes or fails. The name and service
 * strings are copied internally, so they need not remain valid after this
 * call returns.
 *
 * @param r Resolver instance (must not be NULL)
 * @param cb Callback to invoke on completion (cb.func may be NULL to ignore)
 * @param name Hostname to resolve (copied internally, may be NULL for localhost)
 * @param service Service name (e.g., "http") or port number as string
 *                (e.g., "80"), copied internally, may be NULL
 * @param family Address family filter:
 *               - AF_INET: IPv4 only
 *               - AF_INET6: IPv6 only
 *               - AF_UNSPEC: either IPv4 or IPv6
 * @return Query handle for cancellation, or NULL on allocation failure
 *
 * @note The query is automatically freed after the callback returns.
 *       Do not free the query handle manually.
 */
struct resolve_query *resolve_do(
	struct resolver *r, struct resolve_cb cb, const char *name,
	const char *service, int family);

/**
 * @brief Cancel a pending DNS query
 *
 * Prevents the callback from being invoked. The query continues to run
 * in the background (for c-ares) but the result is discarded. The query
 * memory is freed when resolution completes internally.
 *
 * Safe to call multiple times on the same query. Safe to call after
 * the query has already completed (no-op).
 *
 * @param q Query to cancel (safe to pass NULL)
 *
 * @warning Do not call from within the query's own callback.
 */
void resolve_cancel(struct resolve_query *q);

#endif /* RESOLVER_H */
