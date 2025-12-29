/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RESOLVER_H
#define RESOLVER_H

/**
 * @file resolver.h
 * @brief DNS resolver interface
 *
 * This module provides a DNS resolution service that can work with or without
 * c-ares library. It integrates with libev event loop for non-blocking operation
 * and maintains statistics about resolution requests.
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
 */
struct resolver_stats {
	uintmax_t num_query;
	uintmax_t num_success;
};

/**
 * @brief Initialize the global resolver subsystem
 *
 * Must be called once before using any resolver functions.
 * Initializes c-ares library if available.
 */
void resolver_init(void);

/**
 * @brief Cleanup the global resolver subsystem
 *
 * Should be called during program shutdown to free global resources.
 * Cleans up c-ares library if available.
 */
void resolver_cleanup(void);

/**
 * @brief Create a new resolver instance
 *
 * @param loop Event loop to integrate with
 * @param conf Configuration containing nameserver settings
 * @return New resolver instance or NULL on failure
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
 * Cancels all pending queries and frees associated resources.
 * @param r Resolver instance (may be NULL)
 */
void resolver_free(struct resolver *r);

struct sockaddr;

/**
 * @brief Callback structure for DNS resolution completion
 *
 * Called when a DNS query completes, either successfully or with an error.
 */
struct resolve_cb {
	/**
	 * @brief Completion callback function
	 *
	 * @param q The completed query (will be freed after callback returns)
	 * @param loop Event loop where the query was processed
	 * @param data User data passed during query initiation
	 * @param sa Resolved socket address (NULL on failure)
	 */
	void (*func)(
		struct resolve_query *q, struct ev_loop *loop, void *data,
		const struct sockaddr *sa);
	void *data; /**< User data to pass to callback */
};

/**
 * @brief Start a DNS resolution
 *
 * Initiates a DNS query for the given hostname and service. The callback
 * will be invoked when resolution completes or fails.
 *
 * @param r Resolver instance
 * @param cb Callback to invoke on completion
 * @param name Hostname to resolve (required)
 * @param service Service name or port number (optional)
 * @param family Address family (AF_INET, AF_INET6, or AF_UNSPEC)
 * @return Query handle for cancellation, or NULL on immediate failure
 */
struct resolve_query *resolve_do(
	struct resolver *r, struct resolve_cb cb, const char *name,
	const char *service, int family);

/**
 * @brief Cancel a pending DNS query
 *
 * Prevents the callback from being invoked. The query handle becomes
 * invalid after this call.
 *
 * @param q Query to cancel (may be NULL)
 */
void resolve_cancel(struct resolve_query *q);

#endif /* RESOLVER_H */
