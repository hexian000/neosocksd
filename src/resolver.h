/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RESOLVER_H
#define RESOLVER_H

/**
 * @file resolver.h
 * @brief DNS resolver interface
 *
 * Integrated with the libev event loop; supports async or synchronous DNS
 * resolution depending on build configuration.
 */

#include "os/socket.h"

#include <stdint.h>

struct ev_loop;
struct config;

/** Opaque resolver instance handle */
struct resolver;
/** Opaque DNS query handle */
struct resolve_query;

/**
 * @brief DNS resolver statistics; counters are monotonically increasing
 */
struct resolver_stats {
	uint_least64_t num_query;
	uint_least64_t num_success;
};

/** @brief Initialize the global resolver subsystem; call once before any resolver use */
void resolver_init(void);

/** @brief Cleanup the global resolver subsystem; call at program shutdown */
void resolver_cleanup(void);

/**
 * @brief Create a new resolver instance
 * @param loop Event loop to integrate with (not owned; must remain valid)
 * @param conf Configuration containing nameserver settings (must not be NULL)
 * @return New resolver instance or NULL on allocation failure; free with resolver_free()
 */
struct resolver *
resolver_new(struct ev_loop *restrict loop, const struct config *restrict conf);

/**
 * @brief Re-apply the configured nameserver to an existing resolver.
 *
 * resolver_new() snapshots conf->nameserver at creation, which happens before
 * a boot config is loaded; call this afterwards so a nameserver that appears
 * only in the boot config still takes effect. No-op without c-ares, when async
 * resolution is unavailable, or when no nameserver is configured.
 *
 * @param r Resolver instance
 * @param conf Configuration carrying the (possibly boot-updated) nameserver
 *             (must not be NULL)
 */
void resolver_setnameserver(
	struct resolver *restrict r, const struct config *restrict conf);

/**
 * @brief Get resolver statistics
 * @param r Resolver instance
 * @return Pointer valid until resolver is freed
 */
const struct resolver_stats *resolver_stats(const struct resolver *restrict r);

/**
 * @brief Free a resolver instance; cancels pending queries without invoking callbacks
 * @param r Resolver instance (safe to pass NULL)
 */
void resolver_free(struct resolver *restrict r);

/**
 * @brief Upper bound on the addresses one query answers with.
 *
 * A name commonly resolves to more than one address, and a caller that dials
 * only the first fails outright whenever that one is unreachable -- so the
 * whole answer is carried, capped here. The cap bounds the query's own storage
 * and, through it, how far a caller may fan out over one name.
 */
#define RESOLVE_MAX_ADDR 4

/** @brief Callback structure for DNS resolution completion (always from event loop context) */
struct resolve_cb {
	/**
	 * @brief Completion callback; called exactly once; must not call resolve_cancel() on q
	 * @param q The completed query (freed automatically after return)
	 * @param loop Event loop where the query was processed
	 * @param data User data passed during query initiation
	 * @param addr Resolved socket addresses, in the order they are meant to
	 *             be tried; valid until the callback returns, NULL on
	 *             failure
	 * @param num_addr Number of addresses in @p addr; 0 on failure (DNS
	 *                 error, no address, or OOM)
	 */
	void (*func)(
		struct resolve_query *q, struct ev_loop *loop, void *data,
		const union sockaddr_max *addr, size_t num_addr);
	/** User data passed to callback (not freed by resolver). */
	void *data;
};

/**
 * @brief Start a DNS resolution; name and service are copied internally
 * @param r Resolver instance (must not be NULL)
 * @param cb Callback invoked on completion (cb.func may be NULL to ignore)
 * @param name Hostname to resolve (may be NULL for localhost)
 * @param service Service name or port string (e.g. "80"); may be NULL
 * @param family AF_INET, AF_INET6, or AF_UNSPEC. A pinned family answers with
 *               at most one address; AF_UNSPEC answers with up to
 *               RESOLVE_MAX_ADDR of them, the families interleaved as RFC 8305
 *               4 prescribes so a caller walking the list alternates between
 *               them.
 * @return Query handle (freed automatically after callback); NULL on OOM
 */
struct resolve_query *resolve_do(
	struct resolver *restrict r, struct resolve_cb cb,
	const char *restrict name, const char *restrict service, int family);

/**
 * @brief Cancel a pending DNS query
 *
 * Prevents the callback from being invoked. The query continues to run
 * in the background (for c-ares) but the result is discarded. The query
 * memory is freed when resolution completes internally.
 *
 * The handle lives from resolve_do() until the callback is invoked or
 * resolver_free() runs; both free the query. Cancelling suppresses the
 * callback, so no observable event marks the handle's death afterwards --
 * drop it at the cancel. Repeated cancels while the handle is live are a
 * no-op.
 *
 * @param q Query to cancel (safe to pass NULL)
 *
 * @warning Do not call from within the query's own callback, nor on a query
 * whose callback has already returned.
 */
void resolve_cancel(struct resolve_query *restrict q);

#endif /* RESOLVER_H */
