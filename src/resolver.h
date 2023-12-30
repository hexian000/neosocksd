/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RESOLVER_H
#define RESOLVER_H

#include "sockutil.h"
#include "util.h"

#include <stdbool.h>
#include <stdint.h>

struct ev_loop;
struct config;

struct resolver;

struct resolver_stats {
	uintmax_t num_query;
	uintmax_t num_success;
};

void resolver_init(void);
void resolver_cleanup(void);

struct resolver *resolver_new(struct ev_loop *loop, const struct config *conf);
const struct resolver_stats *resolver_stats(struct resolver *r);
void resolver_free(struct resolver *r);

struct resolve_cb {
	void (*cb)(
		handle_t h, struct ev_loop *loop, void *ctx,
		const struct sockaddr *sa);
	void *ctx;
};

handle_t resolve_do(
	struct resolver *r, struct resolve_cb cb, const char *name,
	const char *service, int family);
void resolve_cancel(handle_t h);

#endif /* RESOLVER_H */
