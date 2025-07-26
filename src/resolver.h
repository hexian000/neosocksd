/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RESOLVER_H
#define RESOLVER_H

#include "util.h"

#include <stdint.h>

struct ev_loop;
struct config;

struct resolver;
struct resolve_query;

struct resolver_stats {
	uintmax_t num_query;
	uintmax_t num_success;
};

void resolver_init(void);
void resolver_cleanup(void);

struct resolver *resolver_new(struct ev_loop *loop, const struct config *conf);
const struct resolver_stats *resolver_stats(const struct resolver *r);
void resolver_free(struct resolver *r);

struct sockaddr;

struct resolve_cb {
	void (*func)(
		struct resolve_query *q, struct ev_loop *loop, void *data,
		const struct sockaddr *sa);
	void *data;
};

struct resolve_query *resolve_do(
	struct resolver *r, struct resolve_cb cb, const char *name,
	const char *service, int family);
void resolve_cancel(struct resolve_query *q);

#endif /* RESOLVER_H */
