/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RULESET_H
#define RULESET_H

#include "sockutil.h"

#include <stdbool.h>
#include <stddef.h>

struct ev_loop;
struct stream;
struct ruleset;

struct ruleset_vmstats {
	size_t num_object;
	size_t byt_allocated;
	size_t num_routine;
};

struct ruleset *ruleset_new(struct ev_loop *loop);
void ruleset_gc(struct ruleset *r);
void ruleset_free(struct ruleset *r);

const char *ruleset_error(struct ruleset *r, size_t *len);

bool ruleset_invoke(struct ruleset *r, struct stream *code);
bool ruleset_update(struct ruleset *r, const char *modname, struct stream *code);
bool ruleset_loadfile(struct ruleset *r, const char *filename);

bool ruleset_rpcall(
	struct ruleset *r, struct stream *code, const void **result,
	size_t *resultlen);

struct dialreq *ruleset_resolve(struct ruleset *r, const char *request);
struct dialreq *ruleset_route(struct ruleset *r, const char *request);
struct dialreq *ruleset_route6(struct ruleset *r, const char *request);

void ruleset_vmstats(const struct ruleset *r, struct ruleset_vmstats *s);
const char *ruleset_stats(struct ruleset *r, double dt, size_t *len);

#endif /* RULESET_H */
