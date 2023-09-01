#ifndef RULESET_H
#define RULESET_H

#include "sockutil.h"

#include <stdbool.h>
#include <stddef.h>

struct ev_loop;
struct ruleset;

struct ruleset_memstats {
	size_t num_object;
	size_t byt_allocated;
};

struct ruleset *ruleset_new(struct ev_loop *loop);
const char *ruleset_invoke(struct ruleset *r, const char *code, size_t len);
const char *ruleset_load(struct ruleset *r, const char *code, size_t len);
const char *ruleset_loadfile(struct ruleset *r, const char *filename);
void ruleset_gc(struct ruleset *r);
void ruleset_free(struct ruleset *r);

struct dialreq *ruleset_resolve(struct ruleset *r, const char *request);
struct dialreq *ruleset_route(struct ruleset *r, const char *request);
struct dialreq *ruleset_route6(struct ruleset *r, const char *request);

void ruleset_memstats(const struct ruleset *r, struct ruleset_memstats *s);
const char *ruleset_stats(struct ruleset *r, double dt);

#endif /* RULESET_H */
