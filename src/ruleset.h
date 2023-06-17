#ifndef RULESET_H
#define RULESET_H

#include "conf.h"
#include "sockutil.h"

#include <stdbool.h>
#include <stddef.h>

struct ev_loop;
struct ruleset;

struct ruleset *ruleset_new(struct ev_loop *loop, const struct config *conf);
const char *ruleset_invoke(struct ruleset *r, const char *code, size_t len);
const char *ruleset_load(struct ruleset *r, const char *code, size_t len);
const char *ruleset_loadfile(struct ruleset *r, const char *filename);
void ruleset_gc(struct ruleset *r);
void ruleset_free(struct ruleset *r);

struct dialreq *ruleset_resolve(struct ruleset *r, const char *request);
struct dialreq *ruleset_route(struct ruleset *r, const char *request);
struct dialreq *ruleset_route6(struct ruleset *r, const char *request);

size_t ruleset_memused(struct ruleset *r);
const char *ruleset_stats(struct ruleset *r, double dt);

#endif /* RULESET_H */
