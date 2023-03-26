#ifndef RULESET_H
#define RULESET_H

#include "conf.h"
#include "sockutil.h"

#include <stdbool.h>
#include <stddef.h>

struct ruleset;

struct ruleset *ruleset_new(const struct config *conf);
bool ruleset_load(struct ruleset *r, const char *rulestr);
bool ruleset_loadfile(struct ruleset *r, const char *filename);
void ruleset_gc(struct ruleset *r);
size_t ruleset_memused(struct ruleset *r);
void ruleset_free(struct ruleset *r);

struct dialreq *ruleset_resolve(struct ruleset *r, const char *addr_str);
struct dialreq *ruleset_route(struct ruleset *r, const char *addr_str);
struct dialreq *ruleset_route6(struct ruleset *r, const char *addr_str);

#endif /* RULESET_H */
