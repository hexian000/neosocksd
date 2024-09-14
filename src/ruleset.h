/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RULESET_H
#define RULESET_H

#include <stdbool.h>
#include <stddef.h>

struct ev_loop;
struct stream;
struct ruleset;
struct dialreq;

struct ruleset_vmstats {
	size_t num_object;
	size_t byt_allocated;
	size_t num_routine;
};

struct ruleset *ruleset_new(struct ev_loop *loop);
void ruleset_gc(struct ruleset *r);
void ruleset_free(struct ruleset *r);

const char *ruleset_geterror(struct ruleset *r, size_t *len);

bool ruleset_invoke(struct ruleset *r, struct stream *code);
bool ruleset_update(
	struct ruleset *r, const char *modname, struct stream *code,
	const char *chunkname);
bool ruleset_loadfile(struct ruleset *r, const char *filename);

struct rpcall_state;
typedef void (*rpcall_finished_fn)(
	struct rpcall_state *state, bool ok, const char *result,
	size_t resultlen);
struct rpcall_state {
	rpcall_finished_fn callback;
	void *data;
};
struct rpcall_state *ruleset_rpcall(
	struct ruleset *r, struct stream *code,
	const struct rpcall_state *init_state);

struct dialreq *ruleset_resolve(
	struct ruleset *r, const char *request, const char *username,
	const char *password);
struct dialreq *ruleset_route(
	struct ruleset *r, const char *request, const char *username,
	const char *password);
struct dialreq *ruleset_route6(
	struct ruleset *r, const char *request, const char *username,
	const char *password);

void ruleset_vmstats(const struct ruleset *r, struct ruleset_vmstats *s);
const char *ruleset_stats(struct ruleset *r, double dt, size_t *len);

#endif /* RULESET_H */
