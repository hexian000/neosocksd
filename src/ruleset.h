/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
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
	size_t num_context;
};

struct ruleset *ruleset_new(struct ev_loop *loop);
void ruleset_free(struct ruleset *r);

const char *ruleset_geterror(struct ruleset *r, size_t *len);

bool ruleset_invoke(struct ruleset *r, struct stream *code);

struct rpcall_state;
struct rpcall_cb {
	void (*func)(void *data, const char *result, size_t resultlen);
	void *data;
};
struct rpcall_state *ruleset_rpcall(
	struct ruleset *r, struct stream *code, struct rpcall_cb callback);
void ruleset_rpcall_cancel(struct rpcall_state *state);

bool ruleset_update(
	struct ruleset *r, const char *modname, struct stream *code,
	const char *chunkname);
bool ruleset_loadfile(struct ruleset *r, const char *filename);

bool ruleset_gc(struct ruleset *r);

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
const char *
ruleset_stats(struct ruleset *r, double dt, const char *query, size_t *len);

#endif /* RULESET_H */
