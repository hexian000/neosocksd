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
};

struct ruleset *ruleset_new(struct ev_loop *loop);
void ruleset_free(struct ruleset *r);

const char *ruleset_geterror(struct ruleset *ruleset, size_t *len);

bool ruleset_invoke(struct ruleset *ruleset, struct stream *code);

struct ruleset_state;
void ruleset_cancel(struct ruleset_state *state);

struct ruleset_rpcall_cb {
	void (*func)(void *data, const char *result, size_t resultlen);
	void *data;
};
bool ruleset_rpcall(
	struct ruleset *ruleset, struct ruleset_state **state,
	struct stream *code, const struct ruleset_rpcall_cb *callback);

bool ruleset_update(
	struct ruleset *ruleset, const char *modname, const char *chunkname,
	struct stream *code);
bool ruleset_loadfile(struct ruleset *ruleset, const char *filename);

bool ruleset_gc(struct ruleset *r);

struct ruleset_request_cb {
	void (*func)(struct ev_loop *loop, void *data, struct dialreq *req);
	struct ev_loop *loop;
	void *data;
};
bool ruleset_resolve(
	struct ruleset *ruleset, struct ruleset_state **state,
	const char *request, const char *username, const char *password,
	const struct ruleset_request_cb *callback);
bool ruleset_route(
	struct ruleset *ruleset, struct ruleset_state **state,
	const char *request, const char *username, const char *password,
	const struct ruleset_request_cb *callback);
bool ruleset_route6(
	struct ruleset *ruleset, struct ruleset_state **state,
	const char *request, const char *username, const char *password,
	const struct ruleset_request_cb *callback);

void ruleset_vmstats(const struct ruleset *ruleset, struct ruleset_vmstats *s);
const char *ruleset_stats(
	struct ruleset *ruleset, double dt, const char *query, size_t *len);

#endif /* RULESET_H */
