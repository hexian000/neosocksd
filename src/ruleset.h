/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RULESET_H
#define RULESET_H

#include <ev.h>

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
void ruleset_free(struct ruleset *ruleset);

const char *ruleset_geterror(struct ruleset *ruleset, size_t *len);

bool ruleset_invoke(struct ruleset *ruleset, struct stream *code);

struct ruleset_state;
void ruleset_cancel(struct ev_loop *loop, struct ruleset_state *state);

struct ruleset_callback {
	struct ev_watcher w_finish;
	bool ok;
	union {
		struct {
			struct dialreq *req;
		} request;
		struct {
			const char *result;
			size_t resultlen;
		} rpcall;
	};
};

bool ruleset_rpcall(
	struct ruleset *ruleset, struct ruleset_state **state,
	struct stream *code, struct ruleset_callback *callback);

bool ruleset_update(
	struct ruleset *ruleset, const char *modname, const char *chunkname,
	struct stream *code);
bool ruleset_loadfile(struct ruleset *ruleset, const char *filename);

bool ruleset_gc(struct ruleset *ruleset);

bool ruleset_resolve(
	struct ruleset *ruleset, struct ruleset_state **state,
	const char *request, const char *username, const char *password,
	struct ruleset_callback *callback);
bool ruleset_route(
	struct ruleset *ruleset, struct ruleset_state **state,
	const char *request, const char *username, const char *password,
	struct ruleset_callback *callback);
bool ruleset_route6(
	struct ruleset *ruleset, struct ruleset_state **state,
	const char *request, const char *username, const char *password,
	struct ruleset_callback *callback);

void ruleset_vmstats(const struct ruleset *ruleset, struct ruleset_vmstats *s);
const char *ruleset_stats(
	struct ruleset *ruleset, double dt, const char *query, size_t *len);

#endif /* RULESET_H */
