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
void ruleset_free(struct ruleset *r);

const char *ruleset_geterror(const struct ruleset *r, size_t *len);

bool ruleset_invoke(struct ruleset *r, struct stream *code);

struct ruleset_state;
void ruleset_cancel(struct ev_loop *loop, struct ruleset_state *state);

struct ruleset_callback {
	ev_watcher w_finish;
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
	struct ruleset *r, struct ruleset_state **state, struct stream *code,
	struct ruleset_callback *callback);

bool ruleset_update(
	struct ruleset *r, const char *modname, const char *chunkname,
	struct stream *code);
bool ruleset_loadfile(struct ruleset *r, const char *filename);

bool ruleset_gc(struct ruleset *r);

bool ruleset_resolve(
	struct ruleset *r, struct ruleset_state **state, const char *request,
	const char *username, const char *password,
	struct ruleset_callback *callback);
bool ruleset_route(
	struct ruleset *r, struct ruleset_state **state, const char *request,
	const char *username, const char *password,
	struct ruleset_callback *callback);
bool ruleset_route6(
	struct ruleset *r, struct ruleset_state **state, const char *request,
	const char *username, const char *password,
	struct ruleset_callback *callback);

void ruleset_vmstats(const struct ruleset *r, struct ruleset_vmstats *s);
const char *
ruleset_stats(struct ruleset *r, double dt, const char *query, size_t *len);

#endif /* RULESET_H */
