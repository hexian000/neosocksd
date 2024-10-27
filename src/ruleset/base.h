/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RULESET_BASE_H
#define RULESET_BASE_H

#include "ruleset.h"

#include "lua.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>

struct ruleset {
	struct ev_loop *loop;
	struct ruleset_vmstats vmstats;
	lua_State *L;
	struct ev_timer w_ticker;
};

enum ruleset_ridx {
	/* t[idx] = string */
	RIDX_CONSTANT = LUA_RIDX_LAST + 1,
	/* last error */
	RIDX_LASTERROR,
	/* t[coroutine] = finish callback */
	RIDX_ASYNC_ROUTINE,
	/* t[lightuseradta] = coroutine */
	RIDX_AWAIT_CONTEXT,
};

#define ERR_MEMORY "out of memory"
#define ERR_BAD_REGISTRY "Lua registry is corrupted"
#define ERR_INVALID_ROUTE "unable to parse route"
#define ERR_NOT_ASYNC_ROUTINE "not in asynchronous routine"

struct ruleset *aux_getruleset(lua_State *L);

const char *aux_reader(lua_State *L, void *ud, size_t *sz);

/* [-1, +1, v] */
int aux_format_addr(lua_State *L);

/* [-n, +1, -] */
struct dialreq *aux_todialreq(lua_State *L, int n);

int aux_traceback(lua_State *L);

void aux_resume(lua_State *L, int tidx, int narg);

/* main routine */
bool ruleset_pcall(
	struct ruleset *r, lua_CFunction func, int nargs, int nresults, ...);

/* asynchronous routine */
void ruleset_resume(struct ruleset *r, void *ctx, int narg, ...);

#endif /* RULESET_BASE_H */
