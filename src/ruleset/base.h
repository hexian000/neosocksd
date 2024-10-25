/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RULESET_BASE_H
#define RULESET_BASE_H

#include "ruleset.h"
#include "util.h"

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
	/* t[idx] = function */
	RIDX_CFUNCTION = LUA_RIDX_LAST + 2,
	/* last error */
	RIDX_LASTERROR = LUA_RIDX_LAST + 3,
	/* t[coroutine] = finish callback */
	RIDX_ASYNC_ROUTINE = LUA_RIDX_LAST + 4,
	/* t[lightuseradta] = coroutine */
	RIDX_AWAIT_CONTEXT = LUA_RIDX_LAST + 5,
};

#define ERR_MEMORY "out of memory"
#define ERR_BAD_REGISTRY "Lua registry is corrupted"
#define ERR_INVALID_ROUTE "unable to parse route"
#define ERR_NOT_YIELDABLE "current routine is not yieldable"

static inline struct ruleset *find_ruleset(lua_State *restrict L)
{
	void *ud;
	(void)lua_getallocf(L, &ud);
	return ud;
}

const char *aux_reader(lua_State *L, void *ud, size_t *sz);

int aux_traceback(lua_State *L);

void aux_resume(lua_State *L, int tidx, int narg);

enum ruleset_functions {
	FUNC_REQUEST = 1,
	FUNC_LOADFILE,
	FUNC_INVOKE,
	FUNC_UPDATE,
	FUNC_STATS,
	FUNC_TICK,
	FUNC_RPCALL,
};

bool ruleset_pcall(struct ruleset *r, int func, int nargs, int nresults, ...);

void ruleset_resume(struct ruleset *r, const void *ctx, int narg, ...);

int format_addr_(lua_State *L);

struct dialreq *make_dialreq_(lua_State *L, const int n);

#endif /* RULESET_BASE_H */
