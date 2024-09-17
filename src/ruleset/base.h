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
	RIDX_CONSTANT = LUA_RIDX_LAST + 1,
	RIDX_CFUNCTION = LUA_RIDX_LAST + 2,
	RIDX_AWAIT_CONTEXT = LUA_RIDX_LAST + 3,
	RIDX_LASTERROR = LUA_RIDX_LAST + 4,
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

const char *ruleset_reader(lua_State *L, void *ud, size_t *sz);

enum ruleset_functions {
	FUNC_REQUEST = 1,
	FUNC_LOADFILE,
	FUNC_INVOKE,
	FUNC_UPDATE,
	FUNC_STATS,
	FUNC_TICK,
	FUNC_TRACEBACK,
	FUNC_RPCALL,
};

bool ruleset_pcall(struct ruleset *r, int func, int nargs, int nresults, ...);

bool ruleset_resume(struct ruleset *r, const void *ctx, int narg, ...);

int format_addr_(lua_State *L);

struct dialreq *pop_dialreq_(lua_State *L, const int n);

int ruleset_traceback_(lua_State *L);

#endif /* RULESET_BASE_H */
