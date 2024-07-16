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
	RIDX_ERRORS = LUA_RIDX_LAST + 1,
	RIDX_FUNCTIONS = LUA_RIDX_LAST + 2,
	RIDX_CONTEXTS = LUA_RIDX_LAST + 3,
};

#define ERR_MEMORY "out of memory"
#define ERR_BAD_REGISTRY "Lua registry is corrupted"
#define ERR_NOT_YIELDABLE "await cannot be used in non-yieldable context"
#define ERR_INVALID_ROUTE "unable to parse route"

#if LUA_VERSION_NUM >= 504
#define HAVE_LUA_TOCLOSE 1
#define co_resume lua_resume
#elif LUA_VERSION_NUM == 503
#define LUA_LOADED_TABLE "_LOADED"
static inline int co_resume(lua_State *L, lua_State *from, int narg, int *nres)
{
	const int status = lua_resume(L, from, narg);
	*nres = lua_gettop(L);
	return status;
}
#endif

static inline struct ruleset *find_ruleset(lua_State *restrict L)
{
	void *ud;
	(void)lua_getallocf(L, &ud);
	return ud;
}

struct reader_status {
	struct stream *s;
	const char *prefix;
	size_t prefixlen;
};

const char *ruleset_reader(lua_State *L, void *ud, size_t *sz);

enum ruleset_functions {
	FUNC_REQUEST = 1,
	FUNC_LOADFILE,
	FUNC_INVOKE,
	FUNC_UPDATE,
	FUNC_STATS,
	FUNC_TICK,
	FUNC_TRACEBACK,
	FUNC_XPCALL,
	FUNC_RPCALL,
};

bool ruleset_pcall(struct ruleset *r, int func, int nargs, int nresults, ...);

bool ruleset_resume(struct ruleset *r, const void *ctx, int narg, ...);

int format_addr_(lua_State *L);

struct dialreq *pop_dialreq_(lua_State *L, const int n);

int api_async_(lua_State *L);

#endif /* RULESET_BASE_H */
