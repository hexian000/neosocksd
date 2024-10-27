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

static inline struct ruleset *find_ruleset(lua_State *restrict L)
{
	void *ud;
	(void)lua_getallocf(L, &ud);
	return ud;
}

const char *aux_reader(lua_State *L, void *ud, size_t *sz);

int aux_traceback(lua_State *L);

void aux_resume(lua_State *L, int tidx, int narg);

/* [-1, +1, v] */
int aux_format_addr(lua_State *L);

/* [-n, +1, -] */
struct dialreq *aux_todialreq(lua_State *L, const int n);

bool ruleset_pcall(
	struct ruleset *r, lua_CFunction func, int nargs, int nresults, ...);

void ruleset_resume(struct ruleset *r, const void *ctx, int narg, ...);

#endif /* RULESET_BASE_H */
