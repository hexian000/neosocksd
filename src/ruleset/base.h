/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
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
	struct {
		int memlimit_kb;
		bool traceback;
	} config;
	lua_State *L;
	struct ev_timer w_ticker;
	struct ev_idle w_idle;
};

enum ruleset_ridx {
	/* t[idx] = short string */
	RIDX_CONSTANT = LUA_RIDX_LAST + 1,
	/* last error */
	RIDX_LASTERROR,
	/* t[lightuserdata] = thread */
	RIDX_AWAIT_CONTEXT,
	/* t[thread] = true */
	RIDX_IDLE_THREAD,
};

#define ERR_MEMORY "out of memory"
#define ERR_BAD_REGISTRY "Lua registry is corrupted"
#define ERR_INVALID_INVOKE "invalid invocation target"
#define ERR_NOT_ASYNC_ROUTINE "not in asynchronous routine"

#define HAVE_LUA_WARNING (LUA_VERSION_NUM >= 504)
#define HAVE_LUA_TOCLOSE (LUA_VERSION_NUM >= 504)

struct ruleset *aux_getruleset(lua_State *L);

void aux_newweaktable(lua_State *L, const char *mode);

/* [-0, +1, v] */
void aux_getregtable(lua_State *L, int idx);

/* [-0, +1, v] */
lua_State *aux_getthread(lua_State *L);

const char *aux_reader(lua_State *L, void *ud, size_t *sz);

/* [-1, +1, v] */
int aux_format_addr(lua_State *L);

/* [-n, +(0|1), -] */
bool aux_todialreq(lua_State *L, int n);

int aux_traceback(lua_State *L);

/* co stack: finish ? func ...(narg) */
int aux_resume(lua_State *L, lua_State *from, int narg);

/* main routine */
bool ruleset_pcall(
	struct ruleset *r, lua_CFunction func, int nargs, int nresults, ...);

/* asynchronous routine */
void ruleset_resume(struct ruleset *r, void *ctx, int narg, ...);

#endif /* RULESET_BASE_H */
