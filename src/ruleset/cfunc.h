/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RULESET_CFUNC_H
#define RULESET_CFUNC_H

#include <lua.h>

struct ruleset_callback;

struct ruleset_state {
	struct ruleset_callback *cb;
	/* Address of the caller's own storage slot for this state (e.g.
	 * &ctx->ruleset_state), so state_complete() can synchronously detach
	 * it the moment the routine finishes. See state_complete() in
	 * cfunc.c for why this matters. */
	struct ruleset_state **selfptr;
};

int cfunc_request(lua_State *restrict L);

int cfunc_loadfile(lua_State *restrict L);

int cfunc_loadconfig(lua_State *restrict L);

int cfunc_invoke(lua_State *restrict L);

int cfunc_rpcall(lua_State *restrict L);

int cfunc_update(lua_State *restrict L);

int cfunc_stats(lua_State *restrict L);

int cfunc_metrics(lua_State *restrict L);

int cfunc_tick(lua_State *restrict L);

int cfunc_healthy(lua_State *restrict L);

int cfunc_gc(lua_State *restrict L);

#endif /* RULESET_CFUNC_H */
