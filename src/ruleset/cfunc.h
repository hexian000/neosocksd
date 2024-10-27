/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RULESET_CFUNC_H
#define RULESET_CFUNC_H

#include "ruleset.h"

#include "lua.h"

int cfunc_request(lua_State *L);

int cfunc_loadfile(lua_State *L);

int cfunc_invoke(lua_State *L);

struct rpcall_state {
	struct rpcall_cb callback;
};
int cfunc_rpcall(lua_State *L);

int cfunc_update(lua_State *L);

int cfunc_stats(lua_State *L);

int cfunc_tick(lua_State *L);

int cfunc_gc(lua_State *L);

#endif /* RULESET_CFUNC_H */
