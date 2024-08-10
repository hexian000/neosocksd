/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RULESET_COMPAT_H
#define RULESET_COMPAT_H

#include "lua.h"

#if LUA_VERSION_NUM >= 504
#define HAVE_LUA_TOCLOSE 1
#define HAVE_LUA_WARNING 1
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

#endif /* RULESET_COMPAT_H */
