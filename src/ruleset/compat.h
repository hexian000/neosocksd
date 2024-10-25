/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RULESET_COMPAT_H
#define RULESET_COMPAT_H

#include "lua.h"

#if LUA_VERSION_NUM >= 504
#define HAVE_LUA_TOCLOSE 1
#define HAVE_LUA_WARNING 1
#elif LUA_VERSION_NUM == 503
#define HAVE_LUA_TOCLOSE 0
#define HAVE_LUA_WARNING 0
#define LUA_LOADED_TABLE "_LOADED"
#endif

#endif /* RULESET_COMPAT_H */
