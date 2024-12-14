/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "api.h"

#include "lauxlib.h"
#include "lua.h"

#include <stdbool.h>
#include <time.h>

/* time.monotonic() */
static int time_monotonic(lua_State *restrict L)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t)) {
		lua_pushinteger(L, -1);
		return 1;
	}
	lua_pushnumber(L, t.tv_sec + t.tv_nsec * 1e-9);
	return 1;
}

/* time.process() */
static int time_process(lua_State *restrict L)
{
	struct timespec t;
	if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t)) {
		lua_pushinteger(L, -1);
		return 1;
	}
	lua_pushnumber(L, t.tv_sec + t.tv_nsec * 1e-9);
	return 1;
}

/* time.thread() */
static int time_thread(lua_State *restrict L)
{
	struct timespec t;
	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t)) {
		lua_pushinteger(L, -1);
		return 1;
	}
	lua_pushnumber(L, t.tv_sec + t.tv_nsec * 1e-9);
	return 1;
}

/* time.wall() */
static int time_wall(lua_State *restrict L)
{
	struct timespec t;
	if (clock_gettime(CLOCK_REALTIME, &t)) {
		lua_pushinteger(L, -1);
		return 1;
	}
	lua_pushnumber(L, t.tv_sec + t.tv_nsec * 1e-9);
	return 1;
}

/* cost, ... = time.measure(f, ...) */
static int time_measure(lua_State *restrict L)
{
	const int nargs = lua_gettop(L) - 1;
	lua_pushinteger(L, -1);
	lua_insert(L, 1);
	bool ok = true;
	struct timespec t0, t1;
	if (clock_gettime(CLOCK_MONOTONIC, &t0)) {
		ok = false;
	}
	lua_call(L, nargs, LUA_MULTRET);
	if (clock_gettime(CLOCK_MONOTONIC, &t1)) {
		ok = false;
	}
	const int nres = lua_gettop(L);
	if (!ok) {
		return nres;
	}
	lua_pushnumber(
		L, (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9);
	lua_replace(L, 1);
	return nres;
}

int luaopen_time(lua_State *restrict L)
{
	const luaL_Reg timelib[] = {
		{ "monotonic", time_monotonic },
		{ "process", time_process },
		{ "thread", time_thread },
		{ "wall", time_wall },

		{ "measure", time_measure }, /* uses monotonic time */
		{ NULL, NULL },
	};
	luaL_newlib(L, timelib);
	return 1;
}
