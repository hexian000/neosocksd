/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "time.h"

#include "os/clock.h"

#include "lauxlib.h"
#include "lua.h"

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* time.monotonic() */
static int time_monotonic(lua_State *restrict L)
{
	struct timespec t;
	if (!clock_monotonic(&t)) {
		lua_pushinteger(L, -1);
		return 1;
	}
	lua_pushnumber(L, TIMESPEC_NANO(t) * 1e-9);
	return 1;
}

/* time.process() */
static int time_process(lua_State *restrict L)
{
	struct timespec t;
	if (!clock_process(&t)) {
		lua_pushinteger(L, -1);
		return 1;
	}
	lua_pushnumber(L, TIMESPEC_NANO(t) * 1e-9);
	return 1;
}

/* time.thread() */
static int time_thread(lua_State *restrict L)
{
	struct timespec t;
	if (!clock_thread(&t)) {
		lua_pushinteger(L, -1);
		return 1;
	}
	lua_pushnumber(L, TIMESPEC_NANO(t) * 1e-9);
	return 1;
}

/* time.wall() */
static int time_wall(lua_State *restrict L)
{
	struct timespec t;
	if (!clock_realtime(&t)) {
		lua_pushinteger(L, -1);
		return 1;
	}
	lua_pushnumber(L, TIMESPEC_NANO(t) * 1e-9);
	return 1;
}

/* cost, ... = time.measure(f, ...) */
static int time_measure(lua_State *restrict L)
{
	const int nargs = lua_gettop(L) - 1;
	lua_pushinteger(L, -1);
	lua_insert(L, 1);
	bool ok = true;
	struct timespec ts0, ts1;
	if (!clock_monotonic(&ts0)) {
		ok = false;
	}
	lua_call(L, nargs, LUA_MULTRET);
	if (!clock_monotonic(&ts1)) {
		ok = false;
	}
	const int nres = lua_gettop(L);
	if (!ok) {
		return nres;
	}
	lua_pushnumber(L, TIMESPEC_DIFF(ts0, ts1) * 1e-9);
	lua_replace(L, 1);
	return nres;
}

#undef READ_TIMESPEC

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
