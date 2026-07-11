/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/time.h"

#include "os/clock.h"

#include <lauxlib.h>
#include <lua.h>

#include <stdbool.h>
#include <time.h>

/* Push the given clock's reading in seconds, or -1 on failure. */
static int
push_clock(lua_State *restrict L, bool (*clock_fn)(struct timespec *restrict))
{
	struct timespec t;
	if (!clock_fn(&t)) {
		lua_pushinteger(L, -1);
		return 1;
	}
	lua_pushnumber(L, TIMESPEC_NANO(t) * 1e-9);
	return 1;
}

/* time.monotonic() */
static int time_monotonic(lua_State *restrict L)
{
	return push_clock(L, clock_monotonic);
}

/* time.process() */
static int time_process(lua_State *restrict L)
{
	return push_clock(L, clock_process);
}

/* time.thread() */
static int time_thread(lua_State *restrict L)
{
	return push_clock(L, clock_thread);
}

/* time.unix() */
static int time_unix(lua_State *restrict L)
{
	return push_clock(L, clock_unix);
}

/* cost, ... = time.measure(f, ...) */
static int time_measure(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TFUNCTION);
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
	lua_pushnumber(L, TIMESPEC_DIFF(ts1, ts0) * 1e-9);
	lua_replace(L, 1);
	return nres;
}

int luaopen_time(lua_State *restrict L)
{
	const luaL_Reg timelib[] = {
		{ "monotonic", time_monotonic },
		{ "process", time_process },
		{ "thread", time_thread },
		{ "unix", time_unix },

		{ "measure", time_measure }, /* uses monotonic time */
		{ NULL, NULL },
	};
	luaL_newlib(L, timelib);
	return 1;
}
