/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "regex.h"

#include "lauxlib.h"
#include "lua.h"

#include <regex.h>

#define MT_REGEX "regex"

static int regex_gc_(lua_State *restrict L)
{
	regex_t *preg = lua_touserdata(L, 1);
	regfree(preg);
	return 0;
}

/* regex.compile(pat) */
static int regex_compile_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TSTRING);
	const char *pat = lua_tostring(L, 1);
	regex_t *preg = lua_newuserdata(L, sizeof(regex_t));
	const int err = regcomp(preg, pat, REG_EXTENDED);
	if (err != 0) {
		char errbuf[256];
		const size_t n = regerror(err, preg, errbuf, sizeof(errbuf));
		lua_pushlstring(L, errbuf, n);
		return lua_error(L);
	}
	luaL_setmetatable(L, MT_REGEX);
	return 1;
}

/* regex.find(reg, s) */
static int regex_find_(lua_State *restrict L)
{
	regex_t *preg = luaL_checkudata(L, 1, MT_REGEX);
	const char *s = luaL_checkstring(L, 2);
	regmatch_t match;
	const int err = regexec(preg, s, 1, &match, 0);
	if (err == REG_NOMATCH) {
		lua_pushnil(L);
		return 1;
	}
	if (err != 0) {
		char errbuf[256];
		const size_t n = regerror(err, preg, errbuf, sizeof(errbuf));
		lua_pushlstring(L, errbuf, n);
		return lua_error(L);
	}
	lua_pushinteger(L, match.rm_so + 1);
	lua_pushinteger(L, match.rm_eo);
	return 2;
}

/* regex.match(reg, s) */
static int regex_match_(lua_State *restrict L)
{
	regex_t *preg = luaL_checkudata(L, 1, MT_REGEX);
	const char *s = luaL_checkstring(L, 2);
	regmatch_t match;
	const int err = regexec(preg, s, 1, &match, 0);
	if (err == REG_NOMATCH) {
		lua_pushnil(L);
		return 1;
	}
	if (err != 0) {
		char errbuf[256];
		const size_t n = regerror(err, preg, errbuf, sizeof(errbuf));
		lua_pushlstring(L, errbuf, n);
		return lua_error(L);
	}
	lua_pushlstring(L, s + match.rm_so, match.rm_eo - match.rm_so);
	return 1;
}

int luaopen_regex(lua_State *restrict L)
{
	const luaL_Reg regexlib[] = {
		{ "compile", regex_compile_ },
		{ "find", regex_find_ },
		{ "match", regex_match_ },
		{ NULL, NULL },
	};
	luaL_newlib(L, regexlib);
	if (luaL_newmetatable(L, MT_REGEX)) {
		lua_pushvalue(L, -2);
		lua_setfield(L, -2, "__index");
		lua_pushcfunction(L, regex_gc_);
		lua_setfield(L, -2, "__gc");
	}
	lua_pop(L, 1);
	return 1;
}
