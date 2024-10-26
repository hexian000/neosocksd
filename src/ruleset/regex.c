/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "regex.h"

#include "lauxlib.h"
#include "lua.h"

#include <regex.h>

#include <stddef.h>

#define MT_REGEX "regex"

static int regex_gc(lua_State *restrict L)
{
	regex_t *preg = lua_touserdata(L, 1);
	regfree(preg);
	return 0;
}

static size_t cstrpos(lua_Integer pos, size_t len)
{
	if (pos > 0) {
		return (size_t)pos - 1;
	}
	if (pos == 0) {
		return 0;
	}
	if ((size_t)(-pos) > len) {
		return 0;
	}
	return len + (size_t)pos;
}

/* regex.compile(pattern) */
static int regex_compile(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TSTRING);
	const char *pattern = lua_tostring(L, 1);
	regex_t *preg = lua_newuserdata(L, sizeof(regex_t));
	const int err = regcomp(preg, pattern, REG_EXTENDED | REG_NEWLINE);
	if (err != 0) {
		char errbuf[256];
		const size_t n = regerror(err, preg, errbuf, sizeof(errbuf));
		lua_pushlstring(L, errbuf, n);
		return lua_error(L);
	}
	luaL_setmetatable(L, MT_REGEX);
	return 1;
}

/* regex.find(reg, s [, init]) */
static int regex_find(lua_State *restrict L)
{
	regex_t *preg = luaL_checkudata(L, 1, MT_REGEX);
	size_t len;
	const char *s = luaL_checklstring(L, 2, &len);
	const size_t init = cstrpos(luaL_optinteger(L, 3, 0), len);
	s += init;
	regmatch_t match;
	const int err = regexec(preg, s, 1, &match, 0);
	if (err == REG_NOMATCH) {
		return 0;
	}
	if (err != 0) {
		char errbuf[256];
		const size_t n = regerror(err, preg, errbuf, sizeof(errbuf));
		lua_pushlstring(L, errbuf, n);
		return lua_error(L);
	}
	lua_pushinteger(L, init + match.rm_so + 1);
	lua_pushinteger(L, init + match.rm_eo);
	return 2;
}

static int push_matches(
	lua_State *restrict L, const char *s,
	const regmatch_t *restrict matches, const size_t nmatch)
{
	luaL_checkstack(L, nmatch, "too many subexpressions");
	for (size_t i = 0; i < nmatch; i++) {
		const char *match = s + matches[i].rm_so;
		const size_t len = matches[i].rm_eo - matches[i].rm_so;
		lua_pushlstring(L, match, len);
	}
	return nmatch;
}

/* regex.match(reg, s [, init]) */
static int regex_match(lua_State *restrict L)
{
	const regex_t *restrict preg = luaL_checkudata(L, 1, MT_REGEX);
	size_t len;
	const char *s = luaL_checklstring(L, 2, &len);
	const size_t init = cstrpos(luaL_optinteger(L, 3, 0), len);
	s += init;
	const size_t nmatch = preg->re_nsub + 1;
	regmatch_t matches[nmatch];
	const int err = regexec(preg, s, nmatch, matches, 0);
	if (err == REG_NOMATCH) {
		return 0;
	}
	if (err != 0) {
		char errbuf[256];
		const size_t n = regerror(err, preg, errbuf, sizeof(errbuf));
		lua_pushlstring(L, errbuf, n);
		return lua_error(L);
	}
	return push_matches(L, s, matches, nmatch);
}

static int gmatch_aux_(lua_State *restrict L)
{
	const regex_t *restrict preg = lua_touserdata(L, lua_upvalueindex(1));
	size_t len;
	const char *s = lua_tolstring(L, lua_upvalueindex(2), &len);
	const size_t init = cstrpos(lua_tointeger(L, lua_upvalueindex(3)), len);
	s += init;
	const size_t nmatch = preg->re_nsub + 1;
	regmatch_t matches[nmatch];
	const int err = regexec(preg, s, nmatch, matches, 0);
	if (err == REG_NOMATCH) {
		return 0;
	}
	if (err != 0) {
		char errbuf[256];
		const size_t n = regerror(err, preg, errbuf, sizeof(errbuf));
		lua_pushlstring(L, errbuf, n);
		return lua_error(L);
	}
	lua_pushinteger(L, init + matches[0].rm_eo + 1);
	lua_copy(L, -1, lua_upvalueindex(3));
	return push_matches(L, s, matches, nmatch);
}

/* regex.gmatch(reg, s [, init]) */
static int regex_gmatch(lua_State *restrict L)
{
	(void)luaL_checkudata(L, 1, MT_REGEX);
	(void)luaL_checkstring(L, 2);
	const lua_Integer init = luaL_optinteger(L, 3, 0);
	lua_settop(L, 2);
	lua_pushinteger(L, init);
	lua_pushcclosure(L, gmatch_aux_, 3);
	return 1;
}

int luaopen_regex(lua_State *restrict L)
{
	const luaL_Reg regexlib[] = {
		{ "compile", regex_compile },
		{ "find", regex_find },
		{ "match", regex_match },
		{ "gmatch", regex_gmatch },
		{ NULL, NULL },
	};
	luaL_newlib(L, regexlib);
	if (luaL_newmetatable(L, MT_REGEX)) {
		lua_pushliteral(L, "regex");
		lua_setfield(L, -2, "__name");
		lua_pushvalue(L, -2);
		lua_setfield(L, -2, "__index");
		lua_pushcfunction(L, regex_gc);
		lua_setfield(L, -2, "__gc");
	}
	lua_pop(L, 1);
	return 1;
}
