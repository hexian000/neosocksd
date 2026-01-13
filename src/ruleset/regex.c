/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "regex.h"

#include "lauxlib.h"
#include "lua.h"

#include <regex.h>

#include <limits.h>
#include <stddef.h>

#define MT_REGEX "regex"

static int regex_gc(lua_State *restrict L)
{
	regex_t *preg = lua_touserdata(L, 1);
	regfree(preg);
	return 0;
}

/* Convert Lua string index (1-based, negative for reverse) to C index (0-based).
 * Lua:  1 = first char, -1 = last char, 0 = clamp to start
 * Returns a valid C index in range [0, len]. */
static size_t cstrpos(const lua_Integer pos, const size_t len)
{
	if (len == 0) {
		return 0;
	}
	if (pos < 0) {
		/* negative index: -1 = last, -2 = second last, etc. */
		const lua_Integer adjusted = (lua_Integer)len + pos;
		if (adjusted < 0) {
			return 0; /* underflow: clamp to start */
		}
		return (size_t)adjusted;
	}
	if (pos == 0) {
		return 0; /* 0 = start */
	}
	/* pos > 0: positive index (1-based) */
	if ((lua_Integer)len < pos) {
		return len; /* overflow: clamp to end */
	}
	return (size_t)(pos - 1);
}

static int
regex_error(lua_State *restrict L, int err, const regex_t *restrict preg)
{
	char errbuf[256];
	const size_t n = regerror(err, preg, errbuf, sizeof(errbuf));
	if (n > 0) {
		lua_pushlstring(L, errbuf, n - 1);
	} else {
		lua_pushliteral(L, "unknown regex error");
	}
	return lua_error(L);
}

/* regex.compile(pattern [, cflags]) */
static int regex_compile(lua_State *restrict L)
{
	const char *restrict pattern = luaL_checkstring(L, 1);
	const int cflags =
		(int)luaL_optinteger(L, 2, REG_EXTENDED | REG_NEWLINE);
	regex_t *restrict preg = lua_newuserdata(L, sizeof(regex_t));
	const int err = regcomp(preg, pattern, cflags);
	if (err != 0) {
		return regex_error(L, err, preg);
	}
	luaL_setmetatable(L, MT_REGEX);
	return 1;
}

/* regex.find(reg, s [, init]) */
static int regex_find(lua_State *restrict L)
{
	const regex_t *restrict preg = luaL_checkudata(L, 1, MT_REGEX);
	size_t len;
	const char *restrict s = luaL_checklstring(L, 2, &len);
	const size_t init = cstrpos(luaL_optinteger(L, 3, 0), len);
	s += init;
	regmatch_t match;
	const int err = regexec(preg, s, 1, &match, 0);
	if (err == REG_NOMATCH) {
		return 0;
	}
	if (err != 0) {
		return regex_error(L, err, preg);
	}
	lua_pushinteger(L, (lua_Integer)(init + (size_t)match.rm_so) + 1);
	lua_pushinteger(L, (lua_Integer)(init + (size_t)match.rm_eo));
	return 2;
}

static size_t check_matches(lua_State *restrict L, const regex_t *restrict preg)
{
	const size_t nmatch = preg->re_nsub + 1;
	if (nmatch >= INT_MAX) {
		lua_pushliteral(L, "too many subexpressions");
		return lua_error(L);
	}
	luaL_checkstack(L, (int)nmatch + 1, "too many subexpressions");
	return nmatch;
}

static int push_matches(lua_State *restrict L, const char *s, size_t nmatch)
{
	const regmatch_t *restrict matches = lua_topointer(L, -1);
	for (size_t i = 0; i < nmatch; i++) {
		/* POSIX: rm_so is -1 when subexpression did not participate */
		if (matches[i].rm_so < 0) {
			lua_pushnil(L);
			continue;
		}
		const char *match = s + matches[i].rm_so;
		const size_t len =
			(size_t)(matches[i].rm_eo - matches[i].rm_so);
		lua_pushlstring(L, match, len);
	}
	return (int)nmatch;
}

/* regex.match(reg, s [, init]) */
static int regex_match(lua_State *restrict L)
{
	const regex_t *restrict preg = luaL_checkudata(L, 1, MT_REGEX);
	size_t len;
	const char *restrict s = luaL_checklstring(L, 2, &len);
	const size_t init = cstrpos(luaL_optinteger(L, 3, 0), len);
	s += init;
	const size_t nmatch = check_matches(L, preg);
	regmatch_t *restrict matches =
		lua_newuserdata(L, nmatch * sizeof(regmatch_t));
	const int err = regexec(preg, s, nmatch, matches, 0);
	if (err == REG_NOMATCH) {
		return 0;
	}
	if (err != 0) {
		return regex_error(L, err, preg);
	}
	return push_matches(L, s, nmatch);
}

static int gmatch_aux(lua_State *restrict L)
{
	const regex_t *restrict preg = lua_touserdata(L, lua_upvalueindex(1));
	size_t len;
	const char *restrict s = lua_tolstring(L, lua_upvalueindex(2), &len);
	const size_t init = cstrpos(lua_tointeger(L, lua_upvalueindex(3)), len);
	s += init;
	const size_t nmatch = check_matches(L, preg);
	regmatch_t *restrict matches =
		lua_newuserdata(L, nmatch * sizeof(regmatch_t));
	const int err = regexec(preg, s, nmatch, matches, 0);
	if (err == REG_NOMATCH) {
		return 0;
	}
	if (err != 0) {
		return regex_error(L, err, preg);
	}
	lua_pushinteger(L, (lua_Integer)(init + (size_t)matches[0].rm_eo) + 1);
	lua_replace(L, lua_upvalueindex(3));
	return push_matches(L, s, nmatch);
}

/* regex.gmatch(reg, s [, init]) */
static int regex_gmatch(lua_State *restrict L)
{
	(void)luaL_checkudata(L, 1, MT_REGEX);
	(void)luaL_checkstring(L, 2);
	const lua_Integer init = luaL_optinteger(L, 3, 0);
	lua_settop(L, 2);
	lua_pushinteger(L, init);
	lua_pushcclosure(L, gmatch_aux, 3);
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
	lua_pushinteger(L, REG_EXTENDED);
	lua_setfield(L, -2, "EXTENDED");
	lua_pushinteger(L, REG_ICASE);
	lua_setfield(L, -2, "ICASE");
	lua_pushinteger(L, REG_NEWLINE);
	lua_setfield(L, -2, "NEWLINE");
	lua_pushinteger(L, REG_NOSUB);
	lua_setfield(L, -2, "NOSUB");

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
