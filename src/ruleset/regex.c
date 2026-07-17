/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/regex.h"

#include <lauxlib.h>
#include <lua.h>

#include <limits.h>
#include <regex.h>
#include <stddef.h>
#include <string.h>

#define MT_REGEX "regex"

static int
regex_error(lua_State *restrict L, int err, const regex_t *restrict preg)
{
	char errbuf[256];
	size_t n = regerror(err, preg, errbuf, sizeof(errbuf));
	if (n > 0) {
		/* regerror returns the size needed, not the bytes written; clamp
		 * to the buffer so a truncated (>256B) message never reads past
		 * errbuf. The stored message is NUL-terminated within the buffer. */
		if (n > sizeof(errbuf)) {
			n = sizeof(errbuf);
		}
		lua_pushlstring(L, errbuf, n - 1);
	} else {
		lua_pushliteral(L, "unknown regex error");
	}
	return lua_error(L);
}

/* Lua strings are 8-bit-clean, but POSIX regcomp/regexec take a bare
 * NUL-terminated `const char *` with no length-aware form, so an embedded
 * NUL silently truncates the pattern/subject instead of erroring. Raise
 * instead of matching a truncated view the caller doesn't know was cut. */
static int
check_no_nul(lua_State *restrict L, const char *restrict s, const size_t len)
{
	if (memchr(s, '\0', len) == NULL) {
		return 0;
	}
	return luaL_error(L, "string contains an embedded NUL byte");
}

/* regex.compile(pattern [, cflags]) */
static int regex_compile(lua_State *restrict L)
{
	size_t len;
	const char *restrict const pattern = luaL_checklstring(L, 1, &len);
	check_no_nul(L, pattern, len);
	int cflags = (int)luaL_optinteger(L, 2, REG_EXTENDED | REG_NEWLINE);
	/* find/match/gmatch all report match offsets, which REG_NOSUB makes
	 * regexec() leave unset in pmatch; strip it so those offsets are never
	 * read from an uninitialized regmatch_t */
	cflags &= ~REG_NOSUB;
	regex_t *restrict const preg = lua_newuserdata(L, sizeof(regex_t));
	const int err = regcomp(preg, pattern, cflags);
	if (err != 0) {
		/* POSIX.1-2008: after a failed regcomp() the content of preg is
		 * undefined, so it must not be regfree()d (a double-free / stale
		 * deref on a strict libc; glibc happens to NULL its internals).
		 * regerror() formats the errcode -- the conforming way to report
		 * the failure -- and preg is abandoned (the __gc finalizer is
		 * never attached on this path). */
		return regex_error(L, err, preg);
	}
	luaL_setmetatable(L, MT_REGEX);
	return 1;
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
			/* Underflow: clamp to start. */
			return 0;
		}
		return (size_t)adjusted;
	}
	if (pos == 0) {
		/* Zero means the start position. */
		return 0;
	}
	/* pos > 0: positive index (1-based). Compare in lua_Integer so a huge
	 * pos cannot truncate when narrowed to a (possibly 32-bit) size_t. */
	if (pos > (lua_Integer)len) {
		return len;
	}
	return (size_t)(pos - 1);
}

/* regex.find(reg, s [, init]) */
static int regex_find(lua_State *restrict L)
{
	const regex_t *restrict const preg = luaL_checkudata(L, 1, MT_REGEX);
	size_t len;
	const char *restrict s = luaL_checklstring(L, 2, &len);
	const size_t init = cstrpos(luaL_optinteger(L, 3, 0), len);
	s += init;
	len -= init;
	check_no_nul(L, s, len);
	regmatch_t match;
	const int err = regexec(preg, s, 1, &match, 0);
	if (err == REG_NOMATCH) {
		return 0;
	}
	if (err != 0) {
		return regex_error(L, err, preg);
	}
	lua_pushinteger(L, (lua_Integer)init + match.rm_so + 1);
	lua_pushinteger(L, (lua_Integer)init + match.rm_eo);
	return 2;
}

static size_t check_matches(lua_State *restrict L, const regex_t *restrict preg)
{
	const size_t nmatch = preg->re_nsub + 1;
	if (nmatch >= INT_MAX) {
		lua_pushliteral(L, "too many subexpressions");
		return (size_t)lua_error(L);
	}
	luaL_checkstack(L, (int)nmatch + 1, "too many subexpressions");
	return nmatch;
}

static int
push_matches(lua_State *restrict L, const char *restrict s, size_t nmatch)
{
	const regmatch_t *restrict const matches = lua_topointer(L, -1);
	for (size_t i = 0; i < nmatch; i++) {
		/* POSIX: rm_so is -1 when subexpression did not participate */
		if (matches[i].rm_so < 0) {
			lua_pushnil(L);
			continue;
		}
		const char *const match = s + matches[i].rm_so;
		const size_t len =
			(size_t)(matches[i].rm_eo - matches[i].rm_so);
		lua_pushlstring(L, match, len);
	}
	return (int)nmatch;
}

/* regex.match(reg, s [, init]) */
static int regex_match(lua_State *restrict L)
{
	const regex_t *restrict const preg = luaL_checkudata(L, 1, MT_REGEX);
	size_t len;
	const char *restrict s = luaL_checklstring(L, 2, &len);
	const size_t init = cstrpos(luaL_optinteger(L, 3, 0), len);
	s += init;
	len -= init;
	check_no_nul(L, s, len);
	const size_t nmatch = check_matches(L, preg);
	regmatch_t *restrict const matches =
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

/* Sentinel stored in the "next position" upvalue once the iterator has
 * exhausted the subject string. Both the initial position (normalized in
 * regex_gmatch to cstrpos()+1) and every subsequent one gmatch_aux() stores
 * lie in [1, len+1], so this large-negative value can never collide with a
 * live iteration position. */
#define GMATCH_DONE LUA_MININTEGER

static int gmatch_aux(lua_State *restrict L)
{
	const lua_Integer pos = lua_tointeger(L, lua_upvalueindex(3));
	if (pos == GMATCH_DONE) {
		return 0;
	}
	const regex_t *restrict const preg =
		lua_touserdata(L, lua_upvalueindex(1));
	size_t len;
	const char *restrict s = lua_tolstring(L, lua_upvalueindex(2), &len);
	const size_t init = cstrpos(pos, len);
	s += init;
	/* the subject was NUL-checked once in regex_gmatch */
	const size_t nmatch = check_matches(L, preg);
	regmatch_t *restrict const matches =
		lua_newuserdata(L, nmatch * sizeof(regmatch_t));
	const int err = regexec(preg, s, nmatch, matches, 0);
	if (err == REG_NOMATCH) {
		return 0;
	}
	if (err != 0) {
		return regex_error(L, err, preg);
	}
	size_t advance = (size_t)matches[0].rm_eo;
	if (matches[0].rm_so == matches[0].rm_eo) {
		/* Empty match: advance by at least one byte so the next call
		 * doesn't re-match the same zero-width position forever, same as
		 * Lua's own string.gmatch. */
		advance++;
	}
	const size_t next = init + advance;
	if (next > len) {
		/* No further positions worth trying; mark the iterator exhausted
		 * instead of storing a position cstrpos() would silently re-clamp
		 * to `len` next call, which would repeat this same trailing
		 * empty match forever. */
		lua_pushinteger(L, GMATCH_DONE);
	} else {
		lua_pushinteger(L, (lua_Integer)next + 1);
	}
	lua_replace(L, lua_upvalueindex(3));
	return push_matches(L, s, nmatch);
}

/* regex.gmatch(reg, s [, init]) */
static int regex_gmatch(lua_State *restrict L)
{
	(void)luaL_checkudata(L, 1, MT_REGEX);
	size_t len;
	const char *restrict const s = luaL_checklstring(L, 2, &len);
	const size_t init = cstrpos(luaL_optinteger(L, 3, 0), len);
	/* Scan for an embedded NUL once here, not on every gmatch_aux()
	 * iteration (the subject never changes), keeping iteration O(n). Scan
	 * only the active suffix [init, len) -- exactly what find()/match() do --
	 * since a NUL before the start offset is never seen by regexec(). */
	check_no_nul(L, s + init, len - init);
	lua_settop(L, 2);
	/* Store a normalized 1-based start position; cstrpos()+1 maps it into
	 * [1, len+1], which can never be the GMATCH_DONE sentinel, so a
	 * huge-negative init (e.g. math.mininteger) clamps to the string start
	 * instead of colliding with it. */
	lua_pushinteger(L, (lua_Integer)init + 1);
	lua_pushcclosure(L, gmatch_aux, 3);
	return 1;
}

static int regex_gc(lua_State *restrict L)
{
	regex_t *restrict const preg = lua_touserdata(L, 1);
	regfree(preg);
	return 0;
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
