/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * regex_test - white-box unit tests for ruleset/regex.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   ruleset/regex.c  module under test
 * Leaf libraries: Lua. regex.c has no stateful collaborator to mock; the mock
 * section only holds shared Lua test fixtures.
 */

#include "ruleset/regex.h"

#include "utils/testing.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <stdbool.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * mock - shared Lua test fixtures (regex.c has no collaborator to mock).
 * ---------------------------------------------------------------------- */

static lua_State *new_lua(void)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	luaL_openlibs(L);
	(void)luaopen_regex(L);
	lua_setglobal(L, "regex");
	return L;
}

static bool run_chunk(lua_State *restrict L, const char *restrict chunk)
{
	const int status_load = luaL_loadstring(L, chunk);
	if (status_load != LUA_OK) {
		return false;
	}
	const int status_call = lua_pcall(L, 0, LUA_MULTRET, 0);
	return status_call == LUA_OK;
}

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - pattern compile/match cases.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(regex_module_opens)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_getglobal(L, "regex");
	T_EXPECT(lua_istable(L, -1));
	lua_getfield(L, -1, "compile");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -2, "find");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -3, "match");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -4, "gmatch");
	T_EXPECT(lua_isfunction(L, -1));

	lua_close(L);
}

T_DECLARE_CASE(regex_compile_basic)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('hello') return type(r)"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT_STREQ(lua_tostring(L, -1), "userdata");

	lua_close(L);
}

T_DECLARE_CASE(regex_compile_invalid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	const int status_load = luaL_loadstring(
		L,
		"local ok, err = pcall(regex.compile, '[') return ok, type(err)");
	T_EXPECT_EQ(status_load, LUA_OK);
	const int status_call = lua_pcall(L, 0, LUA_MULTRET, 0);
	T_EXPECT_EQ(status_call, LUA_OK);
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

/*
 * Regression: an embedded NUL in the pattern must be rejected, not silently
 * truncate regcomp()'s view of the pattern. Pre-fix, regcomp() only ever
 * saw "a" (the bytes up to the NUL) via the NUL-terminated C string, so
 * this compiled successfully instead of erroring.
 */
T_DECLARE_CASE(regex_compile_rejects_embedded_nul)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	const int status_load = luaL_loadstring(
		L, "local pattern = 'a' .. string.char(0) .. 'b' "
		   "local ok, err = pcall(regex.compile, pattern) "
		   "return ok, type(err)");
	T_EXPECT_EQ(status_load, LUA_OK);
	const int status_call = lua_pcall(L, 0, LUA_MULTRET, 0);
	T_EXPECT_EQ(status_call, LUA_OK);
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

/*
 * Regression: compiling many invalid patterns must not leak the partial
 * internal state some libc regex implementations allocate before rejecting
 * a pattern (only observable under a leak-detecting build, e.g. `m.sh d`).
 */
T_DECLARE_CASE(regex_compile_invalid_repeated_no_leak)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "for _ = 1, 100 do "
		   "  local ok = pcall(regex.compile, '[') "
		   "  assert(not ok) "
		   "end "
		   "return true"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(regex_find_match)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('ab+') "
		   "return regex.find(r, 'xxabbbz')"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), 3);
	T_EXPECT_EQ(lua_tointeger(L, 2), 6);

	lua_close(L);
}

T_DECLARE_CASE(regex_find_nomatch)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L,
		"local r = regex.compile('ab+') return regex.find(r, 'xyz')"));
	T_EXPECT_EQ(lua_gettop(L), 0);

	lua_close(L);
}

T_DECLARE_CASE(regex_find_with_init)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('ab+') "
		   "local s1, e1 = regex.find(r, 'ab abbb', 1) "
		   "local s2, e2 = regex.find(r, 'ab abbb', 4) "
		   "local s3, e3 = regex.find(r, 'xxabyyabz', -3) "
		   "return s1, e1, s2, e2, s3, e3"));
	T_EXPECT_EQ(lua_gettop(L), 6);
	T_EXPECT_EQ(lua_tointeger(L, 1), 1);
	T_EXPECT_EQ(lua_tointeger(L, 2), 2);
	T_EXPECT_EQ(lua_tointeger(L, 3), 4);
	T_EXPECT_EQ(lua_tointeger(L, 4), 7);
	T_EXPECT_EQ(lua_tointeger(L, 5), 7);
	T_EXPECT_EQ(lua_tointeger(L, 6), 8);

	lua_close(L);
}

T_DECLARE_CASE(regex_find_init_out_of_range)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* init past the end clamps to end-of-string: no match, no results */
	T_EXPECT(run_chunk(
		L, "local r = regex.compile('ab+') "
		   "return regex.find(r, 'ab abbb', 100)"));
	T_EXPECT_EQ(lua_gettop(L), 0);

	/* init 0 clamps to the start: matches from position 1 */
	T_EXPECT(run_chunk(
		L, "local r = regex.compile('ab+') "
		   "return (regex.find(r, 'ab abbb', 0))"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT_EQ(lua_tointeger(L, 1), 1);

	lua_close(L);
}

/*
 * Regression: an embedded NUL in the subject must be rejected, not silently
 * truncate regexec()'s view of the subject. Pre-fix, regexec() only ever
 * saw "a" (the bytes up to the NUL), so an anchored '^a$' pattern matched a
 * 3-byte subject "a\0b" as if it were just "a".
 */
T_DECLARE_CASE(regex_find_rejects_embedded_nul_subject)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	const int status_load = luaL_loadstring(
		L, "local r = regex.compile('^a$') "
		   "local subject = 'a' .. string.char(0) .. 'b' "
		   "local ok, err = pcall(regex.find, r, subject) "
		   "return ok, type(err)");
	T_EXPECT_EQ(status_load, LUA_OK);
	const int status_call = lua_pcall(L, 0, LUA_MULTRET, 0);
	T_EXPECT_EQ(status_call, LUA_OK);
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

T_DECLARE_CASE(regex_match_rejects_embedded_nul_subject)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	const int status_load = luaL_loadstring(
		L, "local r = regex.compile('^a$') "
		   "local subject = 'a' .. string.char(0) .. 'b' "
		   "local ok, err = pcall(regex.match, r, subject) "
		   "return ok, type(err)");
	T_EXPECT_EQ(status_load, LUA_OK);
	const int status_call = lua_pcall(L, 0, LUA_MULTRET, 0);
	T_EXPECT_EQ(status_call, LUA_OK);
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

T_DECLARE_CASE(regex_gmatch_rejects_embedded_nul_subject)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* the subject is NUL-checked up front by regex.gmatch (once, not per
	 * iteration), so the rejection surfaces at iterator creation */
	const int status_load = luaL_loadstring(
		L, "local r = regex.compile('.') "
		   "local subject = 'a' .. string.char(0) .. 'b' "
		   "local ok, err = pcall(regex.gmatch, r, subject) "
		   "return ok, type(err)");
	T_EXPECT_EQ(status_load, LUA_OK);
	const int status_call = lua_pcall(L, 0, LUA_MULTRET, 0);
	T_EXPECT_EQ(status_call, LUA_OK);
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

/* Regression: gmatch's exhausted-iterator sentinel (LUA_MININTEGER) must not
 * collide with a huge-negative init; the init is normalized to the string
 * start, so iteration proceeds instead of returning nothing. */
T_DECLARE_CASE(regex_gmatch_mininteger_init_iterates)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('a') "
		   "local n = 0 "
		   "for _ in regex.gmatch(r, 'aaa', math.mininteger) do "
		   "  n = n + 1 "
		   "end "
		   "return n == 3"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

/* Regression: gmatch's up-front embedded-NUL scan must cover only the active
 * suffix [init, len), matching find()/match(); a NUL *before* the init start
 * offset is never seen by regexec() and must not abort iteration. */
T_DECLARE_CASE(regex_gmatch_init_past_leading_nul_iterates)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('a') "
		   "local subject = string.char(0) .. 'aa' "
		   "local n = 0 "
		   "for _ in regex.gmatch(r, subject, 2) do "
		   "  n = n + 1 "
		   "end "
		   "return n == 2"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(regex_match_captures)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('(foo)(bar)') "
		   "return regex.match(r, 'xxfoobarzz')"));
	T_EXPECT_EQ(lua_gettop(L), 3);
	T_EXPECT_STREQ(lua_tostring(L, 1), "foobar");
	T_EXPECT_STREQ(lua_tostring(L, 2), "foo");
	T_EXPECT_STREQ(lua_tostring(L, 3), "bar");

	lua_close(L);
}

/*
 * An alternation leaves the branch that did not match as a non-participating
 * subexpression (rm_so == -1), which push_matches reports as nil. That is a
 * Lua-visible contract -- it also fixes the returned-value count -- and
 * regex_match_captures cannot reach it, since both of its groups always
 * participate.
 */
T_DECLARE_CASE(regex_match_absent_capture_is_nil)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('(a)|(b)') "
		   "return regex.match(r, 'a')"));
	T_EXPECT_EQ(lua_gettop(L), 3);
	T_EXPECT_STREQ(lua_tostring(L, 1), "a");
	T_EXPECT_STREQ(lua_tostring(L, 2), "a");
	T_EXPECT(lua_isnil(L, 3));
	lua_settop(L, 0);

	/* the symmetric branch: now it is group 1 that is absent */
	T_EXPECT(run_chunk(
		L, "local r = regex.compile('(a)|(b)') "
		   "return regex.match(r, 'b')"));
	T_EXPECT_EQ(lua_gettop(L), 3);
	T_EXPECT_STREQ(lua_tostring(L, 1), "b");
	T_EXPECT(lua_isnil(L, 2));
	T_EXPECT_STREQ(lua_tostring(L, 3), "b");

	lua_close(L);
}

T_DECLARE_CASE(regex_match_nomatch)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L,
		"local r = regex.compile('foo') return regex.match(r, 'bar')"));
	T_EXPECT_EQ(lua_gettop(L), 0);

	lua_close(L);
}

/* regex.match honors the optional init (start) argument, like regex.find. */
T_DECLARE_CASE(regex_match_with_init)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('a+') "
		   "return regex.match(r, 'aaXaa', 3)"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT_STREQ(lua_tostring(L, 1), "aa");

	lua_close(L);
}

/* regex.ICASE makes matching case-insensitive. */
T_DECLARE_CASE(regex_icase_matches_mixed_case)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('hello', regex.ICASE) "
		   "return regex.match(r, 'oh HELLO there')"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT_STREQ(lua_tostring(L, 1), "HELLO");

	lua_close(L);
}

/* Regression: compiling with regex.NOSUB (which makes regexec() leave pmatch
 * unfilled) must not make find/match read an uninitialized regmatch_t. The
 * flag is stripped, so offsets and captures still work. */
T_DECLARE_CASE(regex_nosub_is_neutralized)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L,
		"local r = regex.compile('a(b+)c', regex.EXTENDED | regex.NOSUB) "
		"local s, e = regex.find(r, 'xxabbbcyy') "
		"local whole, cap = regex.match(r, 'xxabbbcyy') "
		"return s, e, whole, cap"));
	T_EXPECT_EQ(lua_gettop(L), 4);
	T_EXPECT_EQ(lua_tointeger(L, 1), 3);
	T_EXPECT_EQ(lua_tointeger(L, 2), 7);
	T_EXPECT_STREQ(lua_tostring(L, 3), "abbbc");
	T_EXPECT_STREQ(lua_tostring(L, 4), "bbb");

	lua_close(L);
}

T_DECLARE_CASE(regex_gmatch_iterator)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('[0-9]+') "
		   "local it = regex.gmatch(r, '1 22 333') "
		   "local a, b, c, d = it(), it(), it(), it() "
		   "return a, b, c, d"));
	T_EXPECT_EQ(lua_gettop(L), 4);
	T_EXPECT_STREQ(lua_tostring(L, 1), "1");
	T_EXPECT_STREQ(lua_tostring(L, 2), "22");
	T_EXPECT_STREQ(lua_tostring(L, 3), "333");
	T_EXPECT(lua_isnil(L, 4));

	lua_close(L);
}

/*
 * Regression: a pattern that can match empty (here, always-empty) must not
 * loop forever -- Lua's own string.gmatch advances by at least one byte
 * after a zero-width match, and this port must too. The loop bound (20) is
 * a safety margin, not a reliance on hanging: even against the pre-fix
 * code this test terminates promptly (it just never observes `done`).
 */
T_DECLARE_CASE(regex_gmatch_empty_match_terminates)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('x*') "
		   "local it = regex.gmatch(r, 'abc') "
		   "local count, done = 0, false "
		   "for _ = 1, 20 do "
		   "  local m = it() "
		   "  if m == nil then done = true break end "
		   "  count = count + 1 "
		   "end "
		   "return done, count"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) != 0);
	/* "abc" has 4 positions (0,1,2,3) where "x*" matches empty. */
	T_EXPECT_EQ(lua_tointeger(L, 2), 4);

	lua_close(L);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(regex_module_opens),
	T_CASE(regex_compile_basic),
	T_CASE(regex_compile_invalid),
	T_CASE(regex_compile_rejects_embedded_nul),
	T_CASE(regex_compile_invalid_repeated_no_leak),
	T_CASE(regex_find_match),
	T_CASE(regex_find_nomatch),
	T_CASE(regex_find_with_init),
	T_CASE(regex_find_init_out_of_range),
	T_CASE(regex_find_rejects_embedded_nul_subject),
	T_CASE(regex_match_rejects_embedded_nul_subject),
	T_CASE(regex_gmatch_rejects_embedded_nul_subject),
	T_CASE(regex_gmatch_mininteger_init_iterates),
	T_CASE(regex_gmatch_init_past_leading_nul_iterates),
	T_CASE(regex_match_captures),
	T_CASE(regex_match_absent_capture_is_nil),
	T_CASE(regex_match_nomatch),
	T_CASE(regex_match_with_init),
	T_CASE(regex_icase_matches_mixed_case),
	T_CASE(regex_nosub_is_neutralized),
	T_CASE(regex_gmatch_iterator),
	T_CASE(regex_gmatch_empty_match_terminates),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
