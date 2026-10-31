/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * regex_test - white-box unit tests for ruleset/regex.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   ruleset/regex.c  module under test
 * Leaf libraries: Lua and libc regex. regexec is observed through a compiler
 * alias that delegates to libc unless an execution error is injected.
 */

#include "regex.h"

#include "utils/testing.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <regex.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * mock - regexec observations and shared Lua test fixtures.
 * ---------------------------------------------------------------------- */

static int g_regexec_error;
static bool g_track_regexec;
static size_t g_regexec_calls;
static size_t g_bounded_calls;
static bool g_bounds_ok;

int test_regexec(
	const regex_t *restrict preg, const char *restrict s, size_t nmatch,
	regmatch_t matches[restrict], int eflags)
{
	if (g_track_regexec) {
		g_regexec_calls++;
#if WITH_REG_STARTEND
		if (eflags & REG_STARTEND) {
			g_bounded_calls++;
			if (matches[0].rm_so != 0 || matches[0].rm_eo < 0 ||
			    (size_t)matches[0].rm_eo != strlen(s)) {
				g_bounds_ok = false;
			}
		}
#endif
	}
	if (g_regexec_error != 0) {
		return g_regexec_error;
	}
	return regexec(preg, s, nmatch, matches, eflags);
}

static unsigned lua_close_count;

static void close_lua(void *data)
{
	lua_close(data);
	lua_close_count++;
}

static lua_State *new_lua(struct testing_ctx *_t_)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	T_CLEANUP(close_lua, L);
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
	lua_State *restrict L = new_lua(_t_);
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
}

T_DECLARE_CASE(regex_compile_basic)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('hello') return type(r)"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT_STREQ(lua_tostring(L, -1), "userdata");
}

T_DECLARE_CASE(regex_compile_invalid)
{
	lua_State *restrict L = new_lua(_t_);
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
}

/*
 * Regression: an embedded NUL in the pattern must be rejected, not silently
 * truncate regcomp()'s view of the pattern. Pre-fix, regcomp() only ever
 * saw "a" (the bytes up to the NUL) via the NUL-terminated C string, so
 * this compiled successfully instead of erroring.
 */
T_DECLARE_CASE(regex_compile_rejects_embedded_nul)
{
	lua_State *restrict L = new_lua(_t_);
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
}

/*
 * Regression: compiling many invalid patterns must not leak the partial
 * internal state some libc regex implementations allocate before rejecting
 * a pattern (only observable under a leak-detecting build, e.g. `m.sh d`).
 */
T_DECLARE_CASE(regex_compile_invalid_repeated_no_leak)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "for _ = 1, 100 do "
		   "  local ok = pcall(regex.compile, '[') "
		   "  assert(not ok) "
		   "end "
		   "return true"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);
}

T_DECLARE_CASE(regex_find_match)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('ab+') "
		   "return regex.find(r, 'xxabbbz')"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), 3);
	T_EXPECT_EQ(lua_tointeger(L, 2), 6);
}

T_DECLARE_CASE(regex_find_nomatch)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L,
		"local r = regex.compile('ab+') return regex.find(r, 'xyz')"));
	T_EXPECT_EQ(lua_gettop(L), 0);
}

/* A failed execution must raise without consuming pattern/iterator state.
 * Disarm the seam and close Lua before asserting so a failed check cannot
 * leave fault injection active for another case. */
T_DECLARE_SUBCASE(
	regex_exec_error_case, const char *setup, const char *invoke,
	const char *recover)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	const bool setup_ok = run_chunk(L, setup);
	lua_settop(L, 0);
	g_regexec_calls = 0;
	g_track_regexec = true;
	g_regexec_error = REG_ESPACE;
	const bool invoke_ok = run_chunk(L, invoke);
	g_regexec_error = 0;
	g_track_regexec = false;
	const bool caught = lua_gettop(L) == 2 && !lua_toboolean(L, 1) &&
			    lua_type(L, 2) == LUA_TSTRING &&
			    lua_rawlen(L, 2) != 0;
	lua_settop(L, 0);
	const bool recover_ok = run_chunk(L, recover);
	const bool reused = lua_toboolean(L, -1) != 0;

	T_EXPECT(setup_ok);
	T_EXPECT(invoke_ok);
	T_EXPECT(caught);
	T_EXPECT_EQ(g_regexec_calls, (size_t)1);
	T_EXPECT(recover_ok);
	T_EXPECT(reused);
}

T_DECLARE_CASE(regex_find_reports_runtime_error)
{
	T_CALL_SUBCASE(
		regex_exec_error_case, "r = regex.compile('(ab+)')",
		"return pcall(regex.find, r, 'xxabbb yyabb')",
		"local s, e = regex.find(r, 'xxabbb yyabb') "
		"return s == 3 and e == 6");
}

T_DECLARE_CASE(regex_match_reports_runtime_error)
{
	T_CALL_SUBCASE(
		regex_exec_error_case, "r = regex.compile('(a)(b+)')",
		"return pcall(regex.match, r, 'xxabbb yyabb')",
		"collectgarbage('collect') "
		"local whole, a, b = regex.match(r, 'xxabbb yyabb') "
		"return whole == 'abbb' and a == 'a' and b == 'bbb'");
}

T_DECLARE_CASE(regex_match_many_captures_reports_runtime_error)
{
	T_CALL_SUBCASE(
		regex_exec_error_case,
		"r = regex.compile(string.rep('(a)', 16))",
		"return pcall(regex.match, r, string.rep('a', 16))",
		"collectgarbage('collect') "
		"local values = table.pack(regex.match(r, string.rep('a', 16))) "
		"return values.n == 17 and values[17] == 'a'");
}

T_DECLARE_CASE(regex_gmatch_reports_runtime_error)
{
	T_CALL_SUBCASE(
		regex_exec_error_case,
		"r = regex.compile('(ab+)') "
		"it = regex.gmatch(r, 'ab abb abbb') "
		"assert(it() == 'ab')",
		"return pcall(it)",
		"local a, ac = it() local b, bc = it() "
		"return a == 'abb' and ac == 'abb' "
		"and b == 'abbb' and bc == 'abbb' "
		"and it() == nil and it() == nil");
}

T_DECLARE_CASE(regex_find_with_init)
{
	lua_State *restrict L = new_lua(_t_);
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
}

T_DECLARE_CASE(regex_find_init_out_of_range)
{
	lua_State *restrict L = new_lua(_t_);
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
}

/*
 * Regression: an embedded NUL in the subject must be rejected, not silently
 * truncate regexec()'s view of the subject. Pre-fix, regexec() only ever
 * saw "a" (the bytes up to the NUL), so an anchored '^a$' pattern matched a
 * 3-byte subject "a\0b" as if it were just "a".
 */
T_DECLARE_CASE(regex_find_rejects_embedded_nul_subject)
{
	lua_State *restrict L = new_lua(_t_);
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
}

T_DECLARE_CASE(regex_match_rejects_embedded_nul_subject)
{
	lua_State *restrict L = new_lua(_t_);
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
}

T_DECLARE_CASE(regex_gmatch_rejects_embedded_nul_subject)
{
	lua_State *restrict L = new_lua(_t_);
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
}

/* Regression: gmatch's exhausted-iterator sentinel (LUA_MININTEGER) must not
 * collide with a huge-negative init; the init is normalized to the string
 * start, so iteration proceeds instead of returning nothing. */
T_DECLARE_CASE(regex_gmatch_mininteger_init_iterates)
{
	lua_State *restrict L = new_lua(_t_);
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
}

/* Regression: gmatch's up-front embedded-NUL scan must cover only the active
 * suffix [init, len), matching find()/match(); a NUL *before* the init start
 * offset is never seen by regexec() and must not abort iteration. */
T_DECLARE_CASE(regex_gmatch_init_past_leading_nul_iterates)
{
	lua_State *restrict L = new_lua(_t_);
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
}

T_DECLARE_CASE(regex_match_captures)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('(foo)(bar)') "
		   "return regex.match(r, 'xxfoobarzz')"));
	T_EXPECT_EQ(lua_gettop(L), 3);
	T_EXPECT_STREQ(lua_tostring(L, 1), "foobar");
	T_EXPECT_STREQ(lua_tostring(L, 2), "foo");
	T_EXPECT_STREQ(lua_tostring(L, 3), "bar");
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
	lua_State *restrict L = new_lua(_t_);
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
}

T_DECLARE_CASE(regex_match_nomatch)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L,
		"local r = regex.compile('foo') return regex.match(r, 'bar')"));
	T_EXPECT_EQ(lua_gettop(L), 0);
}

/* Measure identical protected calls from C after warming their VM stack and
 * interned results. A Lua loop can grow its own stack independently of regex
 * scratch storage, even when an earlier call used the same pattern. */
T_DECLARE_SUBCASE(regex_match_scratch_case, int captures)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);
	lua_pushinteger(L, captures);
	lua_setglobal(L, "captures");
	T_CHECK(run_chunk(
		L,
		"local r = regex.compile(string.rep('(a)', captures) .. 'a') "
		"local subject = string.rep('a', captures + 1) "
		"return function() "
		"  assert(regex.match(r, subject) == subject) "
		"  assert(regex.match(r, 'z') == nil) "
		"end"));
	lua_pushvalue(L, 1);
	T_CHECK(lua_pcall(L, 0, 0, 0) == LUA_OK);

	lua_gc(L, LUA_GCSTOP, 0);
	const size_t before = (size_t)lua_gc(L, LUA_GCCOUNT, 0) * 1024 +
			      (size_t)lua_gc(L, LUA_GCCOUNTB, 0);
	bool matched = true;
	for (size_t i = 0; i < 1000; i++) {
		lua_pushvalue(L, 1);
		if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
			matched = false;
			lua_pop(L, 1);
		}
	}
	const size_t after = (size_t)lua_gc(L, LUA_GCCOUNT, 0) * 1024 +
			     (size_t)lua_gc(L, LUA_GCCOUNTB, 0);
	lua_gc(L, LUA_GCRESTART, 0);
	T_EXPECT(matched);
	T_EXPECT(after <= before);
}

T_DECLARE_CASE(regex_match_common_captures_do_not_allocate_scratch)
{
	T_CALL_SUBCASE(regex_match_scratch_case, 0);
	T_CALL_SUBCASE(regex_match_scratch_case, 1);
	T_CALL_SUBCASE(regex_match_scratch_case, 15);
}

T_DECLARE_CASE(regex_match_many_captures)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L,
		"for _, captures in ipairs({14, 15, 16, 32}) do "
		"  local r = regex.compile(string.rep('(a)', captures) .. '(b)?') "
		"  local word = string.rep('a', captures) "
		"  for _, suffix in ipairs({'', 'b'}) do "
		"    local subject = word .. suffix "
		"    local values = table.pack(regex.match(r, 'xx' .. subject, 3)) "
		"    assert(values.n == captures + 2) "
		"    assert(values[1] == subject) "
		"    for i = 2, captures + 1 do assert(values[i] == 'a') end "
		"    assert(values[captures + 2] == (suffix == 'b' and 'b' or nil)) "
		"  end "
		"  assert(regex.match(r, 'z') == nil) "
		"end return true"));
	T_EXPECT(lua_toboolean(L, -1) != 0);
}

/* regex.match honors the optional init (start) argument, like regex.find. */
T_DECLARE_CASE(regex_match_with_init)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('a+') "
		   "return regex.match(r, 'aaXaa', 3)"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT_STREQ(lua_tostring(L, 1), "aa");
}

/* regex.ICASE makes matching case-insensitive. */
T_DECLARE_CASE(regex_icase_matches_mixed_case)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('hello', regex.ICASE) "
		   "return regex.match(r, 'oh HELLO there')"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT_STREQ(lua_tostring(L, 1), "HELLO");
}

/* Regression: compiling with regex.NOSUB (which makes regexec() leave pmatch
 * unfilled) must not make find/match read an uninitialized regmatch_t. The
 * flag is stripped, so offsets and captures still work. */
T_DECLARE_CASE(regex_nosub_is_neutralized)
{
	lua_State *restrict L = new_lua(_t_);
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
}

T_DECLARE_CASE(regex_gmatch_iterator)
{
	lua_State *restrict L = new_lua(_t_);
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
}

T_DECLARE_CASE(regex_gmatch_supplies_suffix_bounds)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	g_regexec_calls = 0;
	g_bounded_calls = 0;
	g_bounds_ok = true;
	g_track_regexec = true;
	const bool ok = run_chunk(
		L,
		"local r = regex.compile('(.)', regex.EXTENDED | regex.NOSUB) "
		"local it = regex.gmatch(r, 'abc', 2) "
		"local a, ac = it() "
		"local b, bc = it() "
		"return a == 'b' and ac == 'b' and b == 'c' and bc == 'c' "
		"and it() == nil");
	g_track_regexec = false;
	const bool matched = lua_toboolean(L, -1) != 0;

	T_EXPECT(ok);
	T_EXPECT(matched);
	T_EXPECT_EQ(g_regexec_calls, (size_t)3);
#if WITH_REG_STARTEND
	T_EXPECT_EQ(g_bounded_calls, g_regexec_calls);
#else
	T_EXPECT_EQ(g_bounded_calls, (size_t)0);
#endif
	T_EXPECT(g_bounds_ok);
}

/* Keep the iterator alive and stop collection so any scratch userdata stays
 * counted. Warm and repeat the same C call path as in the match regression. */
T_DECLARE_SUBCASE(regex_gmatch_scratch_case, int captures)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);
	lua_pushinteger(L, captures);
	lua_setglobal(L, "captures");
	T_CHECK(run_chunk(
		L,
		"local r = regex.compile(string.rep('(a)', captures) .. 'a') "
		"local subject = string.rep('a', captures + 1) "
		"return regex.gmatch(r, string.rep(subject, 1001))"));
	lua_pushvalue(L, 1);
	T_CHECK(lua_pcall(L, 0, 1, 0) == LUA_OK);
	T_CHECK(lua_isstring(L, -1));
	lua_pop(L, 1);

	lua_gc(L, LUA_GCSTOP, 0);
	const size_t before = (size_t)lua_gc(L, LUA_GCCOUNT, 0) * 1024 +
			      (size_t)lua_gc(L, LUA_GCCOUNTB, 0);
	bool matched = true;
	for (size_t i = 0; i < 1000; i++) {
		lua_pushvalue(L, 1);
		const int status = lua_pcall(L, 0, 1, 0);
		if (status != LUA_OK || !lua_isstring(L, -1)) {
			matched = false;
		}
		lua_pop(L, 1);
	}
	lua_pushvalue(L, 1);
	const int status = lua_pcall(L, 0, 1, 0);
	const bool exhausted = status == LUA_OK && lua_isnil(L, -1);
	lua_pop(L, 1);
	const size_t after = (size_t)lua_gc(L, LUA_GCCOUNT, 0) * 1024 +
			     (size_t)lua_gc(L, LUA_GCCOUNTB, 0);
	lua_gc(L, LUA_GCRESTART, 0);
	T_EXPECT(matched);
	T_EXPECT(exhausted);
	T_EXPECT(after <= before);
}

T_DECLARE_CASE(regex_gmatch_common_captures_do_not_allocate_scratch)
{
	T_CALL_SUBCASE(regex_gmatch_scratch_case, 0);
	T_CALL_SUBCASE(regex_gmatch_scratch_case, 1);
	T_CALL_SUBCASE(regex_gmatch_scratch_case, 15);
}

T_DECLARE_CASE(regex_gmatch_many_captures)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L,
		"for _, captures in ipairs({15, 16, 32}) do "
		"  local r = regex.compile(string.rep('(a)', captures) .. '(b)?') "
		"  local word = string.rep('a', captures) "
		"  local it = regex.gmatch(r, word .. ' ' .. word .. 'b') "
		"  for n = 1, 2 do "
		"    local values = table.pack(it()) "
		"    assert(values.n == captures + 2) "
		"    assert(values[1] == word .. (n == 2 and 'b' or '')) "
		"    for i = 2, captures + 1 do assert(values[i] == 'a') end "
		"    assert(values[captures + 2] == (n == 2 and 'b' or nil)) "
		"  end "
		"  assert(it() == nil and it() == nil) "
		"end return true"));
	T_EXPECT(lua_toboolean(L, -1) != 0);
}

/* Regression: once gmatch reaches the end, repeated probes must not keep
 * allocating match storage while rescanning the same suffix. */
T_DECLARE_CASE(regex_gmatch_exhaustion_is_stable)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_CHECK(run_chunk(
		L, "local r = regex.compile('z') "
		   "return regex.gmatch(r, 'abc')"));
	T_CHECK(lua_gettop(L) == 1);
	lua_pushvalue(L, 1);
	T_CHECK(lua_pcall(L, 0, 1, 0) == LUA_OK);
	T_EXPECT(lua_isnil(L, -1));
	lua_pop(L, 1);

	/* Warm the protected-call path before measuring it from C. A Lua loop
	 * can grow the VM stack even when the iterator allocates nothing. */
	lua_gc(L, LUA_GCSTOP, 0);
	const size_t before = (size_t)lua_gc(L, LUA_GCCOUNT, 0) * 1024 +
			      (size_t)lua_gc(L, LUA_GCCOUNTB, 0);
	g_regexec_calls = 0;
	g_track_regexec = true;
	bool exhausted = true;
	for (size_t i = 0; i < 1000; i++) {
		lua_pushvalue(L, 1);
		const int status = lua_pcall(L, 0, 1, 0);
		if (status != LUA_OK || !lua_isnil(L, -1)) {
			exhausted = false;
		}
		lua_pop(L, 1);
	}
	g_track_regexec = false;
	const size_t after = (size_t)lua_gc(L, LUA_GCCOUNT, 0) * 1024 +
			     (size_t)lua_gc(L, LUA_GCCOUNTB, 0);
	T_EXPECT(exhausted);
	T_EXPECT_EQ(g_regexec_calls, (size_t)0);
	T_EXPECT(after <= before);
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
	lua_State *restrict L = new_lua(_t_);
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
}

/*
 * Regression: gmatch restarts regexec() on the subject advanced past the last
 * match, and POSIX calls the first byte handed to regexec() a line start. With
 * no REG_NOTBOL that made `^` match afresh at every restart, so an anchored
 * pattern yielded one match per position -- three here instead of one.
 */
T_DECLARE_CASE(regex_gmatch_anchor_matches_once)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('^a') "
		   "local it = regex.gmatch(r, 'aaa') "
		   "local n = 0 "
		   "for _ = 1, 10 do "
		   "  if it() == nil then break end "
		   "  n = n + 1 "
		   "end "
		   "return n"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT_EQ(lua_tointeger(L, 1), 1);
}

/* Regression: an explicit init is a start offset, not a line start -- `^` must
 * not match there either. */
T_DECLARE_CASE(regex_find_init_does_not_reanchor)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('^a') "
		   "local at_start = regex.find(r, 'aaa') "
		   "local at_init = regex.find(r, 'aaa', 2) "
		   "return at_start, at_init == nil"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), 1);
	T_EXPECT(lua_toboolean(L, 2) != 0);
}

/*
 * The REG_NOTBOL above must suppress `^` only at the restart byte itself: under
 * the default REG_NEWLINE a newline still inside the subject keeps anchoring,
 * so iterating an anchored pattern over lines still yields every line.
 */
T_DECLARE_CASE(regex_gmatch_anchor_still_matches_each_line)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('^[a-z]+') "
		   "local it = regex.gmatch(r, 'aa\\nbb\\ncc') "
		   "local out = {} "
		   "for _ = 1, 10 do "
		   "  local m = it() "
		   "  if m == nil then break end "
		   "  out[#out + 1] = m "
		   "end "
		   "return #out, table.concat(out, ',')"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), 3);
	T_EXPECT_STREQ(lua_tostring(L, 2), "aa,bb,cc");
}

/*
 * Regression: a pattern consuming its own line terminator restarts gmatch one
 * byte past a newline. That is a genuine line start, but the newline anchoring
 * it now sits outside the subject, so keying REG_NOTBOL on the offset alone
 * suppressed `^` there and dropped every other line -- "bb" here.
 */
T_DECLARE_CASE(regex_gmatch_anchor_matches_consumed_newline_lines)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local r = regex.compile('^[a-z]+\\n?') "
		   "local it = regex.gmatch(r, 'aa\\nbb\\ncc') "
		   "local out = {} "
		   "for _ = 1, 10 do "
		   "  local m = it() "
		   "  if m == nil then break end "
		   "  out[#out + 1] = m "
		   "end "
		   "return #out, table.concat(out, '|')"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), 3);
	T_EXPECT_STREQ(lua_tostring(L, 2), "aa\n|bb\n|cc");
}

/*
 * The line-start exemption above is keyed on regex.NEWLINE: with it, a start
 * offset right after a newline anchors `^`; without it, `^` binds to the string
 * start alone, so that offset stays unanchored like any other.
 */
T_DECLARE_CASE(regex_find_init_after_newline_anchors)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local nl = regex.compile('^bb') "
		   "local nonl = regex.compile('^bb', regex.EXTENDED) "
		   "local s = 'aa\\nbb' "
		   "local at_nl = regex.find(nl, s, 4) "
		   "local at_nonl = regex.find(nonl, s, 4) "
		   "return at_nl, at_nonl == nil"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), 4);
	T_EXPECT(lua_toboolean(L, 2) != 0);
}

/*
 * Regression: regex_cstrpos() must not narrow the subject length to
 * lua_Integer. `huge` is the smallest length exceeding LUA_MAXINTEGER, the
 * only width where that conversion breaks, and is synthetic -- Lua's MAX_SIZE
 * caps a string at a size both size_t and lua_Integer hold -- so no string is
 * allocated. Pre-fix, (lua_Integer)len was implementation-defined there: a
 * positive index clamped to the end instead of converting, and a negative
 * index overflowed signed arithmetic. A size_t that cannot reach past
 * LUA_MAXINTEGER has no such length to pin.
 */
T_DECLARE_CASE(regex_cstrpos_does_not_narrow_length)
{
	if (SIZE_MAX <= (lua_Unsigned)LUA_MAXINTEGER) {
		T_SKIPNOW();
	}
	const size_t huge = (size_t)LUA_MAXINTEGER + 1u;

	/* positive 1-based index converts to pos-1, not clamp-to-end */
	T_EXPECT_EQ(regex_cstrpos(1, huge), (size_t)0);
	T_EXPECT_EQ(regex_cstrpos(5, huge), (size_t)4);
	T_EXPECT_EQ(regex_cstrpos(LUA_MAXINTEGER, huge), huge - 2u);

	/* negative index counts back from the end, no signed overflow */
	T_EXPECT_EQ(regex_cstrpos(-1, huge), huge - 1u);
	T_EXPECT_EQ(regex_cstrpos(-2, huge), huge - 2u);

	/* the largest-magnitude negative index maps to the string start */
	T_EXPECT_EQ(regex_cstrpos(LUA_MININTEGER, huge), (size_t)0);
}

/*
 * Regression: the mirror image -- regex_cstrpos() must not narrow the Lua
 * index to size_t either. lua_Integer is 64-bit by default at every target
 * width, so on a 32-bit-size_t host an index past SIZE_MAX truncated:
 * regex_cstrpos(2^32, 10) returned 4294967295, an offset past len that
 * find/match/gmatch add to the subject pointer while underflowing the
 * remaining length.
 */
T_DECLARE_CASE(regex_cstrpos_does_not_narrow_position)
{
	const size_t len = 10;

	/* the extremes of lua_Integer clamp to the two ends, at any width */
	T_EXPECT_EQ(regex_cstrpos(LUA_MAXINTEGER, len), len);
	T_EXPECT_EQ(regex_cstrpos(LUA_MININTEGER, len), (size_t)0);

	/*
	 * Indices a narrowing cast folds back into range: SIZE_MAX + 1 + k
	 * truncates to k. Only a size_t narrower than lua_Integer has any.
	 */
	if (SIZE_MAX >= (lua_Unsigned)LUA_MAXINTEGER) {
		return;
	}
	const lua_Integer wrap = (lua_Integer)SIZE_MAX + 1;
	T_EXPECT_EQ(regex_cstrpos(wrap, len), len);
	T_EXPECT_EQ(regex_cstrpos(wrap + 3, len), len);
	T_EXPECT_EQ(regex_cstrpos(-wrap, len), (size_t)0);
	T_EXPECT_EQ(regex_cstrpos(-(wrap + 5), len), (size_t)0);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(regex_fixture_intentional_failure)
{
	lua_State *L = new_lua(_t_);
	T_CHECK(L != NULL);
	T_CHECK(run_chunk(L, "return true"));
	T_EXPECT(false);
}

T_DECLARE_CASE(regex_failed_expectation_closes_lua)
{
	const unsigned before = lua_close_count;
	T_DECLARE_CTX(nested);
	T_RUN_CASE(nested, regex_fixture_intentional_failure);
	T_EXPECT_EQ(nested.failed, 1);
	T_EXPECT_EQ(lua_close_count, before + 1);
	T_RUN_CASE(nested, regex_module_opens);
	T_EXPECT_EQ(nested.passed, 1);
	T_EXPECT_EQ(lua_close_count, before + 2);
}

static const struct testing_suite suite[] = {
	T_CASE(regex_failed_expectation_closes_lua),
	T_CASE(regex_module_opens),
	T_CASE(regex_compile_basic),
	T_CASE(regex_compile_invalid),
	T_CASE(regex_compile_rejects_embedded_nul),
	T_CASE(regex_compile_invalid_repeated_no_leak),
	T_CASE(regex_find_match),
	T_CASE(regex_find_nomatch),
	T_CASE(regex_find_reports_runtime_error),
	T_CASE(regex_match_reports_runtime_error),
	T_CASE(regex_match_many_captures_reports_runtime_error),
	T_CASE(regex_gmatch_reports_runtime_error),
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
	T_CASE(regex_match_common_captures_do_not_allocate_scratch),
	T_CASE(regex_match_many_captures),
	T_CASE(regex_match_with_init),
	T_CASE(regex_icase_matches_mixed_case),
	T_CASE(regex_nosub_is_neutralized),
	T_CASE(regex_gmatch_iterator),
	T_CASE(regex_gmatch_supplies_suffix_bounds),
	T_CASE(regex_gmatch_common_captures_do_not_allocate_scratch),
	T_CASE(regex_gmatch_many_captures),
	T_CASE(regex_gmatch_exhaustion_is_stable),
	T_CASE(regex_gmatch_empty_match_terminates),
	T_CASE(regex_gmatch_anchor_matches_once),
	T_CASE(regex_find_init_does_not_reanchor),
	T_CASE(regex_gmatch_anchor_still_matches_each_line),
	T_CASE(regex_gmatch_anchor_matches_consumed_newline_lines),
	T_CASE(regex_find_init_after_newline_anchors),
	T_CASE(regex_cstrpos_does_not_narrow_length),
	T_CASE(regex_cstrpos_does_not_narrow_position),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
