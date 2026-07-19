/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * marshal_test - white-box unit tests for ruleset/marshal.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   ruleset/marshal.c  module under test
 *   ruleset/base.c     ruleset Lua substrate
 *   util.c             leaf
 *   dialer.c, resolver.c  linked for symbols bound by the Lua base library
 *   version.c          leaf
 * No stateful collaborator to mock; the mock section holds Lua fixtures.
 */

#include "ruleset/marshal.h"

#include "utils/testing.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <malloc.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * mock - shared Lua test fixtures (marshal.c has no collaborator to mock).
 * ---------------------------------------------------------------------- */

static lua_State *new_lua(void)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	luaL_openlibs(L);
	(void)luaopen_marshal(L);
	lua_setglobal(L, "marshal");
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

/* ---- realloc fault injection ----
 * marshal()'s vbuffer calls libc realloc() directly, so interposing realloc()
 * here drives its out-of-memory branches. To keep it deterministic the OOM
 * tests run on a Lua state whose allocator never calls realloc()
 * (isolated_alloc below), so an armed failure hits only the vbuffer and never
 * a Lua-internal allocation. The passthrough is reimplemented over
 * malloc()/free() so it needs no libc-internal symbol. */
static unsigned g_realloc_calls;
static unsigned
	g_realloc_fail_from; /* 0 = disabled; else fail call number >= N */

void *realloc(void *ptr, size_t size)
{
	g_realloc_calls++;
	if (g_realloc_fail_from != 0 &&
	    g_realloc_calls >= g_realloc_fail_from) {
		return NULL;
	}
	if (size == 0) {
		free(ptr);
		return NULL;
	}
	void *const np = malloc(size);
	if (np == NULL) {
		return NULL;
	}
	if (ptr != NULL) {
		const size_t oldsize = malloc_usable_size(ptr);
		memcpy(np, ptr, oldsize < size ? oldsize : size);
		free(ptr);
	}
	return np;
}

/* A Lua allocator that never calls realloc(), so the fault injection above
 * only ever affects marshal()'s vbuffer. */
static void *isolated_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	(void)ud;
	if (nsize == 0) {
		free(ptr);
		return NULL;
	}
	void *const np = malloc(nsize);
	if (np == NULL) {
		return NULL;
	}
	if (ptr != NULL) {
		memcpy(np, ptr, osize < nsize ? osize : nsize);
		free(ptr);
	}
	return np;
}

static lua_State *new_lua_isolated(void)
{
	lua_State *restrict L =
#if LUA_VERSION_NUM >= 505
		lua_newstate(isolated_alloc, NULL, luaL_makeseed(NULL));
#else
		lua_newstate(isolated_alloc, NULL);
#endif
	if (L == NULL) {
		return NULL;
	}
	luaL_openlibs(L);
	(void)luaopen_marshal(L);
	lua_setglobal(L, "marshal");
	return L;
}

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - value (de)serialization round-trip cases.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(marshal_module_opens)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_getglobal(L, "marshal");
	T_EXPECT(lua_isfunction(L, -1));

	lua_close(L);
}

T_DECLARE_CASE(marshal_nil_and_bool)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "return marshal(nil), marshal(true), marshal(false)"));
	T_EXPECT_EQ(lua_gettop(L), 3);
	T_EXPECT_STREQ(lua_tostring(L, 1), "nil");
	T_EXPECT_STREQ(lua_tostring(L, 2), "true");
	T_EXPECT_STREQ(lua_tostring(L, 3), "false");

	lua_close(L);
}

T_DECLARE_CASE(marshal_integer_and_roundtrip)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s1 = marshal(0) "
		   "local s2 = marshal(42) "
		   "local s3 = marshal(-1) "
		   "local f1 = assert(load('return '..s1)) "
		   "local f2 = assert(load('return '..s2)) "
		   "local f3 = assert(load('return '..s3)) "
		   "return f1(), f2(), f3()"));
	T_EXPECT_EQ(lua_gettop(L), 3);
	T_EXPECT_EQ(lua_tointeger(L, 1), 0);
	T_EXPECT_EQ(lua_tointeger(L, 2), 42);
	T_EXPECT_EQ(lua_tointeger(L, 3), -1);

	lua_close(L);
}

T_DECLARE_CASE(marshal_number_specials)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local mnan = marshal(0/0) "
		   "local minf = marshal(1/0) "
		   "local mninf = marshal(-1/0) "
		   "return mnan, minf, mninf"));
	T_EXPECT_EQ(lua_gettop(L), 3);
	T_EXPECT_STREQ(lua_tostring(L, 1), "0/0");
	T_EXPECT_STREQ(lua_tostring(L, 2), "1/0");
	T_EXPECT_STREQ(lua_tostring(L, 3), "-1/0");

	lua_close(L);
}

T_DECLARE_CASE(marshal_float_roundtrip)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* Float zero serializes to "0"; finite floats use hex-float notation.
	 * Each must round-trip exactly through load(). The 0.0 case also forces
	 * a float (1/2 + ... ) so it is not reduced to an integer. */
	T_EXPECT(run_chunk(
		L, "local vals = {0.0, 1.5, -2.25, 0.1, 1e300, 4.0} "
		   "for _, v in ipairs(vals) do "
		   "  local m = marshal(v) "
		   "  local f = assert(load('return '..m)) "
		   "  if f() ~= v then return false, v, m end "
		   "end "
		   "return true"));
	T_EXPECT(lua_gettop(L) >= 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(marshal_large_integer_hex)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* These magnitudes exceed marshal_number's decimal cutoff on a 64-bit
	 * lua_Integer, so each is serialized as hex for compactness; assert the
	 * form there (not just the round-trip) so a regression that dropped the
	 * optimization back to decimal is caught. On a LUA_32BITS build the hex
	 * literals wrap and the decimal literal becomes a float, leaving most of
	 * these under the cutoff and serialized as decimal, so the form check is
	 * gated to the 64-bit width — math.mininteger, the one value that stays
	 * hex after narrowing, is covered by marshal_mininteger_uses_hex. The
	 * round-trip through load() must hold at both widths. The chunk is a
	 * variable, not an inline macro argument, so the #if is not embedded in
	 * the T_EXPECT macro's arguments (which would be undefined behavior). */
	const char *const chunk =
		"local vals = {1000000000000, 0x123456789abc, "
		"-0x7fffffffffffffff, math.maxinteger, math.mininteger} "
		"for _, v in ipairs(vals) do "
		"  local m = marshal(v) "
#if !LUA_32BITS
		"  if not m:find('0x', 1, true) then return false, v, m end "
#endif /* !LUA_32BITS */
		"  local f = assert(load('return '..m)) "
		"  if f() ~= v then return false, v, m end "
		"end "
		"return true";
	T_EXPECT(run_chunk(L, chunk));
	T_EXPECT(lua_gettop(L) >= 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(marshal_mininteger_uses_hex)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* math.mininteger has no positive counterpart, so marshal() drops the
	 * sign and lets the value ride on the unsigned bit pattern, which
	 * load() wraps back around. That only works in hex, at every
	 * lua_Integer width: the decimal form would read back as a positive
	 * float. Asserting the form (not just the round-trip) is what makes
	 * this hold on a 32-bit lua_Integer build, where the bit pattern is
	 * small enough to fall under marshal_number's decimal threshold. */
	T_EXPECT(run_chunk(
		L, "local m = marshal(math.mininteger) "
		   "if not m:find('0x', 1, true) then return false, m end "
		   "local v = assert(load('return '..m))() "
		   "if v ~= math.mininteger then return false, m end "
		   "if math.type(v) ~= 'integer' then return false, m end "
		   "return true"));
	T_EXPECT(lua_gettop(L) >= 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(marshal_float_zero)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* A genuine float zero (not the integer 0) marshals to "0". */
	T_EXPECT(run_chunk(L, "return marshal(0.0)"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT_STREQ(lua_tostring(L, 1), "0");
	lua_settop(L, 0);

	/* Regression: -0.0 must keep its sign (round-trips to negative zero,
	 * i.e. 1 / v == -inf), not collapse to +0/integer 0 like +0.0. */
	T_EXPECT(run_chunk(
		L, "local v = assert(load('return '..marshal(-0.0)))() "
		   "return 1 / v == -math.huge"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(marshal_string_roundtrip)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = 'A\\nB\\001\\\\\"' "
		   "local m = marshal(s) "
		   "local f = assert(load('return '..m)) "
		   "return f() == s"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);
	lua_settop(L, 0);

	/* multi-byte safe runs batched around escapes must round-trip and a
	 * plain string with no escapes is emitted verbatim between quotes */
	T_EXPECT(run_chunk(
		L, "local s = 'hello \"world\"\\n\\tfoo bar' "
		   "local f = assert(load('return '..marshal(s))) "
		   "return f() == s, marshal('plain text')"));
	T_EXPECT(lua_toboolean(L, 1) != 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "\"plain text\"");

	lua_close(L);
}

T_DECLARE_CASE(marshal_table_roundtrip)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L,
		"local t = {1, 'a', true, key = 'val'} "
		"local m = marshal(t) "
		"local f = assert(load('return '..m)) "
		"local r = f() "
		"return r[1] == 1 and r[2] == 'a' and r[3] == true and r.key == 'val'"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(marshal_unsupported_type)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local ok, err = pcall(marshal, function() end) "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

T_DECLARE_CASE(marshal_circular_table_rejected)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* A table referencing itself must raise rather than recurse forever. */
	T_EXPECT(run_chunk(
		L, "local t = {} t.self = t "
		   "local ok, err = pcall(marshal, t) "
		   "return ok, tostring(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT(strstr(lua_tostring(L, 2), "circular") != NULL);

	lua_close(L);
}

T_DECLARE_CASE(marshal_shared_table_not_rejected)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* Regression: a table referenced twice from two different places (a
	 * DAG, not a cycle) must not be rejected as circular -- an ordinary
	 * shape for shared config/record sub-tables, not an adversarial one. */
	T_EXPECT(run_chunk(
		L, "local shared = {1, 2, 3} "
		   "local m = marshal({a = shared, b = shared}) "
		   "local r = assert(load('return '..m))() "
		   "return r.a[1] == 1 and r.a[3] == 3 "
		   "and r.b[1] == 1 and r.b[3] == 3"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(marshal_shared_table_across_top_level_arguments)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* Same table passed as two separate top-level arguments to marshal(). */
	T_EXPECT(run_chunk(
		L,
		"local shared = {1, 2, 3} "
		"local m = marshal(shared, shared) "
		"local a, b = load('return '..m)() "
		"return a[1] == 1 and a[3] == 3 and b[1] == 1 and b[3] == 3"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(marshal_table_with_metatable_warns)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	/* A metatable is not marshalled but the plain table still round-trips;
	 * this also exercises the metatable warning path. */
	T_EXPECT(run_chunk(
		L,
		"local t = setmetatable({1, 2}, {__index = function() end}) "
		"local m = marshal(t) "
		"local r = assert(load('return '..m))() "
		"return r[1] == 1 and r[2] == 2 and getmetatable(r) == nil"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

/* -------------------------------------------------------------------------
 * bench - marshal (encode to Lua source) + decode round-trip of a mixed
 * table, the shape used by RPC/gossip payloads. Runs only when a name filter
 * selects it (e.g. --run bench); a plain ctest run skips it.
 * ---------------------------------------------------------------------- */

T_DECLARE_BENCH(bench_marshal_roundtrip)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);
	static const char setup[] =
		"local t = {1, 2, 3, 'hello', true, 3.14, "
		"name = 'neosocksd', nested = {a = 1, b = 'x', c = {4, 5, 6}}} "
		"return function() "
		"  return assert(load('return '..marshal(t)))() "
		"end";
	T_CHECK(luaL_loadstring(L, setup) == LUA_OK);
	T_CHECK(lua_pcall(L, 0, 1, 0) == LUA_OK);
	const int fref = luaL_ref(L, LUA_REGISTRYINDEX);

	for (uint_fast64_t iter = 0; iter < _b_->N; ++iter) {
		lua_rawgeti(L, LUA_REGISTRYINDEX, fref);
		T_CHECK(lua_pcall(L, 0, 1, 0) == LUA_OK);
		lua_pop(L, 1);
	}

	luaL_unref(L, LUA_REGISTRYINDEX, fref);
	lua_close(L);
}

/* marshal() reports ERR_MEMORY when the initial buffer allocation fails. */
T_DECLARE_CASE(marshal_reports_oom_on_buffer_alloc)
{
	lua_State *restrict L = new_lua_isolated();
	T_CHECK(L != NULL);

	/* precompile so the armed window contains only the marshal() call */
	T_CHECK(luaL_loadstring(L, "return marshal('x')") == LUA_OK);
	g_realloc_calls = 0;
	g_realloc_fail_from = 1; /* fail VBUF_NEW, the first vbuffer realloc */
	const int status = lua_pcall(L, 0, LUA_MULTRET, 0);
	g_realloc_fail_from = 0;

	T_EXPECT_EQ(status, LUA_ERRRUN);
	T_EXPECT(strstr(lua_tostring(L, -1), "out of memory") != NULL);

	lua_close(L);
}

/* marshal() reports ERR_MEMORY when growing the buffer fails mid-value. */
T_DECLARE_CASE(marshal_reports_oom_on_buffer_grow)
{
	lua_State *restrict L = new_lua_isolated();
	T_CHECK(L != NULL);

	/* a value larger than the 1KiB initial buffer forces a grow */
	T_CHECK(run_chunk(L, "big = string.rep('x', 4096)"));
	T_CHECK(luaL_loadstring(L, "return marshal(big)") == LUA_OK);
	g_realloc_calls = 0;
	g_realloc_fail_from =
		2; /* VBUF_NEW succeeds; the grow (and after) fail */
	const int status = lua_pcall(L, 0, LUA_MULTRET, 0);
	g_realloc_fail_from = 0;

	T_EXPECT_EQ(status, LUA_ERRRUN);
	T_EXPECT(strstr(lua_tostring(L, -1), "out of memory") != NULL);

	lua_close(L);
}

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(marshal_module_opens),
	T_CASE(marshal_nil_and_bool),
	T_CASE(marshal_integer_and_roundtrip),
	T_CASE(marshal_number_specials),
	T_CASE(marshal_float_roundtrip),
	T_CASE(marshal_large_integer_hex),
	T_CASE(marshal_mininteger_uses_hex),
	T_CASE(marshal_float_zero),
	T_CASE(marshal_string_roundtrip),
	T_CASE(marshal_table_roundtrip),
	T_CASE(marshal_unsupported_type),
	T_CASE(marshal_circular_table_rejected),
	T_CASE(marshal_shared_table_not_rejected),
	T_CASE(marshal_shared_table_across_top_level_arguments),
	T_CASE(marshal_table_with_metatable_warns),
	T_CASE(marshal_reports_oom_on_buffer_alloc),
	T_CASE(marshal_reports_oom_on_buffer_grow),
	T_BENCH(bench_marshal_roundtrip),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
