/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/*
 * zlib_test - white-box unit tests for ruleset/zlib.c.
 *
 * Linked translation units (see CMakeLists.txt):
 *   ruleset/zlib.c   module under test
 *   ruleset/base.c   ruleset Lua substrate
 *   proto/codec.c    leaf
 *   util.c           leaf
 *   dialer.c, resolver.c  linked for symbols bound by the Lua base library
 *   version.c        leaf
 * No stateful collaborator to mock; the mock section holds Lua fixtures.
 */

#include "zlib.h"

#include "utils/testing.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <malloc.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * mock - shared Lua test fixtures (zlib.c has no collaborator to mock).
 * ---------------------------------------------------------------------- */

static lua_State *new_lua(void)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		return NULL;
	}
	luaL_openlibs(L);
	(void)luaopen_zlib(L);
	lua_setglobal(L, "zlib");
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
 * zlib_transcode()'s output vbuffer calls libc realloc() directly (VBUF_NEW,
 * and the heapwriter's VBUF_APPEND growth), so interposing realloc() here
 * drives its out-of-memory branches. The codec streams, memreader and
 * heapwriter allocate with malloc(), so they are unaffected. To keep it
 * deterministic the OOM tests run on a Lua state whose allocator never calls
 * realloc() (isolated_alloc below), so an armed failure hits only the vbuffer
 * and never a Lua-internal allocation. The passthrough is reimplemented over
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
 * only ever affects zlib_transcode()'s vbuffer. */
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
	(void)luaopen_zlib(L);
	lua_setglobal(L, "zlib");
	return L;
}

/* Run @p chunk with realloc() failing from call @p fail_from on, and check it
 * raises an error whose message contains @p msg. The chunk is precompiled so
 * the armed window contains only the call it makes. */
T_DECLARE_SUBCASE(
	expect_realloc_failure, lua_State *restrict L,
	const char *restrict chunk, const unsigned fail_from,
	const char *restrict msg)
{
	T_CHECK(luaL_loadstring(L, chunk) == LUA_OK);
	g_realloc_calls = 0;
	g_realloc_fail_from = fail_from;
	const int status = lua_pcall(L, 0, LUA_MULTRET, 0);
	g_realloc_fail_from = 0;

	T_EXPECT_EQ(status, LUA_ERRRUN);
	const char *restrict const err = lua_tostring(L, -1);
	T_CHECK(err != NULL);
	T_EXPECT(strstr(err, msg) != NULL);
	lua_pop(L, 1);
}

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - compress/decompress binding cases.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(zlib_module_opens)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_getglobal(L, "zlib");
	T_EXPECT(lua_istable(L, -1));
	lua_getfield(L, -1, "compress");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -2, "uncompress");
	T_EXPECT(lua_isfunction(L, -1));

	lua_close(L);
}

T_DECLARE_CASE(zlib_roundtrip_small)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = 'hello zlib hello zlib' "
		   "local z = zlib.compress(s) "
		   "local u = zlib.uncompress(z) "
		   "return s == u"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(zlib_roundtrip_large)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = ('abc123'):rep(20000) "
		   "local z = zlib.compress(s) "
		   "local u = zlib.uncompress(z) "
		   "return #s, #z, #u, s == u"));
	T_EXPECT_EQ(lua_gettop(L), 4);
	T_EXPECT_EQ(lua_tointeger(L, 1), 120000);
	T_EXPECT(lua_tointeger(L, 2) > 0);
	T_EXPECT_EQ(lua_tointeger(L, 3), 120000);
	T_EXPECT(lua_toboolean(L, 4) != 0);

	lua_close(L);
}

T_DECLARE_CASE(zlib_empty_string)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local z = zlib.compress('') "
		   "local u = zlib.uncompress(z) "
		   "return #u, u == ''"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), 0);
	T_EXPECT(lua_toboolean(L, 2) != 0);

	lua_close(L);
}

T_DECLARE_CASE(zlib_uncompress_invalid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local ok, err = pcall(zlib.uncompress, 'not-zlib-data') "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

T_DECLARE_CASE(gzip_module_has_funcs)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	lua_getglobal(L, "zlib");
	T_EXPECT(lua_istable(L, -1));
	lua_getfield(L, -1, "gzip");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -2, "gunzip");
	T_EXPECT(lua_isfunction(L, -1));

	lua_close(L);
}

T_DECLARE_CASE(gzip_roundtrip_small)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = 'hello gzip hello gzip' "
		   "local z = zlib.gzip(s) "
		   "local u = zlib.gunzip(z) "
		   "return s == u"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

T_DECLARE_CASE(gzip_roundtrip_large)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = ('abc123'):rep(20000) "
		   "local z = zlib.gzip(s) "
		   "local u = zlib.gunzip(z) "
		   "return #s, #z, #u, s == u"));
	T_EXPECT_EQ(lua_gettop(L), 4);
	T_EXPECT_EQ(lua_tointeger(L, 1), 120000);
	T_EXPECT(lua_tointeger(L, 2) > 0);
	T_EXPECT_EQ(lua_tointeger(L, 3), 120000);
	T_EXPECT(lua_toboolean(L, 4) != 0);

	lua_close(L);
}

T_DECLARE_CASE(gzip_empty_string)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local z = zlib.gzip('') "
		   "local u = zlib.gunzip(z) "
		   "return #u, u == ''"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), 0);
	T_EXPECT(lua_toboolean(L, 2) != 0);

	lua_close(L);
}

T_DECLARE_CASE(gunzip_invalid)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local ok, err = pcall(zlib.gunzip, 'not-gzip-data') "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

/* #191: a valid stream cut off mid-body must be rejected. inflate ends at a
 * clean EOF in NEEDS_MORE_INPUT rather than a header or checksum error, so this
 * pins the distinct reader-close "truncated is an error, not short success"
 * path -- a regression could silently return a partial plaintext. */
T_DECLARE_CASE(zlib_uncompress_truncated)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = ('payload-'):rep(1000) "
		   "local z = zlib.compress(s) "
		   "local ok, err = pcall(zlib.uncompress, z:sub(1, #z // 2)) "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

/* gunzip counterpart of zlib_uncompress_truncated. */
T_DECLARE_CASE(gunzip_truncated)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = ('payload-'):rep(1000) "
		   "local z = zlib.gzip(s) "
		   "local ok, err = pcall(zlib.gunzip, z:sub(1, #z // 2)) "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

/* The zlib counterpart of gunzip_crc_mismatch: corrupt only the trailing
 * adler-32 so the stream parses and inflates cleanly and only the checksum,
 * verified at reader close, rejects it. zlib_uncompress_invalid cannot reach
 * that path -- it fails at header parse. */
T_DECLARE_CASE(zlib_uncompress_adler_mismatch)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local z = zlib.compress('hello') "
		   "local bad = z:sub(1, #z - 4) .. string.rep('\\0', 4) "
		   "local ok, err = pcall(zlib.uncompress, bad) "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

T_DECLARE_CASE(gunzip_crc_mismatch)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local z = zlib.gzip('hello') "
		   "local bad = z:sub(1, #z - 8) .. string.rep('\\0', 8) "
		   "local ok, err = pcall(zlib.gunzip, bad) "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");

	lua_close(L);
}

/*
 * Repeatedly drive the error path (which unwinds through the to-be-closed
 * __close over two streams and a vbuffer) to catch leaks or double-frees in
 * the cleanup path under a leak-detecting build.
 */
T_DECLARE_CASE(zlib_repeated_failure_no_leak)
{
	lua_State *restrict L = new_lua();
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "for _ = 1, 100 do "
		   "  assert(not pcall(zlib.uncompress, 'not-zlib-data')) "
		   "  assert(not pcall(zlib.gunzip, 'not-gzip-data')) "
		   "end "
		   "return true"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);

	lua_close(L);
}

/* The encoders report ERR_MEMORY when the output buffer cannot be allocated,
 * before any codec is built over it: a codec writer over a NULL-backed
 * heapwriter would otherwise run its close-flush into that sink on unwind. */
T_DECLARE_CASE(zlib_encode_oom_on_buffer_alloc)
{
	lua_State *restrict L = new_lua_isolated();
	T_CHECK(L != NULL);

	/* fail VBUF_NEW, the first vbuffer realloc */
	T_CALL_SUBCASE(
		expect_realloc_failure, L, "return zlib.compress('x')", 1,
		"out of memory");
	T_CALL_SUBCASE(
		expect_realloc_failure, L, "return zlib.gzip('x')", 1,
		"out of memory");
	T_EXPECT_EQ(lua_gettop(L), 0);

	lua_close(L);
}

/* The decoders raise an error and unwind cleanly when the output buffer fails
 * to grow mid-copy: the decoded output outgrows the IO_BUFSIZE initial buffer,
 * so heap_write's append fails and stream_copyall propagates it. */
T_DECLARE_CASE(zlib_decode_oom_on_buffer_grow)
{
	lua_State *restrict L = new_lua_isolated();
	T_CHECK(L != NULL);

	T_CHECK(run_chunk(
		L, "local s = string.rep('a', 1 << 16) "
		   "z = zlib.compress(s) "
		   "gz = zlib.gzip(s)"));
	/* VBUF_NEW succeeds; the grow (and after) fail */
	T_CALL_SUBCASE(
		expect_realloc_failure, L, "return zlib.uncompress(z)", 2,
		"uncompress error");
	T_CALL_SUBCASE(
		expect_realloc_failure, L, "return zlib.gunzip(gz)", 2,
		"gunzip error");
	T_EXPECT_EQ(lua_gettop(L), 0);

	/* the state stays usable once the injection is disarmed */
	T_EXPECT(run_chunk(L, "return #zlib.uncompress(z), #zlib.gunzip(gz)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), 1 << 16);
	T_EXPECT_EQ(lua_tointeger(L, 2), 1 << 16);

	lua_close(L);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

static const struct testing_suite suite[] = {
	T_CASE(zlib_module_opens),
	T_CASE(zlib_roundtrip_small),
	T_CASE(zlib_roundtrip_large),
	T_CASE(zlib_empty_string),
	T_CASE(zlib_uncompress_invalid),
	T_CASE(gzip_module_has_funcs),
	T_CASE(gzip_roundtrip_small),
	T_CASE(gzip_roundtrip_large),
	T_CASE(gzip_empty_string),
	T_CASE(gunzip_invalid),
	T_CASE(zlib_uncompress_truncated),
	T_CASE(gunzip_truncated),
	T_CASE(zlib_uncompress_adler_mismatch),
	T_CASE(gunzip_crc_mismatch),
	T_CASE(zlib_repeated_failure_no_leak),
	T_CASE(zlib_encode_oom_on_buffer_alloc),
	T_CASE(zlib_decode_oom_on_buffer_grow),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
