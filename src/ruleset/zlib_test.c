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

#include "base.h"
#include "proto/codec.h"

#include "io/memory.h"
#include "io/stream.h"
#include "utils/testing.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <malloc.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * mock - shared Lua test fixtures (zlib.c has no collaborator to mock).
 * ---------------------------------------------------------------------- */

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
static size_t g_userdata_alloc_size;
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
	if (ptr == NULL && osize == LUA_TUSERDATA) {
		g_userdata_alloc_size = nsize;
	}
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

static lua_State *new_lua_isolated(struct testing_ctx *_t_)
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
	T_CLEANUP(close_lua, L);
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

/* Constructor faults are confined to zlib.c; real codec and stream cleanup
 * still runs. A failed codec consumes its base just like the real constructor. */
enum constructor_fault {
	CTOR_NONE,
	CTOR_MEMREADER,
	CTOR_HEAPWRITER,
	CTOR_CODEC,
	CTOR_COUNT,
};

static struct {
	bool active;
	enum constructor_fault fault;
	unsigned failures, closes, output_frees;
	unsigned calls[CTOR_COUNT];
	void *output;
	bool short_write;
	int write_error, close_error;
} constructor_probe;

static bool fail_constructor(const enum constructor_fault which)
{
	if (!constructor_probe.active) {
		return false;
	}
	constructor_probe.calls[which]++;
	if (constructor_probe.fault != which) {
		return false;
	}
	constructor_probe.failures++;
	return true;
}

struct io_stream *test_zlib_memreader(const void *buf, const size_t len)
{
	return fail_constructor(CTOR_MEMREADER) ? NULL : io_memreader(buf, len);
}

struct io_stream *test_zlib_heapwriter(struct vbuffer **output)
{
	if (constructor_probe.active) {
		constructor_probe.output = *output;
	}
	return fail_constructor(CTOR_HEAPWRITER) ? NULL : io_heapwriter(output);
}

int test_zlib_stream_close(struct io_stream *stream)
{
	if (constructor_probe.active) {
		constructor_probe.closes++;
	}
	const int err = io_stream_close(stream);
	return constructor_probe.active && constructor_probe.close_error != 0 ?
		       constructor_probe.close_error :
		       err;
}

int test_zlib_stream_write(
	struct io_stream *stream, const void *buf, size_t *len)
{
	if (constructor_probe.active) {
		if (constructor_probe.write_error != 0) {
			*len = 0;
			return constructor_probe.write_error;
		}
		if (constructor_probe.short_write && *len > 0) {
			(*len)--;
			return 0;
		}
	}
	return io_stream_write(stream, buf, len);
}

void test_zlib_free(void *ptr)
{
	if (constructor_probe.active && ptr != NULL &&
	    ptr == constructor_probe.output) {
		constructor_probe.output_frees++;
		constructor_probe.output = NULL;
	}
	free(ptr);
}

static struct io_stream *test_codec(
	struct io_stream *base, struct io_stream *(*codec)(struct io_stream *))
{
	if (fail_constructor(CTOR_CODEC)) {
		T_CHECK(base != NULL);
		(void)test_zlib_stream_close(base);
		return NULL;
	}
	return codec(base);
}

struct io_stream *test_zlib_writer(struct io_stream *base)
{
	return test_codec(base, codec_zlib_writer);
}

struct io_stream *test_zlib_reader(struct io_stream *base)
{
	return test_codec(base, codec_zlib_reader);
}

struct io_stream *test_gzip_writer(struct io_stream *base)
{
	return test_codec(base, codec_gzip_writer);
}

struct io_stream *test_gzip_reader(struct io_stream *base)
{
	return test_codec(base, codec_gzip_reader);
}

static void constructor_cleanup(void *data)
{
	constructor_probe.fault = CTOR_NONE;
	(void)data;
	memset(&constructor_probe, 0, sizeof(constructor_probe));
}

T_DECLARE_SUBCASE(expect_codec_recovery, lua_State *L)
{
	T_EXPECT(run_chunk(
		L,
		"return zlib.uncompress(zlib.compress('recovered')) == 'recovered' "
		"and zlib.gunzip(zlib.gzip('recovered')) == 'recovered'"));
	T_EXPECT(lua_toboolean(L, -1));
	lua_pop(L, 1);
	T_EXPECT_EQ(lua_gettop(L), 0);
}

T_DECLARE_SUBCASE(
	expect_constructor_failure, lua_State *L, const char *chunk,
	const enum constructor_fault fault, const bool encode)
{
	T_CHECK(luaL_loadstring(L, chunk) == LUA_OK);
	/* Keep the previous operation's finalizers outside the observed call. */
	lua_gc(L, LUA_GCCOLLECT, 0);
	lua_gc(L, LUA_GCSTOP, 0);
	memset(&constructor_probe, 0, sizeof(constructor_probe));
	constructor_probe.active = true;
	constructor_probe.fault = fault;
	const int status = lua_pcall(L, 0, LUA_MULTRET, 0);
	constructor_probe.fault = CTOR_NONE;

	T_EXPECT_EQ(status, LUA_ERRRUN);
	const char *err = lua_tostring(L, -1);
	T_EXPECT(err != NULL);
	T_EXPECT(strstr(err, "out of memory") != NULL);
	lua_pop(L, 1);
	T_EXPECT_EQ(constructor_probe.failures, 1u);
	T_EXPECT_EQ(constructor_probe.calls[CTOR_MEMREADER], encode ? 0u : 1u);
	T_EXPECT_EQ(constructor_probe.calls[CTOR_HEAPWRITER], 1u);
	T_EXPECT_EQ(constructor_probe.calls[CTOR_CODEC], 1u);
	const unsigned consumed_base = fault == CTOR_CODEC ? 1u : 0u;
	const unsigned pending = encode ? 0u : 1u;
#if HAVE_LUA_TOCLOSE
	T_EXPECT_EQ(constructor_probe.closes, consumed_base + pending);
	T_EXPECT_EQ(constructor_probe.output_frees, 1u);
#else
	T_EXPECT_EQ(constructor_probe.closes, consumed_base);
	T_EXPECT_EQ(constructor_probe.output_frees, 0u);
#endif
	lua_gc(L, LUA_GCCOLLECT, 0);
	T_EXPECT_EQ(constructor_probe.closes, consumed_base + pending);
	T_EXPECT_EQ(constructor_probe.output_frees, 1u);
	T_EXPECT(constructor_probe.output == NULL);
	/* A later __gc after __close must not close or free a second time. */
	lua_gc(L, LUA_GCCOLLECT, 0);
	T_EXPECT_EQ(constructor_probe.closes, consumed_base + pending);
	T_EXPECT_EQ(constructor_probe.output_frees, 1u);
	constructor_probe.active = false;
	lua_gc(L, LUA_GCRESTART, 0);

	T_CALL_SUBCASE(expect_codec_recovery, L);
}

T_DECLARE_SUBCASE(
	partial_construction_case, const char *chunk, const bool encode)
{
	lua_State *L = new_lua_isolated(_t_);
	T_EXPECT(L != NULL);
	T_CLEANUP(constructor_cleanup, L);
	T_EXPECT(run_chunk(
		L, "z = zlib.compress('payload') gz = zlib.gzip('payload')"));
	if (!encode) {
		T_CALL_SUBCASE(
			expect_constructor_failure, L, chunk, CTOR_MEMREADER,
			encode);
	}
	T_CALL_SUBCASE(
		expect_constructor_failure, L, chunk, CTOR_HEAPWRITER, encode);
	T_CALL_SUBCASE(
		expect_constructor_failure, L, chunk, CTOR_CODEC, encode);
}

/* -------------------------------------------------------------------------
 * fuzz - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * regression - compress/decompress binding cases.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(zlib_module_opens)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	lua_getglobal(L, "zlib");
	T_EXPECT(lua_istable(L, -1));
	lua_getfield(L, -1, "compress");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -2, "uncompress");
	T_EXPECT(lua_isfunction(L, -1));
}

T_DECLARE_CASE(zlib_roundtrip_small)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = 'hello zlib hello zlib' "
		   "local z = zlib.compress(s) "
		   "local u = zlib.uncompress(z) "
		   "return s == u"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);
}

T_DECLARE_CASE(zlib_roundtrip_large)
{
	lua_State *restrict L = new_lua(_t_);
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
}

T_DECLARE_CASE(zlib_empty_string)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local z = zlib.compress('') "
		   "local u = zlib.uncompress(z) "
		   "return #u, u == ''"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), 0);
	T_EXPECT(lua_toboolean(L, 2) != 0);
}

T_DECLARE_CASE(zlib_uncompress_invalid)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local ok, err = pcall(zlib.uncompress, 'not-zlib-data') "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");
}

T_DECLARE_CASE(gzip_module_has_funcs)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	lua_getglobal(L, "zlib");
	T_EXPECT(lua_istable(L, -1));
	lua_getfield(L, -1, "gzip");
	T_EXPECT(lua_isfunction(L, -1));
	lua_getfield(L, -2, "gunzip");
	T_EXPECT(lua_isfunction(L, -1));
}

T_DECLARE_CASE(gzip_roundtrip_small)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = 'hello gzip hello gzip' "
		   "local z = zlib.gzip(s) "
		   "local u = zlib.gunzip(z) "
		   "return s == u"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);
}

T_DECLARE_CASE(gzip_roundtrip_large)
{
	lua_State *restrict L = new_lua(_t_);
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
}

T_DECLARE_CASE(gzip_empty_string)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local z = zlib.gzip('') "
		   "local u = zlib.gunzip(z) "
		   "return #u, u == ''"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT_EQ(lua_tointeger(L, 1), 0);
	T_EXPECT(lua_toboolean(L, 2) != 0);
}

T_DECLARE_CASE(gunzip_invalid)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local ok, err = pcall(zlib.gunzip, 'not-gzip-data') "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");
}

/* #191: a valid stream cut off mid-body must be rejected. inflate ends at a
 * clean EOF in NEEDS_MORE_INPUT rather than a header or checksum error, so this
 * pins the distinct reader-close "truncated is an error, not short success"
 * path -- a regression could silently return a partial plaintext. */
T_DECLARE_CASE(zlib_uncompress_truncated)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = ('payload-'):rep(1000) "
		   "local z = zlib.compress(s) "
		   "local ok, err = pcall(zlib.uncompress, z:sub(1, #z // 2)) "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");
}

/* gunzip counterpart of zlib_uncompress_truncated. */
T_DECLARE_CASE(gunzip_truncated)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local s = ('payload-'):rep(1000) "
		   "local z = zlib.gzip(s) "
		   "local ok, err = pcall(zlib.gunzip, z:sub(1, #z // 2)) "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");
}

/* The zlib counterpart of gunzip_crc_mismatch: corrupt only the trailing
 * adler-32 so the stream parses and inflates cleanly and only the checksum,
 * verified at reader close, rejects it. zlib_uncompress_invalid cannot reach
 * that path -- it fails at header parse. */
T_DECLARE_CASE(zlib_uncompress_adler_mismatch)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local z = zlib.compress('hello') "
		   "local bad = z:sub(1, #z - 4) .. string.rep('\\0', 4) "
		   "local ok, err = pcall(zlib.uncompress, bad) "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");
}

T_DECLARE_CASE(gunzip_crc_mismatch)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "local z = zlib.gzip('hello') "
		   "local bad = z:sub(1, #z - 8) .. string.rep('\\0', 8) "
		   "local ok, err = pcall(zlib.gunzip, bad) "
		   "return ok, type(err)"));
	T_EXPECT_EQ(lua_gettop(L), 2);
	T_EXPECT(lua_toboolean(L, 1) == 0);
	T_EXPECT_STREQ(lua_tostring(L, 2), "string");
}

/*
 * Repeatedly drive the error path (which unwinds through the to-be-closed
 * __close over two streams and a vbuffer) to catch leaks or double-frees in
 * the cleanup path under a leak-detecting build.
 */
T_DECLARE_CASE(zlib_repeated_failure_no_leak)
{
	lua_State *restrict L = new_lua(_t_);
	T_CHECK(L != NULL);

	T_EXPECT(run_chunk(
		L, "for _ = 1, 100 do "
		   "  assert(not pcall(zlib.uncompress, 'not-zlib-data')) "
		   "  assert(not pcall(zlib.gunzip, 'not-gzip-data')) "
		   "end "
		   "return true"));
	T_EXPECT_EQ(lua_gettop(L), 1);
	T_EXPECT(lua_toboolean(L, 1) != 0);
}

/* The encoders report ERR_MEMORY when the output buffer cannot be allocated,
 * before any codec is built over it: a codec writer over a NULL-backed
 * heapwriter would otherwise run its close-flush into that sink on unwind. */
T_DECLARE_CASE(zlib_encode_oom_on_buffer_alloc)
{
	lua_State *restrict L = new_lua_isolated(_t_);
	T_CHECK(L != NULL);

	/* fail VBUF_NEW, the first vbuffer realloc */
	T_CALL_SUBCASE(
		expect_realloc_failure, L, "return zlib.compress('x')", 1,
		"out of memory");
	T_CALL_SUBCASE(
		expect_realloc_failure, L, "return zlib.gzip('x')", 1,
		"out of memory");
	T_EXPECT_EQ(lua_gettop(L), 0);
}

/* The decoders raise an error and unwind cleanly when the output buffer fails
 * to grow mid-copy: the decoded output outgrows the IO_BUFSIZE initial buffer,
 * so heap_write's append fails and stream_copyall propagates it. */
T_DECLARE_CASE(zlib_decode_oom_on_buffer_grow)
{
	lua_State *restrict L = new_lua_isolated(_t_);
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
}

T_DECLARE_CASE(zlib_encode_partial_construction_cleanup)
{
	T_CALL_SUBCASE(
		partial_construction_case, "return zlib.compress('payload')",
		true);
}

T_DECLARE_CASE(gzip_encode_partial_construction_cleanup)
{
	T_CALL_SUBCASE(
		partial_construction_case, "return zlib.gzip('payload')", true);
}

T_DECLARE_CASE(zlib_decode_partial_construction_cleanup)
{
	T_CALL_SUBCASE(
		partial_construction_case, "return zlib.uncompress(z)", false);
}

T_DECLARE_CASE(gzip_decode_partial_construction_cleanup)
{
	T_CALL_SUBCASE(
		partial_construction_case, "return zlib.gunzip(gz)", false);
}

T_DECLARE_CASE(zlib_transforms_use_small_cleanup_userdata)
{
	lua_State *L = new_lua_isolated(_t_);
	T_CHECK(L != NULL);
	T_CLEANUP(constructor_cleanup, L);
	T_CHECK(run_chunk(
		L, "z = zlib.compress('payload') gz = zlib.gzip('payload')"));
	const char *const chunks[] = {
		"return zlib.compress('payload')",
		"return zlib.gzip('payload')",
		"return zlib.uncompress(z)",
		"return zlib.gunzip(gz)",
	};
	for (size_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
		g_userdata_alloc_size = 0;
		memset(&constructor_probe, 0, sizeof(constructor_probe));
		constructor_probe.active = true;
		T_EXPECT(run_chunk(L, chunks[i]));
		T_EXPECT(g_userdata_alloc_size > 0);
		T_EXPECT(g_userdata_alloc_size < 1024);
		T_EXPECT_EQ(
			constructor_probe.calls[CTOR_MEMREADER],
			i < 2 ? 0u : 1u);
		T_EXPECT_EQ(constructor_probe.calls[CTOR_HEAPWRITER], 1u);
		T_EXPECT_EQ(constructor_probe.calls[CTOR_CODEC], 1u);
		constructor_probe.active = false;
		lua_pop(L, 1);
	}
}

T_DECLARE_SUBCASE(
	encode_write_failure, lua_State *L, const char *chunk,
	const bool short_write, const int write_error, const int close_error,
	const int expected_error)
{
	T_CHECK(luaL_loadstring(L, chunk) == LUA_OK);
	lua_gc(L, LUA_GCCOLLECT, 0);
	lua_gc(L, LUA_GCSTOP, 0);
	memset(&constructor_probe, 0, sizeof(constructor_probe));
	constructor_probe.active = true;
	constructor_probe.short_write = short_write;
	constructor_probe.write_error = write_error;
	constructor_probe.close_error = close_error;
	const int status = lua_pcall(L, 0, 1, 0);
	constructor_probe.short_write = false;
	constructor_probe.write_error = 0;
	constructor_probe.close_error = 0;
	T_EXPECT_EQ(status, LUA_ERRRUN);
	T_CHECK(lua_isstring(L, -1));
	lua_pushfstring(L, "error: %d", expected_error);
	T_EXPECT(strstr(lua_tostring(L, -2), lua_tostring(L, -1)) != NULL);
	lua_pop(L, 2);
	lua_gc(L, LUA_GCCOLLECT, 0);
	T_EXPECT_EQ(constructor_probe.closes, 1u);
	T_EXPECT_EQ(constructor_probe.output_frees, 1u);
	constructor_probe.active = false;
	lua_gc(L, LUA_GCRESTART, 0);
}

T_DECLARE_CASE(zlib_encode_write_and_close_failures)
{
	lua_State *L = new_lua_isolated(_t_);
	T_CHECK(L != NULL);
	T_CLEANUP(constructor_cleanup, L);
	const char *const chunks[] = {
		"return zlib.compress('payload')",
		"return zlib.gzip('payload')",
	};
	for (size_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
		T_CALL_SUBCASE(
			encode_write_failure, L, chunks[i], true, 0, EIO,
			ENOSPC);
		T_CALL_SUBCASE(
			encode_write_failure, L, chunks[i], false, EIO,
			ECANCELED, EIO);
		T_CALL_SUBCASE(
			encode_write_failure, L, chunks[i], false, 0, EIO, EIO);
	}
	T_CALL_SUBCASE(expect_codec_recovery, L);
}

/* -------------------------------------------------------------------------
 * bench - none.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * main - test runner.
 * ---------------------------------------------------------------------- */

T_DECLARE_CASE(zlib_fixture_intentional_failure)
{
	lua_State *L = new_lua(_t_);
	T_CHECK(L != NULL);
	T_CHECK(run_chunk(L, "return true"));
	T_EXPECT(false);
}

T_DECLARE_CASE(zlib_failed_expectation_closes_lua)
{
	const unsigned before = lua_close_count;
	T_DECLARE_CTX(nested);
	T_RUN_CASE(nested, zlib_fixture_intentional_failure);
	T_EXPECT_EQ(nested.failed, 1);
	T_EXPECT_EQ(lua_close_count, before + 1);
	T_RUN_CASE(nested, zlib_module_opens);
	T_EXPECT_EQ(nested.passed, 1);
	T_EXPECT_EQ(lua_close_count, before + 2);
}

static const struct testing_suite suite[] = {
	T_CASE(zlib_failed_expectation_closes_lua),
	T_CASE(zlib_transforms_use_small_cleanup_userdata),
	T_CASE(zlib_encode_write_and_close_failures),
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
	T_CASE(zlib_encode_partial_construction_cleanup),
	T_CASE(gzip_encode_partial_construction_cleanup),
	T_CASE(zlib_decode_partial_construction_cleanup),
	T_CASE(gzip_decode_partial_construction_cleanup),
	T_SUITE_END,
};

int main(int argc, char **argv)
{
	return testing_main(argc, argv, suite);
}
