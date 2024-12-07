/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "zlib.h"

#include "io/io.h"
#include "io/memory.h"
#include "io/stream.h"
#include "utils/buffer.h"

#include "codec.h"
#include "ruleset/base.h"

#include "lauxlib.h"
#include "lua.h"

#include <stddef.h>

#define MT_STREAM_CONTEXT "stream_context"

#define HAVE_LUA_TOCLOSE (LUA_VERSION_NUM >= 504)

struct stream_context {
	struct vbuffer *out;
	struct stream *r, *w;
	unsigned char buf[IO_BUFSIZE];
};

static int stream_context_close(lua_State *L)
{
	struct stream_context *restrict s = lua_touserdata(L, 1);
	if (s->r != NULL) {
		(void)stream_close(s->r);
		s->r = NULL;
	}
	if (s->w != NULL) {
		(void)stream_close(s->w);
		s->w = NULL;
	}
	s->out = VBUF_FREE(s->out);
	return 0;
}

static int stream_copyall(struct stream_context *restrict s)
{
	int ret = stream_copy(s->w, s->r, s->buf, sizeof(s->buf));
	int err = stream_close(s->r);
	s->r = NULL;
	if (ret == 0) {
		ret = err;
	}
	err = stream_close(s->w);
	s->w = NULL;
	if (ret == 0) {
		ret = err;
	}
	return ret;
}

/* z = zlib.compress(s) */
static int zlib_compress(lua_State *restrict L)
{
	size_t len;
	const char *src = luaL_checklstring(L, 1, &len);
	struct stream_context *restrict s =
		lua_newuserdata(L, sizeof(struct stream_context));
	if (luaL_newmetatable(L, MT_STREAM_CONTEXT)) {
		lua_pushcfunction(L, stream_context_close);
#if HAVE_LUA_TOCLOSE
		lua_pushvalue(L, -1);
		lua_setfield(L, -3, "__close");
#endif
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
#if HAVE_LUA_TOCLOSE
	lua_toclose(L, -1);
#endif
	s->out = NULL;
	s->r = io_memreader(src, len);
	s->w = codec_zlib_writer(io_heapwriter(&s->out));
	if (s->r == NULL || s->w == NULL) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	const int err = stream_copyall(s);
	if (err != 0) {
		return luaL_error(L, "compress error: %d", err);
	}
	if (s->out == NULL) {
		lua_pushlstring(L, NULL, 0);
		return 1;
	}
	const char *dst = (char *)s->out->data;
	lua_pushlstring(L, dst, s->out->len);
	return 1;
}

/* s = zlib.uncompress(z) */
static int zlib_uncompress(lua_State *restrict L)
{
	size_t len;
	const char *src = luaL_checklstring(L, 1, &len);
	struct stream_context *restrict s =
		lua_newuserdata(L, sizeof(struct stream_context));
	if (luaL_newmetatable(L, MT_STREAM_CONTEXT)) {
		lua_pushcfunction(L, stream_context_close);
#if HAVE_LUA_TOCLOSE
		lua_pushvalue(L, -1);
		lua_setfield(L, -3, "__close");
#endif
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
#if HAVE_LUA_TOCLOSE
	lua_toclose(L, -1);
#endif
	s->out = NULL;
	s->r = codec_zlib_reader(io_memreader(src, len));
	s->w = io_heapwriter(&s->out);
	if (s->r == NULL || s->w == NULL) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	const int err = stream_copyall(s);
	if (err != 0) {
		return luaL_error(L, "uncompress error: %d", err);
	}
	if (s->out == NULL) {
		lua_pushlstring(L, NULL, 0);
		return 1;
	}
	const char *dst = (char *)s->out->data;
	lua_pushlstring(L, dst, s->out->len);
	return 1;
}

int luaopen_zlib(lua_State *restrict L)
{
	const luaL_Reg zlib[] = {
		{ "compress", zlib_compress },
		{ "uncompress", zlib_uncompress },
		{ NULL, NULL },
	};
	luaL_newlib(L, zlib);
	return 1;
}
