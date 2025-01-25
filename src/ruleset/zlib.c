/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "zlib.h"

#include "base.h"

#include "io/io.h"
#include "io/memory.h"
#include "io/stream.h"
#include "utils/buffer.h"

#include "codec.h"

#include "lauxlib.h"
#include "lua.h"

#include <stddef.h>

#define MT_STREAM_CONTEXT "stream_context"

struct stream_context {
	struct vbuffer *out;
	struct stream *r, *w;
	unsigned char buf[IO_BUFSIZE];
};

static int stream_context_close(lua_State *restrict L)
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
	lua_settop(L, 1);
	struct stream_context *restrict s =
		lua_newuserdata(L, sizeof(struct stream_context));
	s->out = NULL;
	s->r = NULL;
	s->w = NULL;
	aux_toclose(L, -1, MT_STREAM_CONTEXT, stream_context_close);

	s->out = VBUF_NEW(IO_BUFSIZE);
	s->r = io_memreader(src, len);
	s->w = codec_zlib_writer(io_heapwriter(&s->out));
	if (s->out == NULL || s->r == NULL || s->w == NULL) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	const int err = stream_copyall(s);
	if (err != 0) {
		return luaL_error(L, "compress error: %d", err);
	}
	lua_pushlstring(L, VBUF_DATA(s->out), VBUF_LEN(s->out));
	aux_close(L, 2);
	return 1;
}

/* s = zlib.uncompress(z) */
static int zlib_uncompress(lua_State *restrict L)
{
	size_t len;
	const char *src = luaL_checklstring(L, 1, &len);
	lua_settop(L, 1);
	struct stream_context *restrict s =
		lua_newuserdata(L, sizeof(struct stream_context));
	s->out = NULL;
	s->r = NULL;
	s->w = NULL;
	aux_toclose(L, -1, MT_STREAM_CONTEXT, stream_context_close);

	s->out = VBUF_NEW(IO_BUFSIZE);
	s->r = codec_zlib_reader(io_memreader(src, len));
	s->w = io_heapwriter(&s->out);
	if (s->out == NULL || s->r == NULL || s->w == NULL) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	const int err = stream_copyall(s);
	if (err != 0) {
		return luaL_error(L, "uncompress error: %d", err);
	}
	lua_pushlstring(L, VBUF_DATA(s->out), VBUF_LEN(s->out));
	aux_close(L, 2);
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
