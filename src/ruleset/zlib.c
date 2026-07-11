/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/zlib.h"

#include "proto/codec.h"
#include "ruleset/base.h"

#include "io/io.h"
#include "io/memory.h"
#include "io/stream.h"
#include "utils/buffer.h"

#include <lauxlib.h>
#include <lua.h>

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
	VBUF_FREE(s->out);
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

/* Run a zlib/gzip transform over the argument string and push the result.
 * When @p encode is true, @p codec wraps the writer (compressing); otherwise
 * it wraps the reader (decompressing). @p what names the operation for errors. */
static int zlib_transcode(
	lua_State *restrict L, const bool encode,
	struct stream *(*const codec)(struct stream *base),
	const char *restrict const what)
{
	size_t len;
	const char *restrict const src = luaL_checklstring(L, 1, &len);
	struct stream_context *restrict const s =
		lua_newuserdata(L, sizeof(struct stream_context));
	s->out = NULL;
	s->r = NULL;
	s->w = NULL;
	aux_toclose(L, -1, MT_STREAM_CONTEXT, stream_context_close);

	s->out = VBUF_NEW(IO_BUFSIZE);
	if (encode) {
		s->r = io_memreader(src, len);
		s->w = codec(io_heapwriter(&s->out));
	} else {
		s->r = codec(io_memreader(src, len));
		s->w = io_heapwriter(&s->out);
	}
	if (s->out == NULL || s->r == NULL || s->w == NULL) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	const int err = stream_copyall(s);
	if (err != 0) {
		return luaL_error(L, "%s error: %d", what, err);
	}
	lua_pushlstring(L, VBUF_DATA(s->out), VBUF_LEN(s->out));
	aux_close(L, -2);
	return 1;
}

/* z = zlib.compress(s) */
static int zlib_compress(lua_State *restrict L)
{
	return zlib_transcode(L, true, codec_zlib_writer, "compress");
}

/* s = zlib.uncompress(z) */
static int zlib_uncompress(lua_State *restrict L)
{
	return zlib_transcode(L, false, codec_zlib_reader, "uncompress");
}

/* z = zlib.gzip(s) */
static int zlib_gzip(lua_State *restrict L)
{
	return zlib_transcode(L, true, codec_gzip_writer, "gzip");
}

/* s = zlib.gunzip(z) */
static int zlib_gunzip(lua_State *restrict L)
{
	return zlib_transcode(L, false, codec_gzip_reader, "gunzip");
}

int luaopen_zlib(lua_State *restrict L)
{
	const luaL_Reg zlib[] = {
		{ "compress", zlib_compress },
		{ "uncompress", zlib_uncompress },
		{ "gzip", zlib_gzip },
		{ "gunzip", zlib_gunzip },
		{ NULL, NULL },
	};
	luaL_newlib(L, zlib);
	return 1;
}
