/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/marshal.h"

#include "ruleset/base.h"
#include "util.h"

#include "utils/ascii.h"
#include "utils/buffer.h"
#include "utils/debug.h"

#include <lauxlib.h>
#include <lua.h>

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <tgmath.h>

#define MT_MARSHAL_BUFFER "marshal_buffer"

static int marshal_buffer_close(lua_State *restrict L)
{
	struct vbuffer **pvbuf = (struct vbuffer **)lua_touserdata(L, 1);
	VBUF_FREE(*pvbuf);
	return 0;
}

static void
marshal_string(lua_State *restrict L, struct vbuffer *restrict *restrict pvbuf)
{
	const int idx = 1;
	size_t len;
	const char *restrict str = lua_tolstring(L, idx, &len);

	VBUF_APPENDSTR(*pvbuf, "\"");
	while (len--) {
		const unsigned char ch = *str;
		if (ch == '"' || ch == '\\' || ch == '\n') {
			const unsigned char buf[2] = { '\\', ch };
			VBUF_APPEND(*pvbuf, buf, sizeof(buf));
		} else if (iscntrl(ch)) {
			unsigned char buf[4];
			unsigned char *s = &buf[sizeof(buf)];
			uint_fast8_t x = ch;

			/* Build decimal representation backwards: \ddd */
			*--s = '0' + x % 10, x /= 10;
			*--s = '0' + x % 10, x /= 10;
			*--s = '0' + x % 10;
			/* Escape prefix. */
			*--s = '\\';

			VBUF_APPEND(*pvbuf, buf, sizeof(buf));
		} else {
			VBUF_APPEND(*pvbuf, &ch, sizeof(ch));
		}
		str++;
	}
	VBUF_APPENDSTR(*pvbuf, "\"");
}

static void
marshal_number(lua_State *restrict L, struct vbuffer *restrict *restrict pvbuf)
{
	const int idx = 1;
	static const char prefix[] = "-0x";
	static const char xdigits[] = "0123456789abcdef";
	unsigned char buf[120];

	if (lua_isinteger(L, idx)) {
		lua_Integer x = lua_tointeger(L, idx);
		unsigned char *const bufend = &buf[sizeof(buf)];
		unsigned char *s = bufend;

		if (x == 0) {
			VBUF_APPENDSTR(*pvbuf, "0");
			return;
		}

		const char *p = prefix;
		const char *pend = prefix + sizeof(prefix) - 1;
		if (x < 0 && x != LUA_MININTEGER) {
			/* Make positive and keep the negative prefix. */
			x = -x;
		} else {
			/* Skip the negative sign. */
			p++;
		}

		lua_Unsigned y = x;

		/* hexadecimal is more compact for large numbers */
		if (y <= UINTMAX_C(999999999999)) {
			/* Skip the "0x" prefix. */
			pend -= 2;
			do {
				*--s = '0' + y % 10;
				y /= 10;
			} while (y);
		} else {
			do {
				*--s = xdigits[(y & 0xf)];
				y >>= 4;
			} while (y);
		}

		VBUF_APPEND(*pvbuf, p, pend - p);
		VBUF_APPEND(*pvbuf, s, bufend - s);
		return;
	}

	lua_Number x = lua_tonumber(L, idx);

	switch (fpclassify(x)) {
	case FP_NAN:
		VBUF_APPENDSTR(*pvbuf, "0/0");
		return;
	case FP_INFINITE:
		if (signbit(x)) {
			VBUF_APPENDSTR(*pvbuf, "-1/0");
			return;
		}
		VBUF_APPENDSTR(*pvbuf, "1/0");
		return;
	case FP_ZERO:
		VBUF_APPENDSTR(*pvbuf, "0");
		return;
	default:
		break;
	}

	/* hexadecimal floating point: [-]0xh.hhhp[+-]d */
	unsigned char *s = buf;

	const char *p = prefix;
	const char *pend = prefix + sizeof(prefix) - 1;
	if (signbit(x)) {
		/* Make positive and keep the negative prefix. */
		x = -x;
	} else {
		/* Skip the negative sign. */
		p++;
	}

	int e2 = 0;
	/* frexp() gives [0.5, 1); convert it to [1, 2). */
	x = frexp(x, &e2) * 2;
	if (x) {
		/* Adjust the exponent for the [1, 2) range. */
		e2--;
	}

	unsigned char *const bufend = &buf[sizeof(buf)];
	unsigned char *estr = bufend;
	for (int r = e2 < 0 ? -e2 : e2; r; r /= 10) {
		*--estr = '0' + r % 10;
	}
	if (estr == bufend) {
		/* Exponent is 0. */
		*--estr = '0';
	}
	*--estr = (e2 < 0 ? '-' : '+');
	/* Binary exponent marker. */
	*--estr = 'p';

	do {
		const int i = (int)x;
		*s++ = xdigits[i];
		/* Extract the next hex digit. */
		x = 16 * (x - i);

		if (s - buf == 1 && x) {
			*s++ = '.';
		}
	} while (x);

	VBUF_APPEND(*pvbuf, p, pend - p);
	VBUF_APPEND(*pvbuf, buf, s - buf);
	VBUF_APPEND(*pvbuf, estr, bufend - estr);
}

#define IDX_BUFFER (lua_upvalueindex(1))
#define IDX_VISITED (lua_upvalueindex(2))
#define IDX_MARSHAL (lua_upvalueindex(3))

/* marshal a table into constructor syntax: {value1,value2,[key]=value,...} */
static void
marshal_table(lua_State *restrict L, struct vbuffer *restrict *restrict pvbuf)
{
	const int idx = 1;

	lua_pushvalue(L, idx);
	if (lua_rawget(L, IDX_VISITED) != LUA_TNIL) {
		lua_pushliteral(
			L, "circular referenced table is not marshallable");
		lua_error(L);
		return;
	}

	lua_pushvalue(L, idx);
	lua_pushboolean(L, 1);
	lua_rawset(L, IDX_VISITED);

	VBUF_APPENDSTR(*pvbuf, "{");
	/* consecutive integer keys from 1 use array syntax */
	lua_Integer i = 1;
	while (lua_next(L, idx) != 0) {
		if (lua_isinteger(L, -2) && lua_tointeger(L, -2) == i) {
			/* Increment the expected index. */
			i = luaL_intop(+, i, 1);
		} else {
			VBUF_APPENDSTR(*pvbuf, "[");
			lua_pushvalue(L, IDX_MARSHAL);
			/* Push key. */
			lua_pushvalue(L, -3);
			lua_call(L, 1, 0);
			VBUF_APPENDSTR(*pvbuf, "]=");
		}

		lua_pushvalue(L, IDX_MARSHAL);
		/* Push value. */
		lua_pushvalue(L, -2);
		lua_call(L, 1, 0);

		VBUF_APPENDSTR(*pvbuf, ",");
		/* Remove the value and keep the key for the next iteration. */
		lua_pop(L, 1);
	}
	VBUF_APPENDSTR(*pvbuf, "}");
}

static int marshal_value(lua_State *restrict L)
{
	const int idx = 1;
	struct vbuffer *restrict *restrict pvbuf =
		(struct vbuffer *restrict *restrict)lua_touserdata(
			L, IDX_BUFFER);
	const int type = lua_type(L, idx);

	switch (type) {
	case LUA_TNIL:
		VBUF_APPENDSTR(*pvbuf, "nil");
		break;

	case LUA_TBOOLEAN:
		if (lua_toboolean(L, idx)) {
			VBUF_APPENDSTR(*pvbuf, "true");
		} else {
			VBUF_APPENDSTR(*pvbuf, "false");
		}
		break;

	case LUA_TNUMBER:
		marshal_number(L, pvbuf);
		break;

	case LUA_TSTRING:
		marshal_string(L, pvbuf);
		break;

	case LUA_TTABLE:
#if HAVE_LUA_WARNING
		/* metatables are not marshalled */
		if (lua_getmetatable(L, idx)) {
			lua_warning(L, "marshal: ", 1);
			lua_warning(L, luaL_tolstring(L, idx, NULL), 1);
			lua_warning(L, " has a metatable", 0);
			lua_pop(L, 1);
		}
#endif
		marshal_table(L, pvbuf);
		break;

	default:
		return luaL_error(
			L, "%s is not marshallable",
			luaL_tolstring(L, idx, NULL));
	}

	if (VBUF_HAS_OOM(*pvbuf)) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}

	return 0;
}

/* marshal(...): marshal values into a comma-separated string
 * that can be loaded back by Lua */
int api_marshal(lua_State *restrict L)
{
	const int n = lua_gettop(L);

	if (n < 1) {
		lua_pushliteral(L, "");
		return 1;
	}

	struct vbuffer *restrict *restrict pvbuf =
		lua_newuserdata(L, sizeof(struct vbuffer *));
	*pvbuf = NULL;
	aux_toclose(L, -1, MT_MARSHAL_BUFFER, marshal_buffer_close);

	*pvbuf = VBUF_NEW(1024);
	if (*pvbuf == NULL) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}

	/* lua stack: args... buffer */

	/* IDX_BUFFER: buffer userdata */
	lua_pushvalue(L, -1);
	/* IDX_VISITED: visited table */
	lua_createtable(L, 0, 16);
	/* IDX_MARSHAL: placeholder for self-reference */
	lua_pushnil(L);
	lua_pushcclosure(L, marshal_value, 3);

	/* Set up self-reference for recursive calls */
	lua_pushvalue(L, -1);
	const char *upvalue = lua_setupvalue(L, -2, 3);
	ASSERT(upvalue != NULL);
	UNUSED(upvalue);

	/* lua stack: args... buffer closure */

	int i = 1;
	for (; i < n; i++) {
		/* Push closure. */
		lua_pushvalue(L, -1);
		/* Push argument. */
		lua_pushvalue(L, i);
		lua_call(L, 1, 0);

		VBUF_APPENDSTR(*pvbuf, ",");
	}

	/* Marshal the final argument without a trailing comma */
	if (i == n) {
		/* Push argument. */
		lua_pushvalue(L, i);
		/* Call the closure with the argument. */
		lua_call(L, 1, 0);
	}

	lua_pushlstring(L, VBUF_DATA(*pvbuf), VBUF_LEN(*pvbuf));
	/* Clean up the buffer. */
	aux_close(L, n + 1);
	return 1;
}

int luaopen_marshal(lua_State *restrict L)
{
	lua_pushcfunction(L, api_marshal);
	return 1;
}
