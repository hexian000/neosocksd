/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "marshal.h"

#include "utils/buffer.h"
#include "utils/debug.h"

#include "ruleset/base.h"

#include "lauxlib.h"
#include "lua.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <tgmath.h>

#define HAVE_LUA_WARNING (LUA_VERSION_NUM >= 504)
#define HAVE_LUA_TOCLOSE (LUA_VERSION_NUM >= 504)

#define MT_MARSHAL_BUFFER "marshal_buffer"

static int marshal_buffer_gc(lua_State *restrict L)
{
	struct vbuffer **pvbuf = lua_touserdata(L, 1);
	*pvbuf = VBUF_FREE(*pvbuf);
	return 0;
}

/* [-0, +0, -] */
static void marshal_string(lua_State *L, struct vbuffer **pvbuf)
{
	const int idx = 1;
	size_t len;
	const char *restrict str = lua_tolstring(L, idx, &len);
	*pvbuf = VBUF_APPENDSTR(*pvbuf, "\"");
	while (len--) {
		const unsigned char ch = *str;
		if (ch == '"' || ch == '\\' || ch == '\n') {
			char buf[2] = { '\\', ch };
			*pvbuf = VBUF_APPEND(*pvbuf, buf, sizeof(buf));
		} else if (iscntrl(ch)) {
			char buf[4];
			char *s = &buf[sizeof(buf)];
			uint_fast8_t x = ch;
			*--s = '0' + x % 10, x /= 10;
			*--s = '0' + x % 10, x /= 10;
			*--s = '0' + x % 10;
			*--s = '\\';
			*pvbuf = VBUF_APPEND(*pvbuf, buf, sizeof(buf));
		} else {
			*pvbuf = VBUF_APPEND(*pvbuf, &ch, sizeof(ch));
		}
		str++;
	}
	*pvbuf = VBUF_APPENDSTR(*pvbuf, "\"");
}

/* [-0, +0, -] */
static void marshal_number(lua_State *L, struct vbuffer **pvbuf)
{
	const int idx = 1;
	static const char prefix[3] = "-0x";
	static const char xdigits[16] = "0123456789abcdef";
	char buf[120];
	if (lua_isinteger(L, idx)) {
		lua_Integer x = lua_tointeger(L, idx);
		char *const bufend = &buf[sizeof(buf)];
		char *s = bufend;
		if (x == 0) {
			*pvbuf = VBUF_APPENDSTR(*pvbuf, "0");
			return;
		}
		const char *p = prefix;
		const char *pend = prefix + sizeof(prefix);
		if (x < 0 && x != LUA_MININTEGER) {
			x = -x;
		} else {
			p++;
		}
		lua_Unsigned y = x;
		if (y <= UINTMAX_C(999999999999)) {
			pend -= 2;
			do {
				*--s = '0' + y % 10;
				y /= 10;
			} while (y);
		} else {
			/* hexadecimal is shorter */
			do {
				*--s = xdigits[(y & 0xf)];
				y >>= 4;
			} while (y);
		}
		*pvbuf = VBUF_APPEND(*pvbuf, p, pend - p);
		*pvbuf = VBUF_APPEND(*pvbuf, s, bufend - s);
		return;
	}
	lua_Number x = lua_tonumber(L, idx);
	switch (fpclassify(x)) {
	case FP_NAN:
		*pvbuf = VBUF_APPENDSTR(*pvbuf, "0/0");
		return;
	case FP_INFINITE:
		if (signbit(x)) {
			*pvbuf = VBUF_APPENDSTR(*pvbuf, "-1/0");
			return;
		}
		*pvbuf = VBUF_APPENDSTR(*pvbuf, "1/0");
		return;
	case FP_ZERO:
		*pvbuf = VBUF_APPENDSTR(*pvbuf, "0");
		return;
	default:
		break;
	}
	char *s = buf;
	/* prefix */
	const char *p = prefix;
	const char *pend = prefix + sizeof(prefix);
	if (signbit(x)) {
		x = -x;
	} else {
		p++;
	}
	/* exponent */
	int e2 = 0;
	x = frexp(x, &e2) * 2;
	if (x) {
		e2--;
	}
	char *const bufend = &buf[sizeof(buf)];
	char *estr = bufend;
	for (int r = e2 < 0 ? -e2 : e2; r; r /= 10) {
		*--estr = '0' + r % 10;
	}
	if (estr == bufend) {
		*--estr = '0';
	}
	*--estr = (e2 < 0 ? '-' : '+');
	*--estr = 'p';
	/* mantissa */
	do {
		const int i = x;
		*s++ = xdigits[i];
		x = 16 * (x - i);
		if (s - buf == 1 && x) {
			*s++ = '.';
		}
	} while (x);

	*pvbuf = VBUF_APPEND(*pvbuf, p, pend - p);
	*pvbuf = VBUF_APPEND(*pvbuf, buf, s - buf);
	*pvbuf = VBUF_APPEND(*pvbuf, estr, bufend - estr);
}

#define IDX_BUFFER (lua_upvalueindex(1))
#define IDX_VISITED (lua_upvalueindex(2))
#define IDX_MARSHAL (lua_upvalueindex(3))

/* [-0, +0, m] */
static void marshal_table(lua_State *L, struct vbuffer **pvbuf)
{
	const int idx = 1;
	/* check visited */
	lua_pushvalue(L, idx);
	if (lua_rawget(L, IDX_VISITED) != LUA_TNIL) {
		lua_pushliteral(
			L, "circular referenced table is not marshallable");
		lua_error(L);
		return;
	}
	/* mark as visited */
	lua_pushvalue(L, idx);
	lua_pushboolean(L, 1);
	lua_rawset(L, IDX_VISITED);
	/* marshal the table */
	*pvbuf = VBUF_APPENDSTR(*pvbuf, "{");
	/* auto index */
	lua_Integer i = 1;
	while (lua_next(L, idx) != 0) {
		if (lua_isinteger(L, -2) && lua_tointeger(L, -2) == i) {
			i = luaL_intop(+, i, 1);
		} else {
			*pvbuf = VBUF_APPENDSTR(*pvbuf, "[");
			lua_pushvalue(L, IDX_MARSHAL);
			lua_pushvalue(L, -3);
			lua_call(L, 1, 0);
			*pvbuf = VBUF_APPENDSTR(*pvbuf, "]=");
		}
		lua_pushvalue(L, IDX_MARSHAL);
		lua_pushvalue(L, -2);
		lua_call(L, 1, 0);
		*pvbuf = VBUF_APPENDSTR(*pvbuf, ",");
		lua_pop(L, 1);
	}
	*pvbuf = VBUF_APPENDSTR(*pvbuf, "}");
}

/* [-0, +0, v] */
static int marshal_value(lua_State *L)
{
	const int idx = 1;
	struct vbuffer **pvbuf = lua_touserdata(L, IDX_BUFFER);
	const int type = lua_type(L, idx);
	switch (type) {
	case LUA_TNIL:
		*pvbuf = VBUF_APPENDSTR(*pvbuf, "nil");
		break;
	case LUA_TBOOLEAN:
		if (lua_toboolean(L, idx)) {
			*pvbuf = VBUF_APPENDSTR(*pvbuf, "true");
		} else {
			*pvbuf = VBUF_APPENDSTR(*pvbuf, "false");
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
	/* VBUF_APPEND* will always reserve 1 extra byte */
	if (VBUF_REMAINING(*pvbuf) == 0) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	return 0;
}

/* s = marshal(...) */
int api_marshal(lua_State *restrict L)
{
	const int n = lua_gettop(L);
	if (n < 1) {
		lua_pushliteral(L, "");
		return 1;
	}
	struct vbuffer **pvbuf = lua_newuserdata(L, sizeof(struct vbuffer *));
	*pvbuf = VBUF_NEW(1024);
	if (luaL_newmetatable(L, MT_MARSHAL_BUFFER)) {
		lua_pushcfunction(L, marshal_buffer_gc);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
	if (*pvbuf == NULL) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	/* build closure */
	/* Lua stack: ... IDX_BUFFER */
	lua_createtable(L, 0, 16); /* IDX_VISITED */
	lua_pushnil(L); /* IDX_MARSHAL */
	lua_pushcclosure(L, marshal_value, 3);
	lua_pushvalue(L, -1);
	CHECK(lua_setupvalue(L, -2, 3) != NULL);
	/* co stack: visited ... */
	int i = 1;
	for (; i < n; i++) {
		lua_pushvalue(L, -1); /* the closure */
		lua_pushvalue(L, i);
		lua_call(L, 1, 0);
		*pvbuf = VBUF_APPENDSTR(*pvbuf, ",");
	}
	if (i == n) {
		lua_pushvalue(L, i);
		lua_call(L, 1, 0);
	}
	lua_pushlstring(L, VBUF_DATA(*pvbuf), VBUF_LEN(*pvbuf));
	*pvbuf = VBUF_FREE(*pvbuf);
	return 1;
}

int luaopen_marshal(lua_State *restrict L)
{
	lua_pushcfunction(L, api_marshal);
	return 1;
}
