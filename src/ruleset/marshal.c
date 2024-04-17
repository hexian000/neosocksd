/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "marshal.h"

#include "io/io.h"

#include "lauxlib.h"
#include "lua.h"

#include <ctype.h>
#include <tgmath.h>

#define MT_MARSHAL_CACHE "marshal.cache"

#define luaL_addliteral(B, s) luaL_addlstring((B), ("" s), sizeof(s) - 1)

static void
marshal_string(lua_State *restrict L, luaL_Buffer *restrict B, const int idx)
{
	size_t len;
	const char *restrict s = lua_tolstring(L, idx, &len);
	luaL_addchar(B, '"');
	while (len--) {
		const unsigned char ch = *s;
		if (ch == '"' || ch == '\\' || ch == '\n') {
			char buf[2] = { '\\', ch };
			luaL_addlstring(B, buf, sizeof(buf));
		} else if (iscntrl(ch)) {
			char buf[4];
			char *s = &buf[sizeof(buf)];
			uint_fast8_t x = ch;
			*--s = '0' + x % 10, x /= 10;
			*--s = '0' + x % 10, x /= 10;
			*--s = '0' + x % 10;
			*--s = '\\';
			luaL_addlstring(B, buf, sizeof(buf));
		} else {
			luaL_addchar(B, ch);
		}
		s++;
	}
	luaL_addchar(B, '"');
}

static void
marshal_number(lua_State *restrict L, luaL_Buffer *restrict B, const int idx)
{
	static const char prefix[3] = "-0x";
	static const char xdigits[16] = "0123456789abcdef";
	char buf[120];
	if (lua_isinteger(L, idx)) {
		lua_Integer x = lua_tointeger(L, idx);
		char *const bufend = &buf[sizeof(buf)];
		char *s = bufend;
		if (x == 0) {
			luaL_addchar(B, '0');
			return;
		}
		if (x < 0 && x != LUA_MININTEGER) {
			x = -x;
			luaL_addlstring(B, prefix, sizeof(prefix));
		} else {
			luaL_addlstring(B, prefix + 1, sizeof(prefix) - 1);
		}
		for (lua_Unsigned y = x; y; y >>= 4) {
			*--s = xdigits[(y & 0xf)];
		}
		luaL_addlstring(B, s, bufend - s);
		return;
	}
	lua_Number x = lua_tonumber(L, idx);
	switch (fpclassify(x)) {
	case FP_NAN:
		luaL_addliteral(B, "0/0");
		return;
	case FP_INFINITE:
		if (signbit(x)) {
			luaL_addliteral(B, "-1/0");
			return;
		}
		luaL_addliteral(B, "1/0");
		return;
	case FP_ZERO:
		luaL_addchar(B, '0');
		return;
	default:
		break;
	}
	char *s = buf;
	/* prefix */
	if (signbit(x)) {
		x = -x;
		luaL_addlstring(B, prefix, sizeof(prefix));
	} else {
		luaL_addlstring(B, prefix + 1, sizeof(prefix) - 1);
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
	const size_t len = (size_t)(s - buf);
	luaL_addlstring(B, buf, len);
	const size_t elen = (size_t)(bufend - estr);
	luaL_addlstring(B, estr, elen);
}

static void marshal_value(
	lua_State *restrict L, luaL_Buffer *restrict B, const int idx,
	const int depth)
{
	if (depth > 200) {
		lua_pushliteral(L, "table is too complex to marshal");
		(void)lua_error(L);
		return;
	}
	const int type = lua_type(L, idx);
	switch (type) {
	case LUA_TNIL:
		luaL_addliteral(B, "nil");
		return;
	case LUA_TBOOLEAN:
		if (lua_toboolean(L, idx)) {
			luaL_addliteral(B, "true");
			return;
		}
		luaL_addliteral(B, "false");
		return;
	case LUA_TNUMBER:
		marshal_number(L, B, idx);
		return;
	case LUA_TSTRING:
		marshal_string(L, B, idx);
		return;
	case LUA_TTABLE:
		break;
	default:
		luaL_error(L, "%s is not marshallable", lua_typename(L, type));
		return;
	}
	/* check closed */
	lua_pushvalue(L, idx);
	if (lua_rawget(L, 2) != LUA_TNIL) {
		luaL_addvalue(B);
		return;
	}
	/* check open */
	lua_pushvalue(L, idx);
	if (lua_rawget(L, 1) != LUA_TNIL) {
		luaL_error(L, "circular referenced table is not marshallable");
		return;
	}
	lua_pop(L, 1);
	/* mark as open */
	lua_pushvalue(L, idx);
	lua_pushboolean(L, 1);
	lua_rawset(L, 1);
	/* marshal the table */
	luaL_Buffer b;
	luaL_buffinit(L, &b);
	luaL_addchar(&b, '{');
	/* auto index */
	lua_Integer n = 0;
	for (lua_Integer i = 1; lua_rawgeti(L, idx, i) != LUA_TNIL; i++) {
		marshal_value(L, &b, -1, depth + 1);
		luaL_addchar(&b, ',');
		lua_pop(L, 1);
		n = i;
		if (i == LUA_MAXINTEGER) {
			lua_pushnil(L);
			break;
		}
	}
	/* explicit index */
	while (lua_next(L, idx) != 0) {
		if (lua_isinteger(L, -2)) {
			const lua_Integer i = lua_tointeger(L, -2);
			if (1 <= i && i <= n) {
				/* already marshalled */
				lua_pop(L, 1);
				continue;
			}
		}
		luaL_addchar(&b, '[');
		marshal_value(L, &b, -2, depth + 1);
		luaL_addliteral(&b, "]=");
		marshal_value(L, &b, -1, depth + 1);
		luaL_addchar(&b, ',');
		lua_pop(L, 1);
	}
	lua_pop(L, 1);
	luaL_addchar(&b, '}');
	luaL_pushresult(&b);
	/* save as closed */
	lua_pushvalue(L, idx);
	lua_pushvalue(L, -2);
	lua_rawset(L, 2);
	luaL_addvalue(B);
}

/* s = marshal(...) */
int api_marshal_(lua_State *restrict L)
{
	const int n = lua_gettop(L);
	/* open */
	lua_newtable(L);
	/* closed */
	lua_newtable(L);
	if (luaL_newmetatable(L, MT_MARSHAL_CACHE)) {
		lua_pushliteral(L, "kv");
		lua_setfield(L, -2, "__mode");
	}
	lua_setmetatable(L, -2);
	lua_rotate(L, 1, 2);
	luaL_Buffer b;
	luaL_buffinitsize(L, &b, IO_BUFSIZE);
	for (int i = 3; i <= 2 + n; i++) {
		if (i > 3) {
			luaL_addchar(&b, ',');
		}
		marshal_value(L, &b, i, 0);
	}
	luaL_pushresult(&b);
	return 1;
}
