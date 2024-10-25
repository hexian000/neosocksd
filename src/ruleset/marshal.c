/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "marshal.h"

#include "lauxlib.h"
#include "lua.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <tgmath.h>

#define luaL_addliteral(B, s) luaL_addlstring((B), ("" s), sizeof(s) - 1)

/* [-0, +1, m] */
static void marshal_string(lua_State *restrict L, const int idx)
{
	lua_pushnil(L);
	const int ridx = lua_absindex(L, -1);
	size_t len;
	const char *restrict str = lua_tolstring(L, idx, &len);
	luaL_Buffer b;
	luaL_buffinit(L, &b);
	luaL_addchar(&b, '"');
	while (len--) {
		const unsigned char ch = *str;
		if (ch == '"' || ch == '\\' || ch == '\n') {
			char buf[2] = { '\\', ch };
			luaL_addlstring(&b, buf, sizeof(buf));
		} else if (iscntrl(ch)) {
			char buf[4];
			char *s = &buf[sizeof(buf)];
			uint_fast8_t x = ch;
			*--s = '0' + x % 10, x /= 10;
			*--s = '0' + x % 10, x /= 10;
			*--s = '0' + x % 10;
			*--s = '\\';
			luaL_addlstring(&b, buf, sizeof(buf));
		} else {
			luaL_addchar(&b, ch);
		}
		str++;
	}
	luaL_addchar(&b, '"');
	luaL_pushresult(&b);
	lua_copy(L, -1, ridx);
	lua_settop(L, ridx);
}

/* [-0, +1, m] */
static void marshal_number(lua_State *restrict L, const int idx)
{
	static const char prefix[3] = "-0x";
	static const char xdigits[16] = "0123456789abcdef";
	char buf[120];
	if (lua_isinteger(L, idx)) {
		lua_Integer x = lua_tointeger(L, idx);
		char *const bufend = &buf[sizeof(buf)];
		char *s = bufend;
		if (x == 0) {
			lua_pushliteral(L, "0");
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
		while (p < pend) {
			*--s = *--pend;
		}
		lua_pushlstring(L, s, bufend - s);
		return;
	}
	lua_Number x = lua_tonumber(L, idx);
	switch (fpclassify(x)) {
	case FP_NAN:
		lua_pushliteral(L, "0/0");
		return;
	case FP_INFINITE:
		if (signbit(x)) {
			lua_pushliteral(L, "-1/0");
			return;
		}
		lua_pushliteral(L, "1/0");
		return;
	case FP_ZERO:
		lua_pushliteral(L, "0");
		return;
	default:
		break;
	}
	lua_pushnil(L);
	const int ridx = lua_absindex(L, -1);
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

	luaL_Buffer b;
	luaL_buffinit(L, &b);
	luaL_addlstring(&b, p, pend - p);
	luaL_addlstring(&b, buf, s - buf);
	luaL_addlstring(&b, estr, bufend - estr);
	luaL_pushresult(&b);
	lua_copy(L, -1, ridx);
	lua_settop(L, ridx);
}

/* [-0, +1, m] */
static void marshal_value(lua_State *restrict L, const int idx, const int depth)
{
	if (depth > 200) {
		lua_pushliteral(L, "table is too complex to marshal");
		lua_error(L);
		return;
	}
	const int type = lua_type(L, idx);
	switch (type) {
	case LUA_TNIL:
		lua_pushliteral(L, "nil");
		return;
	case LUA_TBOOLEAN:
		if (lua_toboolean(L, idx)) {
			lua_pushliteral(L, "true");
			return;
		}
		lua_pushliteral(L, "false");
		return;
	case LUA_TNUMBER:
		marshal_number(L, idx);
		return;
	case LUA_TSTRING:
		marshal_string(L, idx);
		return;
	case LUA_TTABLE:
#if HAVE_LUA_WARNING
		if (lua_getmetatable(L, idx)) {
			lua_warning(L, "marshal: ", 1);
			lua_warning(L, luaL_tolstring(L, idx, NULL), 1);
			lua_warning(L, " has a metatable", 0);
			lua_pop(L, 1);
		}
#endif
		break;
	default:
		luaL_error(
			L, "%s is not marshallable",
			luaL_tolstring(L, idx, NULL));
		return;
	}
	lua_pushnil(L);
	const int ridx = lua_absindex(L, -1);
	/* check cached */
	lua_pushvalue(L, idx);
	if (lua_rawget(L, 2) != LUA_TNIL) {
		return;
	}
	lua_pop(L, 1);
	/* check visited */
	lua_pushvalue(L, idx);
	if (lua_rawget(L, 1) != LUA_TNIL) {
		lua_pushliteral(
			L, "circular referenced table is not marshallable");
		lua_error(L);
		return;
	}
	lua_pop(L, 1);
	/* mark as visited */
	lua_pushvalue(L, idx);
	lua_pushboolean(L, 1);
	lua_rawset(L, 1);
	/* marshal the table */
	lua_pushnil(L);
	lua_pushnil(L);
	const int kidx = lua_absindex(L, -2);
	const int vidx = lua_absindex(L, -1);
	luaL_Buffer b;
	luaL_buffinit(L, &b);
	luaL_addchar(&b, '{');
	/* auto index */
	lua_Integer n = 0;
	for (lua_Unsigned i = 1;
	     lua_rawgeti(L, idx, (lua_Integer)i) != LUA_TNIL; i++) {
		lua_copy(L, -1, vidx);
		lua_pop(L, 1);
		marshal_value(L, vidx, depth + 1);
		luaL_addvalue(&b);
		luaL_addchar(&b, ',');
		n = i;
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
		lua_copy(L, -2, kidx);
		lua_copy(L, -1, vidx);
		lua_pop(L, 2);
		luaL_addchar(&b, '[');
		marshal_value(L, kidx, depth + 1);
		luaL_addvalue(&b);
		luaL_addliteral(&b, "]=");
		marshal_value(L, vidx, depth + 1);
		luaL_addvalue(&b);
		luaL_addchar(&b, ',');
		lua_pushvalue(L, kidx);
	}
	luaL_addchar(&b, '}');
	luaL_pushresult(&b);
	lua_copy(L, -1, ridx);
	/* save as cached */
	lua_pushvalue(L, idx);
	lua_pushvalue(L, -2);
	lua_rawset(L, 2);
	/* return */
	lua_settop(L, ridx);
}

/* s = marshal(...) */
int api_marshal(lua_State *restrict L)
{
	const int n = lua_gettop(L);
	/* visited */
	lua_newtable(L);
	/* cached */
	lua_newtable(L);
	/* cached_mt */
	lua_newtable(L);
	lua_pushliteral(L, "kv");
	lua_setfield(L, -2, "__mode");
	lua_setmetatable(L, -2);
	lua_rotate(L, 1, 2);

	luaL_Buffer b;
	luaL_buffinit(L, &b);
	/* visited cached ... <buffer?> */
	for (int i = 3; i <= 2 + n; i++) {
		if (i > 3) {
			luaL_addchar(&b, ',');
		}
		marshal_value(L, i, 0);
		luaL_addvalue(&b);
	}
	luaL_pushresult(&b);
	return 1;
}
