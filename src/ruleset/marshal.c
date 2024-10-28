/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "marshal.h"

#include "ruleset/base.h"
#include "utils/debug.h"

#include "lauxlib.h"
#include "lua.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <tgmath.h>

#define HAVE_LUA_WARNING (LUA_VERSION_NUM >= 504)

#define luaL_addliteral(B, s) luaL_addlstring((B), ("" s), sizeof(s) - 1)

/* [-0, +0, m] */
static void
marshal_string(luaL_Buffer *restrict B, lua_State *restrict L, const int idx)
{
	size_t len;
	const char *restrict str = lua_tolstring(L, idx, &len);
	luaL_addchar(B, '"');
	while (len--) {
		const unsigned char ch = *str;
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
		str++;
	}
	luaL_addchar(B, '"');
}

/* [-0, +0, m] */
static void
marshal_number(luaL_Buffer *restrict B, lua_State *restrict L, const int idx)
{
	static const char prefix[3] = "-0x";
	static const char xdigits[16] = "0123456789abcdef";
	char buf[120];
	if (lua_isinteger(L, idx)) {
		lua_Integer x = lua_tointeger(L, idx);
		char *const bufend = &buf[sizeof(buf)];
		char *s = bufend;
		if (x == 0) {
			luaL_addliteral(B, "0");
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
		luaL_addliteral(B, "0");
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

	luaL_addlstring(B, p, pend - p);
	luaL_addlstring(B, buf, s - buf);
	luaL_addlstring(B, estr, bufend - estr);
}

enum {
	IDX_VISITED = 1,
};

/* [-0, +0, m] */
static void marshal_value(
	luaL_Buffer *restrict B, lua_State *restrict L, const int idx,
	const int depth)
{
	if (depth > 200) {
		lua_pushliteral(L, "table is too complex to marshal");
		lua_error(L);
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
		marshal_number(B, L, idx);
		return;
	case LUA_TSTRING:
		marshal_string(B, L, idx);
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

	/* check visited */
	lua_pushvalue(L, idx);
	if (lua_rawget(L, IDX_VISITED) != LUA_TNIL) {
		lua_pushliteral(
			L, "circular referenced table is not marshallable");
		lua_error(L);
		return;
	}
	lua_pop(L, 1);
	/* mark as visited */
	lua_pushvalue(L, idx);
	lua_pushboolean(L, 1);
	lua_rawset(L, IDX_VISITED);
	/* marshal the table */
	luaL_addchar(B, '{');
	/* auto index */
	lua_Integer n = 0;
	for (lua_Unsigned i = 1;
	     lua_rawgeti(L, idx, (lua_Integer)i) != LUA_TNIL; i++) {
		marshal_value(B, L, lua_absindex(L, -1), depth + 1);
		lua_pop(L, 1);
		luaL_addchar(B, ',');
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
		luaL_addchar(B, '[');
		marshal_value(B, L, lua_absindex(L, -2), depth + 1);
		luaL_addliteral(B, "]=");
		marshal_value(B, L, lua_absindex(L, -1), depth + 1);
		luaL_addchar(B, ',');
		lua_pop(L, 1);
	}
	luaL_addchar(B, '}');
}

/* s = marshal(...) */
int api_marshal(lua_State *restrict L)
{
	const int n = lua_gettop(L);
	lua_State *restrict co = lua_tothread(L, lua_upvalueindex(1));
	ASSERT(co != NULL);
	lua_settop(co, 0);
	luaL_checkstack(co, 1 + n, NULL);
	/* visited */
	lua_newtable(co);
	lua_xmove(L, co, n);

	luaL_Buffer b;
	luaL_buffinit(L, &b);
	/* co stack: visited ... */
	for (int i = 1; i <= n; i++) {
		if (i > 1) {
			luaL_addchar(&b, ',');
		}
		marshal_value(&b, co, 1 + i, 0);
	}
	luaL_pushresult(&b);
	return 1;
}

int luaopen_marshal(lua_State *restrict L)
{
	(void)lua_newthread(L);
	lua_pushcclosure(L, api_marshal, 1);
	return 1;
}
