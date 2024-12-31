/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "marshal.h"

#include "utils/buffer.h"

#include "ruleset/base.h"

#include "lauxlib.h"
#include "lua.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <tgmath.h>

#define HAVE_LUA_WARNING (LUA_VERSION_NUM >= 504)
#define HAVE_LUA_TOCLOSE (LUA_VERSION_NUM >= 504)

#define MT_MARSHAL_CONTEXT "marshal_context"

#define MAX_DEPTH 200

struct marshal_context {
	struct vbuffer *vbuf;
	lua_State *L;
	int idx_visited;
	int depth;
};

static int marshal_context_close(lua_State *restrict L)
{
	struct marshal_context *restrict m = lua_touserdata(L, 1);
	m->vbuf = VBUF_FREE(m->vbuf);
	return 0;
}

/* [-0, +0, v] */
static void marshal_value(struct marshal_context *m, int idx);

/* [-0, +0, -] */
static void marshal_string(struct marshal_context *restrict m, const int idx)
{
	lua_State *restrict L = m->L;
	size_t len;
	const char *restrict str = lua_tolstring(L, idx, &len);
	m->vbuf = VBUF_APPENDSTR(m->vbuf, "\"");
	while (len--) {
		const unsigned char ch = *str;
		if (ch == '"' || ch == '\\' || ch == '\n') {
			char buf[2] = { '\\', ch };
			m->vbuf = VBUF_APPEND(m->vbuf, buf, sizeof(buf));
		} else if (iscntrl(ch)) {
			char buf[4];
			char *s = &buf[sizeof(buf)];
			uint_fast8_t x = ch;
			*--s = '0' + x % 10, x /= 10;
			*--s = '0' + x % 10, x /= 10;
			*--s = '0' + x % 10;
			*--s = '\\';
			m->vbuf = VBUF_APPEND(m->vbuf, buf, sizeof(buf));
		} else {
			m->vbuf = VBUF_APPEND(m->vbuf, &ch, sizeof(ch));
		}
		str++;
	}
	m->vbuf = VBUF_APPENDSTR(m->vbuf, "\"");
}

/* [-0, +0, -] */
static void marshal_number(struct marshal_context *restrict m, const int idx)
{
	lua_State *restrict L = m->L;
	static const char prefix[3] = "-0x";
	static const char xdigits[16] = "0123456789abcdef";
	char buf[120];
	if (lua_isinteger(L, idx)) {
		lua_Integer x = lua_tointeger(L, idx);
		char *const bufend = &buf[sizeof(buf)];
		char *s = bufend;
		if (x == 0) {
			m->vbuf = VBUF_APPENDSTR(m->vbuf, "0");
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
		m->vbuf = VBUF_APPEND(m->vbuf, s, bufend - s);
		return;
	}
	lua_Number x = lua_tonumber(L, idx);
	switch (fpclassify(x)) {
	case FP_NAN:
		m->vbuf = VBUF_APPENDSTR(m->vbuf, "0/0");
		return;
	case FP_INFINITE:
		if (signbit(x)) {
			m->vbuf = VBUF_APPENDSTR(m->vbuf, "-1/0");
			return;
		}
		m->vbuf = VBUF_APPENDSTR(m->vbuf, "1/0");
		return;
	case FP_ZERO:
		m->vbuf = VBUF_APPENDSTR(m->vbuf, "0");
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

	m->vbuf = VBUF_APPEND(m->vbuf, p, pend - p);
	m->vbuf = VBUF_APPEND(m->vbuf, buf, s - buf);
	m->vbuf = VBUF_APPEND(m->vbuf, estr, bufend - estr);
}

/* [-0, +0, m] */
static void marshal_table(struct marshal_context *restrict m, const int idx)
{
	lua_State *restrict L = m->L;
	if (m->depth > MAX_DEPTH) {
		lua_pushliteral(L, "table is too complex to marshal");
		lua_error(L);
		return;
	}
	/* check visited */
	lua_pushvalue(L, idx);
	if (lua_rawget(L, m->idx_visited) != LUA_TNIL) {
		lua_pushliteral(
			L, "circular referenced table is not marshallable");
		lua_error(L);
		return;
	}
	/* mark as visited */
	lua_pushvalue(L, idx);
	lua_pushboolean(L, 1);
	lua_rawset(L, m->idx_visited);
	/* marshal the table */
	m->depth++;
	m->vbuf = VBUF_APPENDSTR(m->vbuf, "{");
	/* auto index */
	lua_Integer i = 1;
	while (lua_next(L, idx) != 0) {
		if (lua_isinteger(L, -2) && lua_tointeger(L, -2) == i) {
			i = luaL_intop(+, i, 1);
		} else {
			m->vbuf = VBUF_APPENDSTR(m->vbuf, "[");
			marshal_value(m, lua_absindex(L, -2));
			m->vbuf = VBUF_APPENDSTR(m->vbuf, "]=");
		}
		marshal_value(m, lua_absindex(L, -1));
		m->vbuf = VBUF_APPENDSTR(m->vbuf, ",");
		lua_pop(L, 1);
	}
	m->vbuf = VBUF_APPENDSTR(m->vbuf, "}");
	m->depth--;
}

static void marshal_value(struct marshal_context *restrict m, const int idx)
{
	lua_State *restrict L = m->L;
	const int type = lua_type(L, idx);
	switch (type) {
	case LUA_TNIL:
		m->vbuf = VBUF_APPENDSTR(m->vbuf, "nil");
		break;
	case LUA_TBOOLEAN:
		if (lua_toboolean(L, idx)) {
			m->vbuf = VBUF_APPENDSTR(m->vbuf, "true");
		} else {
			m->vbuf = VBUF_APPENDSTR(m->vbuf, "false");
		}
		break;
	case LUA_TNUMBER:
		marshal_number(m, idx);
		break;
	case LUA_TSTRING:
		marshal_string(m, idx);
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
		marshal_table(m, idx);
		break;
	default:
		luaL_error(
			L, "%s is not marshallable",
			luaL_tolstring(L, idx, NULL));
		return;
	}
	/* VBUF_APPEND* will always reserve 1 extra byte */
	if (VBUF_REMAINING(m->vbuf) == 0) {
		lua_pushliteral(m->L, ERR_MEMORY);
		lua_error(m->L);
		return;
	}
}

/* s = marshal(...) */
int api_marshal(lua_State *restrict L)
{
	const int n = lua_gettop(L);
	if (n < 1) {
		lua_pushliteral(L, "");
		return 1;
	}
	struct marshal_context *restrict m =
		lua_newuserdata(L, sizeof(struct marshal_context));
	if (luaL_newmetatable(L, MT_MARSHAL_CONTEXT)) {
		lua_pushcfunction(L, marshal_context_close);
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
	m->vbuf = VBUF_NEW(1024);
	if (m->vbuf == NULL) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	m->L = L;
	/* visited */
	lua_createtable(L, 0, 16);
	m->idx_visited = lua_absindex(L, -1);
	m->depth = 1;
	/* co stack: visited ... */
	for (int i = 1; i <= n; i++) {
		if (i > 1) {
			m->vbuf = VBUF_APPENDSTR(m->vbuf, ",");
		}
		marshal_value(m, i);
	}
	lua_pushlstring(L, VBUF_DATA(m->vbuf), VBUF_LEN(m->vbuf));
	m->vbuf = VBUF_FREE(m->vbuf);
	return 1;
}

int luaopen_marshal(lua_State *restrict L)
{
	lua_pushcfunction(L, api_marshal);
	return 1;
}
