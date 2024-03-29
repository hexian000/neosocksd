/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset.h"

#if WITH_RULESET

#include "codec.h"
#include "conf.h"
#include "dialer.h"
#include "http_client.h"
#include "resolver.h"
#include "server.h"
#include "sockutil.h"
#include "util.h"

#include "io/io.h"
#include "io/memory.h"
#include "io/stream.h"
#include "net/addr.h"
#include "utils/arraysize.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/serialize.h"
#include "utils/slog.h"

#include "lauxlib.h"
#include "lua.h"
#include "luaconf.h"
#include "lualib.h"

#include <arpa/inet.h>
#include <ev.h>
#include <netinet/in.h>
#include <regex.h>

#include <assert.h>
#include <ctype.h>
#include <locale.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tgmath.h>

struct ruleset {
	struct ev_loop *loop;
	struct ruleset_vmstats vmstats;
	lua_State *L;
	struct ev_timer w_ticker;
};

#if LUA_VERSION_NUM >= 504
#define HAVE_LUA_TOCLOSE 1
#define co_resume lua_resume
#elif LUA_VERSION_NUM == 503
#define LUA_LOADED_TABLE "_LOADED"
static int co_resume(lua_State *L, lua_State *from, int narg, int *nres)
{
	const int status = lua_resume(L, from, narg);
	*nres = lua_gettop(L);
	return status;
}
#endif

#define luaL_addliteral(B, s) luaL_addlstring((B), ("" s), sizeof(s) - 1)

#define CONST_LSTRING(s, len)                                                  \
	((len) != NULL ? (*(len) = sizeof(s) - 1, "" s) : ("" s))

enum ruleset_ridx {
	RIDX_ERRORS = LUA_RIDX_LAST + 1,
	RIDX_FUNCTIONS = LUA_RIDX_LAST + 2,
	RIDX_CONTEXTS = LUA_RIDX_LAST + 3,
};

#define ERR_MEMORY "out of memory"
#define ERR_BAD_REGISTRY "Lua registry is corrupted"
#define ERR_NOT_YIELDABLE "await cannot be used in non-yieldable context"
#define ERR_INVALID_ROUTE "unable to parse route"

#define MT_MARSHAL_CACHE "marshal.cache"
#define MT_AWAIT_IDLE "await.idle"
#define MT_AWAIT_SLEEP "await.sleep"
#define MT_AWAIT_RESOLVE "await.resolve"
#define MT_AWAIT_RPCALL "await.invoke"
#define MT_REGEX "regex"
#define MT_STREAM_CONTEXT "stream_context"

static struct ruleset *find_ruleset(lua_State *L)
{
	void *ud;
	lua_Alloc allocf = lua_getallocf(L, &ud);
	(void)allocf, assert(allocf != NULL);
	return ud;
}

static void find_callback(lua_State *restrict L, const int idx)
{
	assert(idx > 0);
	const char *func = lua_topointer(L, idx);
	(void)lua_getglobal(L, "ruleset");
	(void)lua_getfield(L, -1, func);
	lua_replace(L, idx);
	lua_pop(L, 1);
}

static struct dialreq *pop_dialreq(lua_State *restrict L, const int n)
{
	if (n < 1) {
		return NULL;
	}
	const size_t nproxy = (size_t)(n - 1);
	struct dialreq *req = dialreq_new(nproxy);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	size_t len;
	for (size_t i = 0; i <= nproxy; i++) {
		const char *s = lua_tolstring(L, -1, &len);
		if (s == NULL) {
			dialreq_free(req);
			return NULL;
		}
		if (i < nproxy) {
			if (!dialreq_addproxy(req, s, len)) {
				dialreq_free(req);
				return NULL;
			}
		} else {
			if (!dialaddr_parse(&req->addr, s, len)) {
				dialreq_free(req);
				return NULL;
			}
		}
		lua_pop(L, 1);
	}
	return req;
}

static int format_addr(lua_State *restrict L)
{
	const struct sockaddr *sa = lua_topointer(L, -1);
	if (sa == NULL) {
		lua_pushnil(L);
		return 1;
	}
	const int af = sa->sa_family;
	switch (af) {
	case AF_INET: {
		char buf[INET_ADDRSTRLEN];
		const char *addr_str = inet_ntop(
			af, &((const struct sockaddr_in *)sa)->sin_addr, buf,
			sizeof(buf));
		if (addr_str == NULL) {
			const int err = errno;
			lua_pushstring(L, strerror(err));
			return lua_error(L);
		}
		lua_pushstring(L, addr_str);
	} break;
	case AF_INET6: {
		char buf[INET6_ADDRSTRLEN];
		const char *addr_str = inet_ntop(
			af, &((const struct sockaddr_in6 *)sa)->sin6_addr, buf,
			sizeof(buf));
		if (addr_str == NULL) {
			const int err = errno;
			lua_pushstring(L, strerror(err));
			return lua_error(L);
		}
		lua_pushstring(L, addr_str);
	} break;
	default:
		return luaL_error(L, "unknown af: %d", af);
	}
	return 1;
}

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
		luaL_error(L, "table is too complex to marshal");
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
static int marshal_(lua_State *restrict L)
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

struct reader_status {
	struct stream *s;
	const char *prefix;
	size_t prefixlen;
};

static const char *read_stream(lua_State *L, void *ud, size_t *restrict sz)
{
	UNUSED(L);
	struct reader_status *restrict rd = ud;
	const void *buf = rd->prefix;
	if (buf != NULL) {
		*sz = rd->prefixlen;
		rd->prefix = NULL;
		rd->prefixlen = 0;
		return buf;
	}
	*sz = SIZE_MAX; /* Lua allows arbitrary length */
	const int err = stream_direct_read(rd->s, &buf, sz);
	if (err != 0) {
		LOGE_F("read_stream: error %d", err);
	}
	if (*sz == 0) {
		return NULL;
	}
	return buf;
}

enum ruleset_functions {
	FUNC_REQUEST = 1,
	FUNC_LOADFILE,
	FUNC_INVOKE,
	FUNC_UPDATE,
	FUNC_STATS,
	FUNC_TICK,
	FUNC_TRACEBACK,
	FUNC_XPCALL,
	FUNC_RPCALL,
};

static int ruleset_request_(lua_State *restrict L)
{
	find_callback(L, 1);
	const char *request = lua_topointer(L, 2);
	(void)lua_pushstring(L, request);
	lua_replace(L, 2);

	lua_call(L, 1, LUA_MULTRET);
	const int n = lua_gettop(L);
	if (n < 1) {
		return 0;
	}
	const int type = lua_type(L, -1);
	switch (type) {
	case LUA_TSTRING:
		break;
	case LUA_TNIL:
		return 0;
	default:
		LOGE_F("request `%s': invalid return type %s", request,
		       lua_typename(L, type));
		return 0;
	}
	struct dialreq *req = pop_dialreq(L, n);
	if (req == NULL) {
		LOGE_F("request `%s': invalid return", request);
	}
	lua_pushlightuserdata(L, req);
	return 1;
}

static int ruleset_loadfile_(lua_State *restrict L)
{
	const char *filename = lua_topointer(L, 1);
	lua_pop(L, 1);
	if (luaL_loadfile(L, filename) != LUA_OK) {
		return lua_error(L);
	}
	lua_pushliteral(L, "ruleset");
	lua_call(L, 1, 1);
	lua_setglobal(L, "ruleset");
	return 0;
}

static int ruleset_invoke_(lua_State *restrict L)
{
	struct reader_status rd = { .s = (struct stream *)lua_topointer(L, 1) };
	if (lua_load(L, read_stream, &rd, "=invoke", NULL) != LUA_OK) {
		return lua_error(L);
	}
	lua_call(L, 0, 0);
	return 0;
}

static int ruleset_rpcall_(lua_State *restrict L)
{
	struct reader_status rd = { .s = (struct stream *)lua_topointer(L, 1) };
	const void **result = (const void **)lua_topointer(L, 2);
	size_t *resultlen = (size_t *)lua_topointer(L, 3);
	lua_settop(L, 0);
	lua_pushcfunction(L, marshal_);
	if (lua_load(L, read_stream, &rd, "=rpc", NULL) != LUA_OK) {
		return lua_error(L);
	}
	/* stack: marshal f */
	lua_call(L, 0, LUA_MULTRET);
	/* stack: marshal ... */
	lua_call(L, lua_gettop(L) - 1, 1);
	*result = lua_tolstring(L, -1, resultlen);
	return 1;
}

/* replace(modname, chunk) */
static int package_replace_(lua_State *restrict L)
{
	const int idx_modname = 1;
	luaL_checktype(L, idx_modname, LUA_TSTRING);
	const int idx_openf = 2;
	luaL_checktype(L, idx_openf, LUA_TFUNCTION);
	lua_settop(L, 2);
	const int idx_loaded = 3;
	luaL_getsubtable(L, LUA_REGISTRYINDEX, LUA_LOADED_TABLE);
	const int idx_glb = 4;
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS) != LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		return lua_error(L);
	}

	int glb = 0;
	/* LOADED[modname] */
	lua_pushvalue(L, idx_modname);
	if (lua_gettable(L, idx_loaded) != LUA_TNIL) {
		lua_pushvalue(L, idx_modname);
		lua_gettable(L, idx_glb); /* _G[modname] */
		glb = lua_compare(L, -2, -1, LUA_OPEQ);
		lua_pop(L, 2);
	} else {
		lua_pop(L, 1);
	}
	lua_pushvalue(L, idx_openf); /* open function */
	lua_pushvalue(L, idx_modname); /* argument to open function */
	lua_call(L, 1, 1); /* call open function */
	lua_pushvalue(L, idx_modname); /* modname */
	if (!lua_isnil(L, -2)) {
		lua_pushvalue(L, -2); /* make copy of module (call result) */
	} else {
		lua_pushboolean(L, 1); /* no value, use true as result */
	}
	lua_settable(L, idx_loaded); /* LOADED[modname] = module */
	if (glb) {
		lua_pushvalue(L, idx_modname); /* modname */
		lua_pushvalue(L, -2); /* copy of module */
		lua_settable(L, idx_glb); /* _G[modname] = module */
	}
	return 1;
}

static int ruleset_update_(lua_State *restrict L)
{
	const char *modname = lua_topointer(L, 1);
	struct reader_status rd = { .s = (struct stream *)lua_topointer(L, 2) };
	lua_settop(L, 0);
	if (modname == NULL) {
		if (lua_load(L, read_stream, &rd, "=ruleset", NULL) != LUA_OK) {
			return lua_error(L);
		}
		lua_pushliteral(L, "ruleset");
		lua_call(L, 1, 1);
		lua_setglobal(L, "ruleset");
		return 0;
	}
	{
		const size_t namelen = strlen(modname);
		(void)lua_pushlstring(L, modname, namelen);
		char name[1 + namelen + 1];
		name[0] = '=';
		memcpy(name + 1, modname, namelen);
		name[1 + namelen] = '\0';
		if (lua_load(L, read_stream, &rd, name, NULL) != LUA_OK) {
			return lua_error(L);
		}
	}
	(void)package_replace_(L);
	return 0;
}

static int ruleset_stats_(lua_State *restrict L)
{
	find_callback(L, 1);
	lua_pushnumber(L, *(double *)lua_topointer(L, -1));
	lua_replace(L, 2);
	lua_call(L, 1, 1);
	return 1;
}

static int ruleset_tick_(lua_State *restrict L)
{
	find_callback(L, 1);
	lua_pushnumber(L, *(ev_tstamp *)lua_topointer(L, 2));
	lua_replace(L, 2);
	lua_call(L, 1, 0);
	return 0;
}

static int ruleset_traceback_(lua_State *restrict L)
{
	size_t len;
	const char *msg = luaL_tolstring(L, -1, &len);
	LOG_STACK_F(DEBUG, 0, "ruleset traceback: %.*s", (int)len, msg);
	luaL_traceback(L, L, msg, 1);
	msg = lua_tolstring(L, -1, &len);
	LOG_TXT(VERBOSE, msg, len, "Lua traceback");
	return 1;
}

static int
ruleset_xpcall_k_(lua_State *restrict L, const int status, lua_KContext ctx)
{
	UNUSED(ctx);
	/* stack: FUNC_TRACEBACK, true, ... */
	const int nresults = lua_gettop(L) - 1;
	if (status == LUA_OK) {
		return nresults;
	}
	return lua_error(L);
}

static int ruleset_xpcall_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TFUNCTION);
	const int n = lua_gettop(L) - 1;
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_FUNCTIONS) != LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		return lua_error(L);
	}
	if (lua_rawgeti(L, -1, FUNC_TRACEBACK) != LUA_TFUNCTION) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		return lua_error(L);
	}
	lua_pushboolean(L, 1);
	lua_rotate(L, 1, 2);
	/* FUNC_TRACEBACK, true, f, ..., RIDX_FUNCTIONS */
	lua_pop(L, 1);
	const int status =
		lua_pcallk(L, n, LUA_MULTRET, 1, 0, ruleset_xpcall_k_);
	return ruleset_xpcall_k_(L, status, 0);
}

static void init_registry(lua_State *restrict L)
{
	const char *errors[] = {
		ERR_MEMORY,
		ERR_BAD_REGISTRY,
		ERR_NOT_YIELDABLE,
		ERR_INVALID_ROUTE,
	};
	lua_createtable(L, ARRAY_SIZE(errors), 0);
	for (lua_Integer i = 0; i < (lua_Integer)ARRAY_SIZE(errors); i++) {
		lua_pushstring(L, errors[i]);
		lua_seti(L, -2, i + 1);
	}
	lua_seti(L, LUA_REGISTRYINDEX, RIDX_ERRORS);

	const struct {
		lua_Integer idx;
		lua_CFunction func;
	} reg[] = {
		{ FUNC_REQUEST, ruleset_request_ },
		{ FUNC_LOADFILE, ruleset_loadfile_ },
		{ FUNC_INVOKE, ruleset_invoke_ },
		{ FUNC_UPDATE, ruleset_update_ },
		{ FUNC_STATS, ruleset_stats_ },
		{ FUNC_TICK, ruleset_tick_ },
		{ FUNC_TRACEBACK, ruleset_traceback_ },
		{ FUNC_XPCALL, ruleset_xpcall_ },
		{ FUNC_RPCALL, ruleset_rpcall_ },
	};
	lua_createtable(L, ARRAY_SIZE(reg), 0);
	for (size_t i = 0; i < ARRAY_SIZE(reg); i++) {
		lua_pushcfunction(L, reg[i].func);
		lua_seti(L, -2, reg[i].idx);
	}
	lua_seti(L, LUA_REGISTRYINDEX, RIDX_FUNCTIONS);
}

static void check_memlimit(struct ruleset *restrict r)
{
	const size_t memlimit = G.conf->memlimit;
	if (memlimit == 0 || (r->vmstats.byt_allocated >> 20u) < memlimit) {
		return;
	}
	ruleset_gc(r);
}

static bool ruleset_pcall(
	struct ruleset *restrict r, enum ruleset_functions func, int nargs,
	int nresults, ...)
{
	lua_State *restrict L = r->L;
	lua_settop(L, 0);
	check_memlimit(r);
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_FUNCTIONS) != LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		return false;
	}
	const bool traceback = G.conf->traceback;
	if (traceback) {
		if (lua_rawgeti(L, 1, FUNC_TRACEBACK) != LUA_TFUNCTION) {
			lua_pushliteral(L, ERR_BAD_REGISTRY);
			return false;
		}
	}
	if (lua_rawgeti(L, 1, func) != LUA_TFUNCTION) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		return false;
	}
	lua_remove(L, 1);
	va_list args;
	va_start(args, nresults);
	for (int i = 0; i < nargs; i++) {
		lua_pushlightuserdata(L, va_arg(args, void *));
	}
	va_end(args);
	return lua_pcall(L, nargs, nresults, traceback ? 1 : 0) == LUA_OK;
}

static int regex_gc_(lua_State *restrict L)
{
	regex_t *preg = lua_touserdata(L, 1);
	regfree(preg);
	return 0;
}

/* regex.compile(pat) */
static int regex_compile_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TSTRING);
	const char *pat = lua_tostring(L, 1);
	regex_t *preg = lua_newuserdata(L, sizeof(regex_t));
	const int err = regcomp(preg, pat, REG_EXTENDED);
	if (err != 0) {
		char errbuf[256];
		const size_t n = regerror(err, preg, errbuf, sizeof(errbuf));
		lua_pushlstring(L, errbuf, n);
		return lua_error(L);
	}
	luaL_setmetatable(L, MT_REGEX);
	return 1;
}

/* regex.find(reg, s) */
static int regex_find_(lua_State *restrict L)
{
	regex_t *preg = luaL_checkudata(L, 1, MT_REGEX);
	const char *s = luaL_checkstring(L, 2);
	regmatch_t match;
	const int err = regexec(preg, s, 1, &match, 0);
	if (err == REG_NOMATCH) {
		lua_pushnil(L);
		return 1;
	}
	if (err != 0) {
		char errbuf[256];
		const size_t n = regerror(err, preg, errbuf, sizeof(errbuf));
		lua_pushlstring(L, errbuf, n);
		return lua_error(L);
	}
	lua_pushinteger(L, match.rm_so + 1);
	lua_pushinteger(L, match.rm_eo);
	return 2;
}

/* regex.match(reg, s) */
static int regex_match_(lua_State *restrict L)
{
	regex_t *preg = luaL_checkudata(L, 1, MT_REGEX);
	const char *s = luaL_checkstring(L, 2);
	regmatch_t match;
	const int err = regexec(preg, s, 1, &match, 0);
	if (err == REG_NOMATCH) {
		lua_pushnil(L);
		return 1;
	}
	if (err != 0) {
		char errbuf[256];
		const size_t n = regerror(err, preg, errbuf, sizeof(errbuf));
		lua_pushlstring(L, errbuf, n);
		return lua_error(L);
	}
	lua_pushlstring(L, s + match.rm_so, match.rm_eo - match.rm_so);
	return 1;
}

static int luaopen_regex(lua_State *restrict L)
{
	const luaL_Reg regexlib[] = {
		{ "compile", regex_compile_ },
		{ "find", regex_find_ },
		{ "match", regex_match_ },
		{ NULL, NULL },
	};
	luaL_newlib(L, regexlib);
	if (luaL_newmetatable(L, MT_REGEX)) {
		lua_pushvalue(L, -2);
		lua_setfield(L, -2, "__index");
		lua_pushcfunction(L, regex_gc_);
		lua_setfield(L, -2, "__gc");
	}
	lua_pop(L, 1);
	return 1;
}

struct stream_context {
	struct vbuffer *out;
	struct stream *r, *w;
	unsigned char buf[IO_BUFSIZE];
};

static int stream_context_close_(struct lua_State *L)
{
	struct stream_context *restrict s =
		(struct stream_context *)lua_topointer(L, 1);
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

/* z = zlib.compress(s) */
static int zlib_compress_(lua_State *restrict L)
{
	size_t len;
	const char *src = luaL_checklstring(L, 1, &len);
	struct stream_context *restrict s =
		lua_newuserdata(L, sizeof(struct stream_context));
	if (luaL_newmetatable(L, MT_STREAM_CONTEXT)) {
		lua_pushcfunction(L, stream_context_close_);
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
	const int err = stream_copy(s->w, s->r, s->buf, sizeof(s->buf));
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
static int zlib_uncompress_(lua_State *restrict L)
{
	size_t len;
	const char *src = luaL_checklstring(L, 1, &len);
	struct stream_context *restrict s =
		lua_newuserdata(L, sizeof(struct stream_context));
	if (luaL_newmetatable(L, MT_STREAM_CONTEXT)) {
		lua_pushcfunction(L, stream_context_close_);
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
	const int err = stream_copy(s->w, s->r, s->buf, sizeof(s->buf));
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

static int luaopen_zlib(lua_State *restrict L)
{
	const luaL_Reg zlib[] = {
		{ "compress", zlib_compress_ },
		{ "uncompress", zlib_uncompress_ },
		{ NULL, NULL },
	};
	luaL_newlib(L, zlib);
	return 1;
}

/* ok, ... = async(f, ...) */
static int ruleset_async_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TFUNCTION);
	int n = lua_gettop(L);
	lua_State *restrict co = lua_newthread(L);
	lua_pop(L, 1);
	if (G.conf->traceback) {
		if (lua_rawgeti(co, LUA_REGISTRYINDEX, RIDX_FUNCTIONS) !=
		    LUA_TTABLE) {
			lua_pushliteral(L, ERR_BAD_REGISTRY);
			return lua_error(L);
		}
		if (lua_rawgeti(co, -1, FUNC_XPCALL) != LUA_TFUNCTION) {
			lua_pushliteral(L, ERR_BAD_REGISTRY);
			return lua_error(L);
		}
		lua_remove(co, -2); /* RIDX_FUNCTIONS */
		lua_xmove(L, co, n);
		/* co stack: FUNC_XPCALL, f, ... */
	} else {
		lua_xmove(L, co, n);
		n--;
		/* co stack: f, ... */
	}
	const int status = co_resume(co, L, n, &n);
	if (status != LUA_OK && status != LUA_YIELD) {
		lua_pushboolean(L, 0);
		lua_xmove(co, L, 1);
		return 2;
	}
	lua_settop(L, 0);
	if (!lua_checkstack(L, 1 + n)) {
		lua_pushboolean(L, 0);
		lua_pushliteral(L, "too many results");
		return 2;
	}
	lua_pushboolean(L, 1);
	lua_xmove(co, L, n);
	return 1 + n;
}

/* neosocksd.invoke(code, addr, proxyN, ..., proxy1) */
static int api_invoke_(lua_State *restrict L)
{
	const int n = lua_gettop(L);
	for (int i = 1; i <= MAX(2, n); i++) {
		luaL_checktype(L, i, LUA_TSTRING);
	}
	struct dialreq *req = pop_dialreq(L, n - 1);
	if (req == NULL) {
		lua_pushliteral(L, ERR_INVALID_ROUTE);
		return lua_error(L);
	}
	struct ruleset *restrict r = find_ruleset(L);
	size_t len;
	const char *code = lua_tolstring(L, 1, &len);
	struct http_client_cb cb = { NULL, NULL };
	http_client_do(r->loop, req, "/ruleset/invoke", code, len, cb);
	return 0;
}

#define AWAIT_CHECK_YIELDABLE(L)                                               \
	do {                                                                   \
		if (!lua_isyieldable((L))) {                                   \
			lua_pushliteral((L), ERR_NOT_YIELDABLE);               \
			return lua_error((L));                                 \
		}                                                              \
	} while (0)

static void
await_pin(struct ruleset *restrict r, lua_State *restrict L, const void *p)
{
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_CONTEXTS) != LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		lua_error(L);
	}
	if (lua_pushthread(L)) {
		lua_pushliteral(L, ERR_NOT_YIELDABLE);
		lua_error(L);
	}
	lua_rawsetp(L, -2, (p));
	lua_pop(L, 1);
	r->vmstats.num_routine++;
}

static void
await_unpin(struct ruleset *restrict r, lua_State *restrict L, const void *p)
{
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_CONTEXTS) != LUA_TTABLE) {
		lua_pushliteral(L, ERR_BAD_REGISTRY);
		lua_error(L);
	}
	lua_pushnil(L);
	lua_rawsetp(L, -2, (p));
	lua_pop(L, 1);
	r->vmstats.num_routine--;
}

static bool
await_resume(struct ruleset *restrict r, const void *p, int narg, ...)
{
	check_memlimit(r);
	lua_State *restrict L = r->L;
	if (lua_rawgeti(L, LUA_REGISTRYINDEX, RIDX_CONTEXTS) != LUA_TTABLE) {
		LOGE(ERR_BAD_REGISTRY);
		return NULL;
	}
	lua_rawgetp(L, -1, p);
	lua_State *restrict co = lua_tothread(L, -1);
	lua_pop(L, 2);
	if (co == NULL) {
		LOGE_F("async context lost: %p", p);
		return false;
	}
	va_list args;
	va_start(args, narg);
	for (int i = 0; i < narg; i++) {
		lua_pushlightuserdata(co, va_arg(args, void *));
	}
	va_end(args);
	int nres;
	const int status = co_resume(co, L, narg, &nres);
	if (status != LUA_OK && status != LUA_YIELD) {
		lua_xmove(co, L, 1);
		return false;
	}
	return true;
}

static int await_idle_gc_(struct lua_State *L)
{
	struct ruleset *restrict r = find_ruleset(L);
	struct ev_idle *w = (struct ev_idle *)lua_topointer(L, 1);
	ev_idle_stop(r->loop, w);
	return 0;
}

static void idle_cb(struct ev_loop *loop, struct ev_idle *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct ruleset *restrict r = watcher->data;
	const void *p = watcher;
	if (!await_resume(r, p, 0)) {
		LOGE_F("idle_cb: %s", ruleset_error(r, NULL));
	}
}

static int
await_idle_k_(lua_State *restrict L, const int status, lua_KContext ctx)
{
	struct ruleset *restrict r = find_ruleset(L);
	struct ev_idle *restrict w =
		(struct ev_idle *)lua_topointer(L, (int)ctx);
	await_unpin(r, L, w);
	switch (status) {
	case LUA_OK:
	case LUA_YIELD:
		break;
	default:
		return lua_error(L);
	}
	return 0;
}

/* await.idle() */
static int await_idle_(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	struct ruleset *restrict r = find_ruleset(L);
	struct ev_idle *restrict w = lua_newuserdata(L, sizeof(struct ev_idle));
	ev_idle_init(w, idle_cb);
	ev_set_priority(w, EV_MINPRI);
	w->data = r;
	if (luaL_newmetatable(L, MT_AWAIT_IDLE)) {
		lua_pushcfunction(L, await_idle_gc_);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
	await_pin(r, L, w);
	ev_idle_start(r->loop, w);
	const lua_KContext ctx = (lua_KContext)lua_gettop(L);
	const int status = lua_yieldk(L, 0, ctx, await_idle_k_);
	return await_idle_k_(L, status, ctx);
}

static int await_sleep_gc_(struct lua_State *L)
{
	struct ruleset *restrict r = find_ruleset(L);
	struct ev_timer *w = (struct ev_timer *)lua_topointer(L, 1);
	ev_timer_stop(r->loop, w);
	return 0;
}

static void
sleep_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	ev_timer_stop(loop, watcher);
	struct ruleset *restrict r = watcher->data;
	const void *p = watcher;
	if (!await_resume(r, p, 0)) {
		LOGE_F("sleep_cb: %s", ruleset_error(r, NULL));
	}
}

static int
await_sleep_k_(lua_State *restrict L, const int status, lua_KContext ctx)
{
	struct ruleset *restrict r = find_ruleset(L);
	struct ev_timer *restrict w =
		(struct ev_timer *)lua_topointer(L, (int)ctx);
	await_unpin(r, L, w);
	switch (status) {
	case LUA_OK:
	case LUA_YIELD:
		break;
	default:
		return lua_error(L);
	}
	return 0;
}

/* await.sleep(n) */
static int await_sleep_(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	lua_Number n = luaL_checknumber(L, 1);
	if (!isnormal(n)) {
		return 0;
	}
	n = CLAMP(n, 1e-3, 1e+9);
	struct ruleset *restrict r = find_ruleset(L);
	struct ev_timer *restrict w =
		lua_newuserdata(L, sizeof(struct ev_timer));
	ev_timer_init(w, sleep_cb, n, 0.0);
	ev_set_priority(w, EV_MINPRI);
	w->data = r;
	if (luaL_newmetatable(L, MT_AWAIT_SLEEP)) {
		lua_pushcfunction(L, await_sleep_gc_);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
	await_pin(r, L, w);
	ev_timer_start(r->loop, w);
	const lua_KContext ctx = (lua_KContext)lua_gettop(L);
	const int status = lua_yieldk(L, 0, ctx, await_sleep_k_);
	return await_sleep_k_(L, status, ctx);
}

static int await_resolve_close_(struct lua_State *L)
{
	handle_type *restrict h = (handle_type *)lua_topointer(L, 1);
	if (*h != INVALID_HANDLE) {
		resolve_cancel(*h);
		*h = INVALID_HANDLE;
	}
	return 0;
}

static void resolve_cb(
	handle_type h, struct ev_loop *loop, void *ctx,
	const struct sockaddr *sa)
{
	UNUSED(loop);
	struct ruleset *restrict r = ctx;
	const void *p = handle_toptr(h);
	if (!await_resume(r, p, 1, (void *)sa)) {
		LOGE_F("resolve_cb: %s", ruleset_error(r, NULL));
	}
}

static int
await_resolve_k_(lua_State *restrict L, const int status, lua_KContext ctx)
{
	handle_type *restrict p = (handle_type *)lua_topointer(L, (int)ctx);
	struct ruleset *restrict r = find_ruleset(L);
	await_unpin(r, L, handle_toptr(*p));
	*p = INVALID_HANDLE;
	switch (status) {
	case LUA_OK:
	case LUA_YIELD:
		break;
	default:
		return lua_error(L);
	}
	return format_addr(L);
}

/* await.resolve(host) */
static int await_resolve_(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	luaL_checktype(L, 1, LUA_TSTRING);
	struct ruleset *restrict r = find_ruleset(L);
	const char *name = luaL_checkstring(L, 1);
	const handle_type h = resolve_do(
		G.resolver,
		(struct resolve_cb){
			.cb = resolve_cb,
			.ctx = find_ruleset(L),
		},
		name, NULL, G.conf->resolve_pf);
	if (h == INVALID_HANDLE) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	handle_type *restrict p = lua_newuserdata(L, sizeof(handle_type));
	*p = h;
	if (luaL_newmetatable(L, MT_AWAIT_RESOLVE)) {
		lua_pushcfunction(L, await_resolve_close_);
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
	const lua_KContext ctx = (lua_KContext)lua_gettop(L);
	await_pin(r, L, handle_toptr(h));
	const int status = lua_yieldk(L, 0, ctx, await_resolve_k_);
	return await_resolve_k_(L, status, ctx);
}

static int await_invoke_close_(struct lua_State *L)
{
	handle_type *h = (handle_type *)lua_topointer(L, 1);
	if (*h != INVALID_HANDLE) {
		struct ruleset *restrict r = find_ruleset(L);
		http_client_cancel(r->loop, *h);
		*h = INVALID_HANDLE;
	}
	return 0;
}

static void invoke_cb(
	handle_type h, struct ev_loop *loop, void *ctx, bool ok,
	const void *data, size_t len)
{
	UNUSED(loop);
	struct ruleset *restrict r = ctx;
	const void *p = handle_toptr(h);
	if (!await_resume(r, p, 3, (void *)&ok, (void *)data, (void *)&len)) {
		LOGE_F("http_client_cb: %s", ruleset_error(r, NULL));
	}
}

static int
await_invoke_k_(lua_State *restrict L, const int status, lua_KContext ctx)
{
	handle_type *restrict p = (handle_type *)lua_topointer(L, (int)ctx);
	struct ruleset *restrict r = find_ruleset(L);
	await_unpin(r, L, handle_toptr(*p));
	*p = INVALID_HANDLE;
	switch (status) {
	case LUA_OK:
	case LUA_YIELD:
		break;
	default:
		return lua_error(L);
	}
	const bool ok = *(bool *)lua_topointer(L, -3);
	const void *data = lua_topointer(L, -2);
	const size_t len = *(size_t *)lua_topointer(L, -1);
	lua_pop(L, 3);
	lua_pushboolean(L, ok);
	if (!ok) {
		lua_pushlstring(L, data, len);
		return 2;
	}
	/* unmarshal */
	const int base = lua_gettop(L);
	struct reader_status rd = {
		.s = (struct stream *)data,
		.prefix = "return ",
		.prefixlen = 7,
	};
	if (lua_load(L, read_stream, &rd, "=unmarshal", NULL) != LUA_OK) {
		return lua_error(L);
	}
	lua_call(L, 0, LUA_MULTRET);
	return 1 + (lua_gettop(L) - base);
}

/* ok, ... = await.invoke(code, addr, proxyN, ..., proxy1) */
static int await_invoke_(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	size_t len;
	const char *code = luaL_checklstring(L, 1, &len);
	const int n = lua_gettop(L);
	for (int i = 2; i <= MAX(2, n); i++) {
		luaL_checktype(L, i, LUA_TSTRING);
	}
	struct dialreq *req = pop_dialreq(L, n - 1);
	if (req == NULL) {
		lua_pushliteral(L, ERR_INVALID_ROUTE);
		return lua_error(L);
	}
	struct ruleset *restrict r = find_ruleset(L);
	struct http_client_cb cb = {
		.func = invoke_cb,
		.ctx = r,
	};
	handle_type h =
		http_client_do(r->loop, req, "/ruleset/rpcall", code, len, cb);
	if (h == INVALID_HANDLE) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}
	lua_pop(L, 1); /* code */
	handle_type *restrict p = lua_newuserdata(L, sizeof(handle_type));
	*p = h;
	if (luaL_newmetatable(L, MT_AWAIT_RPCALL)) {
		lua_pushcfunction(L, await_invoke_close_);
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
	const lua_KContext ctx = (lua_KContext)lua_gettop(L);
	await_pin(r, L, handle_toptr(h));
	const int status = lua_yieldk(L, 0, ctx, await_invoke_k_);
	return await_invoke_k_(L, status, ctx);
}

/* neosocksd.resolve(host) */
static int api_resolve_(lua_State *restrict L)
{
	const char *name = luaL_checkstring(L, 1);
	union sockaddr_max addr;
	if (!resolve_addr(&addr, name, NULL, G.conf->resolve_pf)) {
		lua_pushnil(L);
		return 1;
	}
	lua_pushlightuserdata(L, &addr.sa);
	return format_addr(L);
}

/* neosocksd.parse_ipv4(ipv4) */
static int api_parse_ipv4_(lua_State *restrict L)
{
	const char *s = lua_tostring(L, 1);
	if (s == NULL) {
		return 0;
	}
	struct in_addr in;
	if (inet_pton(AF_INET, s, &in) != 1) {
		return 0;
	}
	const uint32_t *addr = (void *)&in;
	lua_pushinteger(L, (lua_Integer)read_uint32((const void *)&addr[0]));
	return 1;
}

/* neosocksd.parse_ipv6(ipv6) */
static int api_parse_ipv6_(lua_State *restrict L)
{
	const char *s = lua_tostring(L, 1);
	if (s == NULL) {
		return 0;
	}
	struct in6_addr in6;
	if (inet_pton(AF_INET6, s, &in6) != 1) {
		return 0;
	}
	const lua_Integer *addr = (void *)&in6;
#if LUA_32BITS
	lua_pushinteger(L, (lua_Integer)read_uint32((const void *)&addr[0]));
	lua_pushinteger(L, (lua_Integer)read_uint32((const void *)&addr[1]));
	lua_pushinteger(L, (lua_Integer)read_uint32((const void *)&addr[2]));
	lua_pushinteger(L, (lua_Integer)read_uint32((const void *)&addr[3]));
	return 4;
#else
	lua_pushinteger(L, (lua_Integer)read_uint64((const void *)&addr[0]));
	lua_pushinteger(L, (lua_Integer)read_uint64((const void *)&addr[1]));
	return 2;
#endif
}

static void tick_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct ruleset *restrict r = watcher->data;
	const char *func = "tick";
	const ev_tstamp now = ev_now(loop);
	const bool ok = ruleset_pcall(r, FUNC_TICK, 2, 0, func, &now);
	if (!ok) {
		LOGE_F("ruleset.%s: %s", func, ruleset_error(r, NULL));
		return;
	}
}

/* neosocksd.setinterval(interval) */
static int api_setinterval_(lua_State *restrict L)
{
	luaL_checktype(L, 1, LUA_TNUMBER);
	double interval = lua_tonumber(L, 1);

	struct ruleset *restrict r = find_ruleset(L);
	struct ev_timer *restrict w_ticker = &r->w_ticker;
	ev_timer_stop(r->loop, w_ticker);
	if (!isnormal(interval)) {
		return 0;
	}

	interval = CLAMP(interval, 1e-3, 1e+9);
	ev_timer_set(w_ticker, interval, interval);
	w_ticker->data = r;
	ev_timer_start(r->loop, w_ticker);
	return 0;
}

/* neosocksd.splithostport() */
static int api_splithostport_(lua_State *restrict L)
{
	size_t len;
	const char *s = luaL_checklstring(L, 1, &len);
	/* FQDN + ':' + port */
	if (len > FQDN_MAX_LENGTH + 1 + 5) {
		(void)lua_pushfstring(L, "address too long: %zu bytes", len);
		return lua_error(L);
	}
	char buf[len + 1];
	(void)memcpy(buf, s, len);
	buf[len] = '\0';
	char *host, *port;
	if (!splithostport(buf, &host, &port)) {
		(void)lua_pushfstring(L, "invalid address: `%s'", s);
		return lua_error(L);
	}
	lua_settop(L, 0);
	(void)lua_pushstring(L, host);
	(void)lua_pushstring(L, port);
	return 2;
}

/* neosocksd.stats() */
static int api_stats_(lua_State *restrict L)
{
	struct server *restrict s = G.server;
	if (s == NULL) {
		lua_pushnil(L);
		return 1;
	}
	struct ruleset *restrict r = find_ruleset(L);
	const struct server_stats *restrict stats = &s->stats;
	lua_newtable(L);
	lua_pushinteger(L, (lua_Integer)stats->num_halfopen);
	lua_setfield(L, -2, "num_halfopen");
	lua_pushinteger(L, (lua_Integer)stats->num_sessions);
	lua_setfield(L, -2, "num_sessions");
	lua_pushinteger(L, (lua_Integer)stats->byt_up);
	lua_setfield(L, -2, "byt_up");
	lua_pushinteger(L, (lua_Integer)stats->byt_down);
	lua_setfield(L, -2, "byt_down");
	lua_pushnumber(L, (lua_Number)(ev_now(r->loop) - stats->started));
	lua_setfield(L, -2, "uptime");
	return 1;
}

/* neosocksd.now() */
static int api_now_(lua_State *restrict L)
{
	struct ruleset *restrict r = find_ruleset(L);
	const ev_tstamp now = ev_now(r->loop);
	lua_pushnumber(L, (lua_Number)now);
	return 1;
}

static int luaopen_await(lua_State *restrict L)
{
	lua_newtable(L);
	lua_seti(L, LUA_REGISTRYINDEX, RIDX_CONTEXTS);
	lua_pushcfunction(L, ruleset_async_);
	lua_setglobal(L, "async");
	const luaL_Reg awaitlib[] = {
		{ "resolve", await_resolve_ },
		{ "invoke", await_invoke_ },
		{ "sleep", await_sleep_ },
		{ "idle", await_idle_ },
		{ NULL, NULL },
	};
	luaL_newlib(L, awaitlib);
	return 1;
}

static int luaopen_neosocksd(lua_State *restrict L)
{
	lua_pushcfunction(L, marshal_);
	lua_setglobal(L, "marshal");
	const luaL_Reg apilib[] = {
		{ "invoke", api_invoke_ },
		{ "resolve", api_resolve_ },
		{ "setinterval", api_setinterval_ },
		{ "splithostport", api_splithostport_ },
		{ "parse_ipv4", api_parse_ipv4_ },
		{ "parse_ipv6", api_parse_ipv6_ },
		{ "stats", api_stats_ },
		{ "now", api_now_ },
		{ NULL, NULL },
	};
	luaL_newlib(L, apilib);
	return 1;
}

static int ruleset_luainit_(lua_State *restrict L)
{
	init_registry(L);
	/* load all libraries */
	luaL_openlibs(L);
	const luaL_Reg libs[] = {
		{ "neosocksd", luaopen_neosocksd },
		{ "regex", luaopen_regex },
		{ "zlib", luaopen_zlib },
		{ "await", luaopen_await },
		{ NULL, NULL },
	};
	for (const luaL_Reg *lib = libs; lib->func; lib++) {
		luaL_requiref(L, lib->name, lib->func, 1);
		lua_pop(L, 1);
	}
	/* set flags */
	lua_pushboolean(L, !LOGLEVEL(DEBUG));
	lua_setglobal(L, "NDEBUG");
	/* prefer generational GC on supported lua versions */
#ifdef LUA_GCGEN
	lua_gc(L, LUA_GCGEN, 0, 0);
#endif
	return 0;
}

static void *l_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	struct ruleset *restrict r = ud;
	if (nsize == 0) {
		/* free */
		if (ptr != NULL) {
			free(ptr);
			r->vmstats.byt_allocated -= osize;
			r->vmstats.num_object--;
		}
		return NULL;
	}
	if (ptr == NULL) {
		/* malloc */
		void *ret = malloc(nsize);
		if (ret != NULL) {
			r->vmstats.num_object++;
			r->vmstats.byt_allocated += nsize;
		}
		return ret;
	}
	/* realloc */
	void *ret = realloc(ptr, nsize);
	if (ret != NULL) {
		r->vmstats.byt_allocated =
			r->vmstats.byt_allocated - osize + nsize;
	}
	return ret;
}

static int l_panic(lua_State *L)
{
	if (lua_isstring(L, -1)) {
		LOGF_F("panic: %s", lua_tostring(L, -1));
	} else {
		LOGF_F("panic: (%s: %p)", lua_typename(L, lua_type(L, -1)),
		       lua_topointer(L, -1));
	}
	LOG_STACK(FATAL, 0, "stacktrace");
	return 0; /* return to Lua to abort */
}

struct ruleset *ruleset_new(struct ev_loop *loop)
{
	struct ruleset *restrict r = malloc(sizeof(struct ruleset));
	if (r == NULL) {
		return NULL;
	}
	r->loop = loop;
	r->vmstats = (struct ruleset_vmstats){ 0 };
	lua_State *restrict L = lua_newstate(l_alloc, r);
	if (L == NULL) {
		ruleset_free(r);
		return NULL;
	}
	(void)lua_atpanic(L, l_panic);
	r->L = L;
	{
		/* initialize in advance to prevent undefined behavior */
		struct ev_timer *restrict w_ticker = &r->w_ticker;
		ev_timer_init(w_ticker, tick_cb, 1.0, 1.0);
		w_ticker->data = r;
	}

	lua_pushcfunction(L, ruleset_luainit_);
	switch (lua_pcall(L, 0, 0, 0)) {
	case LUA_OK:
		break;
	case LUA_ERRMEM:
		ruleset_free(r);
		return NULL;
	default:
		FAILMSGF("ruleset init: %s", ruleset_error(r, NULL));
	}
	return r;
}

void ruleset_free(struct ruleset *restrict r)
{
	if (r == NULL) {
		return;
	}
	ev_timer_stop(r->loop, &r->w_ticker);
	lua_close(r->L);
	free(r);
}

const char *ruleset_error(struct ruleset *restrict r, size_t *len)
{
	lua_State *restrict L = r->L;
	if (lua_gettop(L) < 1) {
		return CONST_LSTRING("(no error)", len);
	}
	if (!lua_isstring(L, -1)) {
		return CONST_LSTRING("(error object is not a string)", len);
	}
	return lua_tolstring(L, -1, len);
}

bool ruleset_invoke(struct ruleset *r, struct stream *code)
{
	return ruleset_pcall(r, FUNC_INVOKE, 1, 0, code);
}

bool ruleset_rpcall(
	struct ruleset *r, struct stream *code, const void **result,
	size_t *resultlen)
{
	return ruleset_pcall(r, FUNC_RPCALL, 3, 1, code, result, resultlen);
}

bool ruleset_update(struct ruleset *r, const char *modname, struct stream *code)
{
	return ruleset_pcall(r, FUNC_UPDATE, 2, 0, modname, code);
}

bool ruleset_loadfile(struct ruleset *r, const char *filename)
{
	return ruleset_pcall(r, FUNC_LOADFILE, 1, 0, filename);
}

void ruleset_gc(struct ruleset *restrict r)
{
	lua_State *restrict L = r->L;
	if (!lua_gc(L, LUA_GCSTEP, 0)) {
		lua_gc(L, LUA_GCCOLLECT, 0);
	}
}

static struct dialreq *
dispatch_req(struct ruleset *restrict r, const char *func, const char *request)
{
	lua_State *restrict L = r->L;
	const bool ok = ruleset_pcall(
		r, FUNC_REQUEST, 2, 1, (void *)func, (void *)request);
	if (!ok) {
		LOGE_F("ruleset.%s: %s", func, ruleset_error(r, NULL));
		return NULL;
	}
	return (struct dialreq *)lua_topointer(L, -1);
}

struct dialreq *ruleset_resolve(struct ruleset *r, const char *request)
{
	return dispatch_req(r, "resolve", request);
}

struct dialreq *ruleset_route(struct ruleset *r, const char *request)
{
	return dispatch_req(r, "route", request);
}

struct dialreq *ruleset_route6(struct ruleset *r, const char *request)
{
	return dispatch_req(r, "route6", request);
}

void ruleset_vmstats(
	const struct ruleset *restrict r, struct ruleset_vmstats *restrict s)
{
	*s = r->vmstats;
}

const char *
ruleset_stats(struct ruleset *restrict r, const double dt, size_t *len)
{
	lua_State *restrict L = r->L;
	const char *func = "stats";
	const bool ok =
		ruleset_pcall(r, FUNC_STATS, 2, 1, (void *)func, (void *)&dt);
	if (!ok) {
		LOGE_F("ruleset.%s: %s", func, ruleset_error(r, NULL));
		return NULL;
	}
	return lua_tolstring(L, -1, len);
}

#endif /* WITH_RULESET */
