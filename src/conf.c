/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"

#if WITH_LUA
#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
#endif

#include "utils/slog.h"

#include <sys/socket.h>

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#if WITH_LUA
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

struct config conf_default(void)
{
	const struct config conf = {
		.log_level = LOG_LEVEL_NOTICE,
		.resolve_pf = PF_UNSPEC,
		.timeout = 60.0,

		.tcp_nodelay = true,
		.tcp_keepalive = true,
		.tcp_sndbuf = 0,
		.tcp_rcvbuf = 0,
#if WITH_TCP_FASTOPEN
		.tcp_fastopen = true,
#endif
#if WITH_TCP_FASTOPEN_CONNECT
		.tcp_fastopen_connect = false,
#endif
		.conn_cache = true,
		.block_multicast = true,

		.max_sessions = 0,
		.startup_limit_start = 0,
		.startup_limit_rate = 30,
		.startup_limit_full = 0,
	};
	return conf;
}

static bool range_check_int(
	const char *restrict key, const int value, const int lbound,
	const int ubound)
{
	if (!(lbound <= value && value <= ubound)) {
		LOGE_F("%s is out of range (%d - %d)", key, lbound, ubound);
		return false;
	}
	return true;
}

static bool range_check_double(
	const char *restrict key, const double value, const double lbound,
	const double ubound)
{
	if (!(lbound <= value && value <= ubound)) {
		LOGE_F("%s is out of range (%g - %g)", key, lbound, ubound);
		return false;
	}
	return true;
}

#define RANGE_CHECK(key, value, lbound, ubound)                                \
	_Generic(value, int: range_check_int, double: range_check_double)(     \
		key, value, lbound, ubound)

bool conf_check(const struct config *restrict conf)
{
	if (conf->listen == NULL && conf->http_listen == NULL) {
		LOGE("listen address is not specified");
		return false;
	}
	if (conf->http_listen != NULL && conf->forward != NULL) {
		LOGE("--http is incompatible with -f");
		return false;
	}
#if WITH_TPROXY
	if (conf->http_listen != NULL && conf->transparent) {
		LOGE("--http is incompatible with --tproxy");
		return false;
	}
	if (conf->forward != NULL && conf->transparent) {
		LOGE("incompatible flags are specified");
		return false;
	}
	const bool auth_supported =
		(conf->forward == NULL && !conf->transparent);
#else
	const bool auth_supported = (conf->forward == NULL);
#endif
	if (conf->block_global && conf->block_local) {
		LOGE("incompatible outbound policies are specified");
		return false;
	}
	if (conf->tcp_sndbuf > 0 && conf->tcp_sndbuf < 16384) {
		LOGW("tcp send buffer may be too small");
	}
	if (conf->tcp_rcvbuf > 0 && conf->tcp_rcvbuf < 16384) {
		LOGW("tcp recv buffer may be too small");
	}
#if WITH_RULESET
	if (conf->ruleset != NULL && conf->proxy != NULL) {
		LOGW("the proxy will be overwritten by ruleset");
	}
#endif
	if (conf->proxy != NULL) {
		if (conf->socks5_bind) {
			LOGE_F("%s is incompatible with forwarding proxy",
			       "SOCKS5 BIND");
			return false;
		}
		if (conf->socks5_udp) {
			LOGE_F("%s is incompatible with forwarding proxy",
			       "SOCKS5 UDPASSOCIATE");
			return false;
		}
	}
#if WITH_RULESET
	if (conf->ruleset != NULL) {
		if (conf->socks5_bind) {
			LOGE_F("%s is incompatible with ruleset",
			       "SOCKS5 BIND");
			return false;
		}
		if (conf->socks5_udp) {
			LOGE_F("%s is incompatible with ruleset",
			       "SOCKS5 UDPASSOCIATE");
			return false;
		}
	}
#endif
	if (conf->auth_required) {
		if (!auth_supported) {
			LOGE("authentication is not supported in current mode");
			return false;
		}
#if WITH_RULESET
		if (conf->ruleset == NULL) {
			LOGE("ruleset must be enabled for authentication");
			return false;
		}
#endif
	}

	return RANGE_CHECK("timeout", conf->timeout, 5.0, 86400.0) &&
	       RANGE_CHECK(
		       "startup_limit_start", conf->startup_limit_start, 0,
		       conf->startup_limit_full) &&
	       RANGE_CHECK(
		       "startup_limit_rate", conf->startup_limit_rate, 0,
		       100) &&
	       RANGE_CHECK(
		       "startup_limit_full", conf->startup_limit_full,
		       conf->startup_limit_start,
		       conf->max_sessions > 0 ? conf->max_sessions : INT_MAX);
}

#if WITH_LUA
/* Copy a Lua string at stack index idx into a heap allocation. */
static const char *lutil_strdup(lua_State *restrict L, const int idx)
{
	size_t len;
	const char *restrict s = lua_tolstring(L, idx, &len);
	char *restrict copy = malloc(len + 1);
	if (copy == NULL) {
		return NULL;
	}
	memcpy(copy, s, len + 1);
	return copy;
}

/* Descriptor table: one entry per struct config field, terminated by key=NULL. */
static const struct metaconfig conf_fields[] = {
	{ "listen", CONF_STRING, offsetof(struct config, listen) },
	{ "forward", CONF_STRING, offsetof(struct config, forward) },
	{ "proxy", CONF_STRING, offsetof(struct config, proxy) },
	{ "restapi", CONF_STRING, offsetof(struct config, restapi) },
	{ "http_listen", CONF_STRING, offsetof(struct config, http_listen) },
#if WITH_RULESET
	{ "ruleset", CONF_STRING, offsetof(struct config, ruleset) },
#endif
	{ "user_name", CONF_STRING, offsetof(struct config, user_name) },
#if WITH_CARES
	{ "nameserver", CONF_STRING, offsetof(struct config, nameserver) },
#endif
#if WITH_NETDEVICE
	{ "netdev", CONF_STRING, offsetof(struct config, netdev) },
#endif
	{ "log_level", CONF_INT, offsetof(struct config, log_level) },
	{ "resolve_pf", CONF_INT, offsetof(struct config, resolve_pf) },
	{ "timeout", CONF_DOUBLE, offsetof(struct config, timeout) },
#if WITH_RULESET
	{ "memlimit", CONF_INT, offsetof(struct config, memlimit) },
#endif
	{ "auth_required", CONF_BOOL, offsetof(struct config, auth_required) },
	{ "bidir_timeout", CONF_BOOL, offsetof(struct config, bidir_timeout) },
#if WITH_SPLICE
	{ "pipe", CONF_BOOL, offsetof(struct config, pipe) },
#endif
#if WITH_REUSEPORT
	{ "reuseport", CONF_BOOL, offsetof(struct config, reuseport) },
#endif
#if WITH_TCP_FASTOPEN
	{ "tcp_fastopen", CONF_BOOL, offsetof(struct config, tcp_fastopen) },
#endif
#if WITH_TCP_FASTOPEN_CONNECT
	{ "tcp_fastopen_connect", CONF_BOOL,
	  offsetof(struct config, tcp_fastopen_connect) },
#endif
	{ "tcp_nodelay", CONF_BOOL, offsetof(struct config, tcp_nodelay) },
	{ "tcp_keepalive", CONF_BOOL, offsetof(struct config, tcp_keepalive) },
#if WITH_TPROXY
	{ "transparent", CONF_BOOL, offsetof(struct config, transparent) },
#endif
#if WITH_RULESET
	{ "traceback", CONF_BOOL, offsetof(struct config, traceback) },
#endif
	{ "conn_cache", CONF_BOOL, offsetof(struct config, conn_cache) },
	{ "socks5_bind", CONF_BOOL, offsetof(struct config, socks5_bind) },
	{ "socks5_udp", CONF_BOOL, offsetof(struct config, socks5_udp) },
	{ "daemonize", CONF_BOOL, offsetof(struct config, daemonize) },
	{ "block_loopback", CONF_BOOL,
	  offsetof(struct config, block_loopback) },
	{ "block_multicast", CONF_BOOL,
	  offsetof(struct config, block_multicast) },
	{ "block_local", CONF_BOOL, offsetof(struct config, block_local) },
	{ "block_global", CONF_BOOL, offsetof(struct config, block_global) },
	{ "tcp_sndbuf", CONF_INT, offsetof(struct config, tcp_sndbuf) },
	{ "tcp_rcvbuf", CONF_INT, offsetof(struct config, tcp_rcvbuf) },
	{ "max_sessions", CONF_INT, offsetof(struct config, max_sessions) },
	{ "startup_limit_start", CONF_INT,
	  offsetof(struct config, startup_limit_start) },
	{ "startup_limit_rate", CONF_DOUBLE,
	  offsetof(struct config, startup_limit_rate) },
	{ "startup_limit_full", CONF_INT,
	  offsetof(struct config, startup_limit_full) },
	{ NULL, 0, 0 },
};

/* Load one field from the Lua table at stack top into *conf.
 * Returns false on type error. */
static bool conf_field_load(
	lua_State *restrict L, const struct metaconfig *restrict f,
	struct config *restrict conf)
{
	void *const field = (char *)conf + f->offset;
	lua_getfield(L, -1, f->key);
	const bool isnil = lua_isnil(L, -1);
	bool ok = true;
	switch (f->type) {
	case CONF_STRING:
		if (!isnil && lua_type(L, -1) != LUA_TSTRING) {
			LOGE_F("boot: field `%s' must be a string", f->key);
			ok = false;
		} else if (!isnil) {
			const char *restrict s = lutil_strdup(L, -1);
			if (s == NULL) {
				LOGE("boot: out of memory");
				ok = false;
			} else {
				*(const char **)field = s;
			}
		}
		break;
	case CONF_INT:
		if (!isnil && !lua_isinteger(L, -1)) {
			LOGE_F("boot: field `%s' must be an integer", f->key);
			ok = false;
		} else if (!isnil) {
			const lua_Integer v = lua_tointeger(L, -1);
			if (v < (lua_Integer)INT_MIN ||
			    v > (lua_Integer)INT_MAX) {
				LOGE_F("boot: field `%s' is out of range",
				       f->key);
				ok = false;
			} else {
				*(int *)field = (int)v;
			}
		}
		break;
	case CONF_DOUBLE:
		if (!isnil && !lua_isnumber(L, -1)) {
			LOGE_F("boot: field `%s' must be a number", f->key);
			ok = false;
		} else if (!isnil) {
			*(double *)field = (double)lua_tonumber(L, -1);
		}
		break;
	case CONF_BOOL:
		if (!isnil && lua_type(L, -1) != LUA_TBOOLEAN) {
			LOGE_F("boot: field `%s' must be a boolean", f->key);
			ok = false;
		} else if (!isnil) {
			*(bool *)field = lua_toboolean(L, -1) != 0;
		}
		break;
	}
	lua_pop(L, 1);
	return ok;
}

bool conf_loadfile(
	const char *restrict path, const int argc,
	const char *const restrict argv[const restrict],
	struct config *restrict conf)
{
	lua_State *restrict L = luaL_newstate();
	if (L == NULL) {
		LOGE("boot: cannot create Lua state");
		return false;
	}
	luaL_openlibs(L);

	/* inject arg[1..argc] with arg.n = argc */
	lua_createtable(L, argc, 1);
	for (int_fast32_t i = 0; i < argc; i++) {
		lua_pushstring(L, argv[i]);
		lua_rawseti(L, -2, (lua_Integer)(i + 1));
	}
	lua_pushinteger(L, (lua_Integer)argc);
	lua_setfield(L, -2, "n");
	lua_setglobal(L, "arg");

	/* load and execute the boot script; expect one return value */
	if (luaL_loadfile(L, path) != LUA_OK) {
		LOGE_F("boot: %s", lua_tostring(L, -1));
		lua_close(L);
		return false;
	}
	if (lua_pcall(L, 0, 1, 0) != LUA_OK) {
		LOGE_F("boot: %s", lua_tostring(L, -1));
		lua_close(L);
		return false;
	}
	if (!lua_istable(L, -1)) {
		LOGE_F("boot: expected table, got %s", luaL_typename(L, -1));
		lua_close(L);
		return false;
	}

	/* iterate descriptor table; apply only fields present in Lua table */
	bool ok = true;
	for (const struct metaconfig *f = conf_fields; f->key != NULL; f++) {
		if (!conf_field_load(L, f, conf)) {
			ok = false;
		}
	}
	lua_close(L);
	return ok;
}

/* Write a Lua double-quoted string literal for s. */
static bool conf_write_string(const char *restrict s)
{
	if (fputc('"', stdout) == EOF) {
		return false;
	}
	for (; *s != '\0'; s++) {
		const unsigned char c = (unsigned char)*s;
		if (c == '\\' || c == '"') {
			if (fprintf(stdout, "\\%c", c) < 0) {
				return false;
			}
		} else if (c < 0x20 || c == 0x7f) {
			if (fprintf(stdout, "\\%u", (unsigned int)c) < 0) {
				return false;
			}
		} else {
			if (fputc(c, stdout) == EOF) {
				return false;
			}
		}
	}
	return fputc('"', stdout) != EOF;
}

/* Print one config field as a Lua table entry. */
static bool conf_field_print(
	const struct metaconfig *restrict field,
	const struct config *restrict conf)
{
	const void *const ptr = (const char *)conf + field->offset;
	if (fprintf(stdout, "  %s = ", field->key) < 0) {
		return false;
	}
	switch (field->type) {
	case CONF_STRING: {
		const char *const s = *(const char *const *)ptr;
		if (s == NULL) {
			if (fputs("nil", stdout) == EOF) {
				return false;
			}
		} else if (!conf_write_string(s)) {
			return false;
		}
	} break;
	case CONF_INT:
		if (fprintf(stdout, "%d", *(const int *)ptr) < 0) {
			return false;
		}
		break;
	case CONF_DOUBLE:
		if (fprintf(stdout, "%g", *(const double *)ptr) < 0) {
			return false;
		}
		break;
	case CONF_BOOL:
		if (fputs(*(const bool *)ptr ? "true" : "false", stdout) ==
		    EOF) {
			return false;
		}
		break;
	}
	return fputs(",\n", stdout) != EOF;
}

bool conf_print(const struct config *restrict conf)
{
	bool ok = fputs("return {\n", stdout) != EOF;
	for (const struct metaconfig *field = conf_fields;
	     ok && field->key != NULL; field++) {
		ok = conf_field_print(field, conf);
	}
	if (ok) {
		ok = fputs("}\n", stdout) != EOF;
	}
	return ok;
}
#endif /* WITH_LUA */
