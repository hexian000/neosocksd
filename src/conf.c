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

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Module-level state for conf_parseargs / conf_reload */
static struct {
	int argc;
	char **argv;
} args;

#if WITH_LUA
/* Tag for a struct config field's C type. */
enum conf_type {
	CONF_STRING, /* const char * */
	CONF_INT, /* int */
	CONF_DOUBLE, /* double */
	CONF_BOOL, /* bool */
};

/* Descriptor for one named field of struct config. */
struct metaconfig {
	const char *key;
	enum conf_type type;
	size_t offset;
};

/* Pointer into conf_argv[i]; valid for the process lifetime */
static const char *bootfile;
/* The baseline config produced by pure argv parsing (strings == NULL).
 * conf_reload resets to this before applying the Lua file. */
static struct config baseconf;
#endif

struct config conf_default(void)
{
	const struct config conf = {
		.loglevel = LOG_LEVEL_NOTICE,
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

static void print_usage(void)
{
	(void)fprintf(
		stderr, "%s %s\n  %s\n\n", PROJECT_NAME, PROJECT_VER,
		PROJECT_HOMEPAGE);
	(void)fprintf(stderr, "usage: %s <option>... \n", args.argv[0]);
	(void)fprintf(
		stderr, "%s",
		"  -h, --help                 show usage and exit\n"
#if WITH_LUA
		"  -c, --config <boot.lua>    load configuration from Lua script\n"
		"  --dump-config              dump effective configuration as Lua and exit\n"
#endif
		"  -4, -6                     resolve requested doamin name as IPv4/IPv6 only\n"
		"  -l, --listen <address>     proxy listen address\n"
		"  --http [address]           run an HTTP proxy; if address is omitted, use -l\n"
		"  --auth-required            require basic authentication\n"
		"  -f, --forward <address>    run TCP port forwarding instead of SOCKS\n"
		"  -x, --proxy proxy1[,...[,proxyN]]\n"
		"                             forward outbound connection over proxy chain\n"
#if WITH_CARES
		"  --nameserver <address>     use specified nameserver instead of resolv.conf\n"
#endif
#if WITH_NETDEVICE
		"  -i, --netdev <name>        bind outgoing connections to network device\n"
#endif
#if WITH_REUSEPORT
		"  --reuseport                allow multiple instances to listen on the same port\n"
#endif
#if WITH_SPLICE
		"  --pipe                     use pipes to transfer data between connections\n"
#endif
#if WITH_TCP_FASTOPEN
		"  --no-fastopen              disable server-side TCP fast open (RFC 7413)\n"
#endif
#if WITH_TPROXY
		"  --tproxy                   operate as a transparent proxy\n"
#endif
#if WITH_RULESET
		"  -r, --ruleset <file>       load ruleset from Lua file\n"
		"  --traceback                print ruleset error traceback (for debugging)\n"
		"  --memlimit <size>          set a soft limit on the total Lua object size in MiB\n"
#endif
		"  --no-conn-cache            disable upstream connection cache\n"
		"  --enable-socks5-bind       enable SOCKS5 BIND command (incompatible with -r/-x)\n"
		"  --enable-socks5-udp        enable SOCKS5 UDP ASSOCIATE command (incompatible with -r/-x)\n"
		"  --api <bind_address>       RESTful API listen address\n"
		"  -t, --timeout <seconds>    maximum time in seconds that a halfopen connection\n"
		"                             can take (default: 60.0)\n"
		"  --bidir-timeout            continue counting timeout before bidirectional\n"
		"                             traffic is established\n"
		"  --loglevel <level>         0-8 are Silence, Fatal, Error, Warning, Notice, Info,\n"
		"                             Debug, Verbose, VeryVerbose respectively (default: 4)\n"
		"  -C, --color                colorized log output using ANSI escape sequences\n"
		"  -d, --daemonize            run in background and write logs to syslog\n"
		"  -u, --user [user][:[group]]\n"
		"                             run as the specified identity, e.g. `nobody:nogroup'\n"
		"  -m, --max-sessions <n>     maximum number of concurrent connections\n"
		"                             (default: unlimited)\n"
		"  --max-startups <start:rate:full>\n"
		"                             maximum number of concurrent halfopen connections\n"
		"                             (default: unlimited)\n"
		"  --block-outbound <list>    block outbound address classes in comma-separated\n"
		"                             list: loopback,multicast,local,global\n"
		"                             (default: multicast)\n"
		"\n"
		"example:\n"
		"  neosocksd -l 0.0.0.0:1080                  # start a SOCKS 4/4a/5 server\n"
		"  neosocksd -l 0.0.0.0:80 -f 127.0.0.1:8080  # forward port 80 to 8080\n"
		"  neosocksd -l 127.0.0.1:1080 -x socks5://user:pass@gate.internal:1080\n"
		"  neosocksd -l 0.0.0.0:1080 --api 127.0.1.1:9080 -r ruleset.lua\n"
		"  neosocksd -l 0.0.0.0:10500 -f : -r lb.lua\n"
		"  neosocksd -l 0.0.0.0:1080 --http 0.0.0.0:8080  # SOCKS and HTTP proxy\n"
		"\n");
	(void)fflush(stderr);
}

#if WITH_LUA
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
	{ "loglevel", CONF_INT, offsetof(struct config, loglevel) },
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
	{ "startup_limit_rate", CONF_INT,
	  offsetof(struct config, startup_limit_rate) },
	{ "startup_limit_full", CONF_INT,
	  offsetof(struct config, startup_limit_full) },
	{ NULL, 0, 0 },
};

/* Load one non-string field from the Lua table at stack top into *conf.
 * Must not be called for CONF_STRING fields. Returns false on type error. */
static bool lutil_loadfield(
	lua_State *restrict L, const struct metaconfig *restrict f,
	struct config *restrict conf)
{
	void *const field = (char *)conf + f->offset;
	lua_getfield(L, -1, f->key);
	const bool isnil = lua_isnil(L, -1);
	bool ok = true;
	switch (f->type) {
	case CONF_STRING:
		break; /* handled separately in conf_loadfile */
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

static bool conf_loadfile(
	const char *restrict path, const int argc, char *argv[],
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

	/* Load non-string fields directly */
	for (const struct metaconfig *f = conf_fields; f->key != NULL; f++) {
		if (f->type == CONF_STRING) {
			continue;
		}
		if (!lutil_loadfield(L, f, conf)) {
			lua_close(L);
			return false;
		}
	}

	/* Pass 1: measure the block size for Lua-provided string fields only.
	 * Nil fields keep their existing pointer; only type errors abort. */
	size_t total = 0;
	for (const struct metaconfig *f = conf_fields; f->key != NULL; f++) {
		if (f->type != CONF_STRING) {
			continue;
		}
		lua_getfield(L, -1, f->key);
		if (lua_isnil(L, -1)) {
			/* existing pointer preserved; no allocation needed */
		} else if (lua_type(L, -1) == LUA_TSTRING) {
			size_t len;
			lua_tolstring(L, -1, &len);
			total += len + 1;
		} else {
			LOGE_F("boot: field `%s' must be a string", f->key);
			lua_pop(L, 1);
			lua_close(L);
			return false;
		}
		lua_pop(L, 1);
	}

	/* Allocate single block for all strings */
	char *restrict block = (total > 0) ? malloc(total) : NULL;
	if (total > 0 && block == NULL) {
		LOGE("boot: out of memory");
		lua_close(L);
		return false;
	}

	/* Pass 2: copy Lua-provided strings into block; nil fields unchanged */
	char *pos = block;
	for (const struct metaconfig *f = conf_fields; f->key != NULL; f++) {
		if (f->type != CONF_STRING) {
			continue;
		}
		const char **fptr = (const char **)((char *)conf + f->offset);
		lua_getfield(L, -1, f->key);
		if (!lua_isnil(L, -1)) {
			size_t len;
			const char *restrict s = lua_tolstring(L, -1, &len);
			memcpy(pos, s, len + 1);
			*fptr = pos;
			pos += len + 1;
		}
		lua_pop(L, 1);
	}

	lua_close(L);
	free(conf->strings);
	conf->strings = block;
	return true;
}

/* Write a Lua double-quoted string literal for s. */
static bool lutil_printstring(const char *restrict s)
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
static bool lutil_printfield(
	const struct metaconfig *restrict field,
	const struct config *restrict conf)
{
	const void *const ptr = (const char *)conf + field->offset;
	if (fprintf(stdout, "    %s = ", field->key) < 0) {
		return false;
	}
	switch (field->type) {
	case CONF_STRING: {
		const char *const s = *(const char *const *)ptr;
		if (s == NULL) {
			if (fputs("nil", stdout) == EOF) {
				return false;
			}
		} else if (!lutil_printstring(s)) {
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

static bool conf_print(const struct config *restrict conf)
{
	bool ok = fputs("return {\n", stdout) != EOF;
	for (const struct metaconfig *field = conf_fields;
	     ok && field->key != NULL; field++) {
		ok = lutil_printfield(field, conf);
	}
	if (ok) {
		ok = fputs("}\n", stdout) != EOF;
	}
	return ok;
}
#endif /* WITH_LUA */

bool conf_parseargs(struct config *restrict conf, const int argc, char *argv[])
{
#define OPT_REQUIRE_ARG(argc, argv, i)                                         \
	do {                                                                   \
		if ((i) + 1 >= (argc)) {                                       \
			LOGF_F("option `%s' requires an argument",             \
			       (argv)[(i)]);                                   \
			return false;                                          \
		}                                                              \
	} while (false)

#define OPT_ARG_ERROR(argv, i)                                                 \
	do {                                                                   \
		LOGF_F("argument error: %s `%s'", (argv)[(i) - 1],             \
		       (argv)[(i)]);                                           \
		return false;                                                  \
	} while (false)

	args.argc = argc;
	args.argv = argv;
	*conf = conf_default();
	bool http_only = false;
#if WITH_LUA
	bool dump_config = false;
	bootfile = NULL;
#endif
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 ||
		    strcmp(argv[i], "--help") == 0) {
			print_usage();
			return false;
		}
#if WITH_LUA
		if (strcmp(argv[i], "-c") == 0 ||
		    strcmp(argv[i], "--config") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			bootfile = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "--dump-config") == 0) {
			dump_config = true;
			continue;
		}
#endif
		if (strcmp(argv[i], "-4") == 0) {
			conf->resolve_pf = PF_INET;
			continue;
		}
		if (strcmp(argv[i], "-6") == 0) {
			conf->resolve_pf = PF_INET6;
			continue;
		}
		if (strcmp(argv[i], "-l") == 0 ||
		    strcmp(argv[i], "--listen") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			conf->listen = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "-f") == 0 ||
		    strcmp(argv[i], "--forward") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			conf->forward = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "-x") == 0 ||
		    strcmp(argv[i], "--proxy") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			conf->proxy = argv[++i];
			continue;
		}
#if WITH_CARES
		if (strcmp(argv[i], "--nameserver") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			conf->nameserver = argv[++i];
			continue;
		}
#endif
		if (strcmp(argv[i], "--http") == 0) {
			if (i + 1 < argc && argv[i + 1][0] != '-') {
				conf->http_listen = argv[++i];
			} else {
				http_only = true;
			}
			continue;
		}
		if (strcmp(argv[i], "--auth-required") == 0) {
			conf->auth_required = true;
			continue;
		}
#if WITH_TPROXY
		if (strcmp(argv[i], "--tproxy") == 0) {
			conf->transparent = true;
			continue;
		}
#endif
#if WITH_NETDEVICE
		if (strcmp(argv[i], "-i") == 0 ||
		    strcmp(argv[i], "--netdev") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			conf->netdev = argv[++i];
			continue;
		}
#endif
#if WITH_REUSEPORT
		if (strcmp(argv[i], "--reuseport") == 0) {
			conf->reuseport = true;
			continue;
		}
#endif
#if WITH_SPLICE
		if (strcmp(argv[i], "--pipe") == 0) {
			conf->pipe = true;
			continue;
		}
#endif
#if WITH_TCP_FASTOPEN
		if (strcmp(argv[i], "--no-fastopen") == 0) {
			conf->tcp_fastopen = false;
			continue;
		}
#endif
#if WITH_TCP_FASTOPEN_CONNECT
		if (strcmp(argv[i], "--fastopen-connect") == 0) {
			conf->tcp_fastopen_connect = true;
			LOGW("the undocumented `--fastopen-connect' may cause issues with `--pipe' and server first protocols");
			continue;
		}
#endif
		if (strcmp(argv[i], "--api") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			conf->restapi = argv[++i];
			continue;
		}
#if WITH_RULESET
		if (strcmp(argv[i], "-r") == 0 ||
		    strcmp(argv[i], "--ruleset") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			conf->ruleset = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "--traceback") == 0) {
			conf->traceback = true;
			continue;
		}
		if (strcmp(argv[i], "--memlimit") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			++i;
			char *endptr = NULL;
			intmax_t soft = strtoimax(argv[i], &endptr, 10);
			if (soft > INT_MAX / 1024) {
				OPT_ARG_ERROR(argv, i);
			} else if (soft < 0) {
				soft = 0;
			}
			conf->memlimit = (int)soft;
			continue;
		}
#endif
		if (strcmp(argv[i], "--no-conn-cache") == 0) {
			conf->conn_cache = false;
			continue;
		}
		if (strcmp(argv[i], "-u") == 0 ||
		    strcmp(argv[i], "--user") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			conf->user_name = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "-t") == 0 ||
		    strcmp(argv[i], "--timeout") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			++i;
			const size_t n = strlen(argv[i]);
			char *endptr = NULL;
			conf->timeout = strtod(argv[i], &endptr);
			if (argv[i] + n != endptr) {
				OPT_ARG_ERROR(argv, i);
			}
			continue;
		}
		if (strcmp(argv[i], "--loglevel") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			++i;
			char *endptr;
			const uintmax_t value = strtoumax(argv[i], &endptr, 10);
			if (*endptr || value > INT_MAX) {
				OPT_ARG_ERROR(argv, i);
			}
			conf->loglevel = (int)value;
			continue;
		}
		if (strcmp(argv[i], "-C") == 0 ||
		    strcmp(argv[i], "--color") == 0) {
			slog_setoutput(SLOG_OUTPUT_TERMINAL, stderr);
			continue;
		}
		if (strcmp(argv[i], "-d") == 0 ||
		    strcmp(argv[i], "--daemonize") == 0) {
			conf->daemonize = true;
			continue;
		}
		if (strcmp(argv[i], "--block-outbound") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			++i;
			const size_t n = strlen(argv[i]);
			if (n > 255) {
				OPT_ARG_ERROR(argv, i);
			}
			char list[n + 1];
			memcpy(list, argv[i], n + 1);
			conf->block_loopback = false;
			conf->block_multicast = false;
			conf->block_local = false;
			conf->block_global = false;
			for (char *tok = strtok(list, ","); tok != NULL;
			     tok = strtok(NULL, ",")) {
				if (strcmp(tok, "loopback") == 0) {
					conf->block_loopback = true;
				} else if (strcmp(tok, "multicast") == 0) {
					conf->block_multicast = true;
				} else if (strcmp(tok, "local") == 0) {
					conf->block_local = true;
				} else if (strcmp(tok, "global") == 0) {
					conf->block_global = true;
				} else {
					OPT_ARG_ERROR(argv, i);
				}
			}
			continue;
		}
		if (strcmp(argv[i], "-m") == 0 ||
		    strcmp(argv[i], "--max-sessions") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			++i;
			char *endptr;
			const uintmax_t value = strtoumax(argv[i], &endptr, 10);
			if (*endptr || value > INT_MAX) {
				OPT_ARG_ERROR(argv, i);
			}
			conf->max_sessions = (int)value;
			continue;
		}
		if (strcmp(argv[i], "--max-startups") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			++i;
			const char *nptr = argv[i];
			char *endptr = NULL;
			const uintmax_t start = strtoumax(nptr, &endptr, 10);
			if (*endptr != ':' || start > INT_MAX) {
				OPT_ARG_ERROR(argv, i);
			}
			nptr = endptr + 1;
			const uintmax_t rate = strtoumax(nptr, &endptr, 10);
			if (*endptr != ':' || rate > INT_MAX) {
				OPT_ARG_ERROR(argv, i);
			}
			nptr = endptr + 1;
			const uintmax_t full = strtoumax(nptr, &endptr, 10);
			if (*endptr != '\0' || full > INT_MAX) {
				OPT_ARG_ERROR(argv, i);
			}
			conf->startup_limit_start = (int)start;
			conf->startup_limit_rate = (int)rate;
			conf->startup_limit_full = (int)full;
			continue;
		}
		if (strcmp(argv[i], "--proto-timeout") == 0) {
			LOGW("`--proto-timeout' is deprecated, use `--bidir-timeout' instead");
			conf->bidir_timeout = true;
			continue;
		}
		if (strcmp(argv[i], "--bidir-timeout") == 0) {
			conf->bidir_timeout = true;
			continue;
		}
		if (strcmp(argv[i], "--enable-socks5-bind") == 0) {
			conf->socks5_bind = true;
			continue;
		}
		if (strcmp(argv[i], "--enable-socks5-udp") == 0) {
			conf->socks5_udp = true;
			continue;
		}
		if (strcmp(argv[i], "--") == 0) {
			break;
		}
		LOGF_F("unknown argument: `%s', try \"%s --help\" for more information",
		       argv[i], argv[0]);
		return false;
	}

#undef OPT_REQUIRE_ARG
#undef OPT_ARG_ERROR
	if (http_only) {
		conf->http_listen = conf->listen;
		conf->listen = NULL;
	}
#if WITH_LUA
	/* Save baseline before Lua overrides: all strings point into argv[] */
	baseconf = *conf;
	if (bootfile != NULL) {
		if (!conf_loadfile(bootfile, argc - 1, argv + 1, conf)) {
			return false;
		}
	}
	if (dump_config) {
		if (!conf_print(conf)) {
			return false;
		}
		return true;
	}
#endif
	slog_setlevel(conf->loglevel);
	return true;
}

bool conf_reload(struct config *restrict conf)
{
#if WITH_LUA
	if (bootfile == NULL) {
		LOGW("reload: no config file loaded");
		return false;
	}
	/* Load into a temporary built from the argv baseline; this ensures nil
	 * Lua fields revert to command-line values rather than keeping stale
	 * values from the previous reload. */
	struct config new_conf = baseconf;
	if (!conf_loadfile(bootfile, 0, NULL, &new_conf)) {
		LOGW("reload: config reload failed");
		return false;
	}
	free(conf->strings);
	*conf = new_conf;
	LOGN("reload: config successfully reloaded");
	slog_setlevel(conf->loglevel);
	return true;
#else
	LOGW("reload: not supported in current build");
	return false;
#endif
}
