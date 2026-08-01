/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"

#if WITH_LUA
#include "proto/codec.h"

#include "io/stream.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#endif

#include "io/file.h"
#include "meta/arraysize.h"
#include "utils/slog.h"

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#if WITH_LUA
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

#endif /* WITH_LUA */

/* io_filewriter() heap-allocates a stream that slog only borrows for the
 * process lifetime; cache one per standard stream so repeated --log switches
 * neither leak the prior sink nor dangle. */
static struct io_stream *log_filewriter(FILE *const f)
{
	static struct io_stream *stdout_writer = NULL;
	static struct io_stream *stderr_writer = NULL;
	struct io_stream **restrict slot =
		(f == stdout) ? &stdout_writer : &stderr_writer;
	if (*slot == NULL) {
		*slot = io_filewriter(f);
	}
	return *slot;
}

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
#else /* WITH_TPROXY */
	const bool auth_supported = (conf->forward == NULL);
#endif /* WITH_TPROXY */
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
	if (conf->proxy != NULL && conf->socks5_bind) {
		LOGE_F("%s is incompatible with forwarding proxy",
		       "SOCKS5 BIND");
		return false;
	}
	if (conf->proxy != NULL && conf->socks5_udp) {
		LOGE_F("%s is incompatible with forwarding proxy",
		       "SOCKS5 UDPASSOCIATE");
		return false;
	}
#if WITH_RULESET
	if (conf->ruleset != NULL && conf->socks5_bind) {
		LOGE_F("%s is incompatible with ruleset", "SOCKS5 BIND");
		return false;
	}
	if (conf->ruleset != NULL && conf->socks5_udp) {
		LOGE_F("%s is incompatible with ruleset",
		       "SOCKS5 UDPASSOCIATE");
		return false;
	}
#endif /* WITH_RULESET */
	if (conf->auth_required && !auth_supported) {
		LOGE("authentication is not supported in current mode");
		return false;
	}
	/* the ruleset requirement is checked in main() after loading */

	return RANGE_CHECK(
		       "loglevel", conf->loglevel, LOG_LEVEL_SILENCE,
		       LOG_LEVEL_VERYVERBOSE) &&
	       RANGE_CHECK("timeout", conf->timeout, 5.0, 86400.0) &&
	       RANGE_CHECK(
		       "startup_limit_start", conf->startup_limit_start, 0,
		       conf->startup_limit_full > 0 ? conf->startup_limit_full :
						      INT_MAX) &&
	       RANGE_CHECK(
		       "startup_limit_rate", conf->startup_limit_rate, 0,
		       100) &&
	       /* startup_limit_full == 0 means "unlimited"; the start bound
		* above already enforces start <= full when full > 0 */
	       (conf->startup_limit_full == 0 ||
		RANGE_CHECK(
			"startup_limit_full", conf->startup_limit_full,
			conf->startup_limit_start,
			conf->max_sessions > 0 ? conf->max_sessions : INT_MAX));
}

static void print_usage(const char *restrict argv0)
{
	(void)fprintf(
		stderr, "%s %s\n  %s\n\n", PROJECT_NAME, PROJECT_VER,
		PROJECT_HOMEPAGE);
	(void)fprintf(stderr, "usage: %s <option>... \n", argv0);
	(void)fprintf(
		stderr, "%s",
		"  -h, --help                 show usage and exit\n"
#if WITH_LUA
		"  -c, --config <config.lua>  load configuration from Lua script\n"
#if WITH_RULESET
		"                             the script may also set the ruleset via _G.ruleset\n"
#endif /* WITH_RULESET */
		"  --dump-config              dump the command-line configuration as Lua and exit\n"
#endif /* WITH_LUA */
		"  -4, -6                     resolve requested domain name as IPv4/IPv6 only\n"
		"  -l, --listen <address>     proxy listen address\n"
		"  --http [address]           run an HTTP proxy; if address is omitted, use -l\n"
#if WITH_RULESET
		"  --auth-required            require basic authentication\n"
#endif
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
		"  --enable-socks5-bind       enable SOCKS5 BIND command (incompatible with -r/-x)\n"
		"  --enable-socks5-udp        enable SOCKS5 UDP ASSOCIATE command (incompatible with -r/-x)\n"
		"  --api <bind_address>       RESTful API listen address\n"
		"  -t, --timeout <seconds>    maximum time in seconds that a halfopen connection\n"
		"                             can take (default: 60.0)\n"
		"  --log <output>             log destination: stdout, stderr, terminal (colorized\n"
		"                             stderr), syslog or discard\n"
		"  --loglevel <level>         0-8 are Silence, Fatal, Error, Warning, Notice, Info,\n"
		"                             Debug, Verbose, VeryVerbose respectively (default: 4)\n"
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

/* Parse a non-negative decimal integer in [0, INT_MAX] at *s. On success store
 * it in *out and advance *s past the consumed digits, leaving the terminator
 * for the caller to check; return false on a missing digit or on overflow. */
static bool opt_parse_int(const char **restrict s, int *restrict out)
{
	char *endptr;
	const uintmax_t value = strtoumax(*s, &endptr, 10);
	if (endptr == *s || value > INT_MAX) {
		return false;
	}
	*s = endptr;
	*out = (int)value;
	return true;
}

/* Install the logging sink named by a --log argument. Returns false (without
 * changing the active sink) on an unknown name or on OOM building the stream
 * writer, so the caller can fail the option instead of installing a NULL
 * writer that would silently discard every log line. */
static bool set_log_output(const char *restrict dst)
{
	if (strcmp(dst, "syslog") == 0) {
		slog_setoutput(SLOG_OUTPUT_SYSLOG, PROJECT_NAME, NULL);
		return true;
	}
	if (strcmp(dst, "discard") == 0) {
		slog_setoutput(SLOG_OUTPUT_DISCARD);
		return true;
	}
	int output;
	FILE *stream;
	if (strcmp(dst, "stdout") == 0) {
		output = SLOG_OUTPUT_STREAM;
		stream = stdout;
	} else if (strcmp(dst, "stderr") == 0) {
		output = SLOG_OUTPUT_STREAM;
		stream = stderr;
	} else if (strcmp(dst, "terminal") == 0) {
		output = SLOG_OUTPUT_TERMINAL;
		stream = stderr;
	} else {
		return false;
	}
	/* io_filewriter closes the stream and returns NULL on OOM */
	struct io_stream *const w = log_filewriter(stream);
	if (w == NULL) {
		return false;
	}
	slog_setoutput(output, w);
	return true;
}

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

	*conf = conf_default();
	bool http_only = false;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 ||
		    strcmp(argv[i], "--help") == 0) {
			print_usage(argv[0]);
			return false;
		}
#if WITH_LUA
		if (strcmp(argv[i], "-c") == 0 ||
		    strcmp(argv[i], "--config") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			conf->boot = argv[++i];
			continue;
		}
#endif /* WITH_LUA */
#if WITH_LUA
		if (strcmp(argv[i], "--dump-config") == 0) {
			conf->dump_config = true;
			continue;
		}
#endif /* WITH_LUA */
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
#if WITH_RULESET
		if (strcmp(argv[i], "--auth-required") == 0) {
			conf->auth_required = true;
			continue;
		}
#endif /* WITH_RULESET */
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
			if (*endptr != '\0' || endptr == argv[i] ||
			    soft > INT_MAX / 1024) {
				OPT_ARG_ERROR(argv, i);
			} else if (soft < 0) {
				soft = 0;
			}
			conf->memlimit = (int)soft;
			continue;
		}
#endif /* WITH_RULESET */
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
			if (endptr == argv[i] || argv[i] + n != endptr) {
				OPT_ARG_ERROR(argv, i);
			}
			continue;
		}
		if (strcmp(argv[i], "--log") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			++i;
			if (!set_log_output(argv[i])) {
				OPT_ARG_ERROR(argv, i);
			}
			continue;
		}
		if (strcmp(argv[i], "--loglevel") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			++i;
			const char *s = argv[i];
			if (!opt_parse_int(&s, &conf->loglevel) || *s != '\0') {
				OPT_ARG_ERROR(argv, i);
			}
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
			const char *s = argv[i];
			if (!opt_parse_int(&s, &conf->max_sessions) ||
			    *s != '\0') {
				OPT_ARG_ERROR(argv, i);
			}
			continue;
		}
		if (strcmp(argv[i], "--max-startups") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			++i;
			const char *s = argv[i];
			if (!opt_parse_int(&s, &conf->startup_limit_start) ||
			    *s != ':') {
				OPT_ARG_ERROR(argv, i);
			}
			s++;
			if (!opt_parse_int(&s, &conf->startup_limit_rate) ||
			    *s != ':') {
				OPT_ARG_ERROR(argv, i);
			}
			s++;
			if (!opt_parse_int(&s, &conf->startup_limit_full) ||
			    *s != '\0') {
				OPT_ARG_ERROR(argv, i);
			}
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
#if WITH_RULESET
	if (conf->boot != NULL && conf->ruleset != NULL) {
		LOGF("`-c'/`--config' and `-r'/`--ruleset' are mutually exclusive");
		return false;
	}
#endif
	if (http_only) {
		conf->http_listen = conf->listen;
		conf->listen = NULL;
	}
	slog_setlevel(conf->loglevel);
	return true;
}

#if WITH_LUA
/* Descriptor table: one entry per struct config field, terminated by key=NULL. */
static const struct metaconfig conf_fields[] = {
	{ "listen", CONF_STRING, offsetof(struct config, listen) },
	{ "forward", CONF_STRING, offsetof(struct config, forward) },
	{ "proxy", CONF_STRING, offsetof(struct config, proxy) },
	{ "restapi", CONF_STRING, offsetof(struct config, restapi) },
	{ "http_listen", CONF_STRING, offsetof(struct config, http_listen) },
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
	{ "auth_required", CONF_BOOL, offsetof(struct config, auth_required) },
#endif
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
	{ "socks5_bind", CONF_BOOL, offsetof(struct config, socks5_bind) },
	{ "socks5_udp", CONF_BOOL, offsetof(struct config, socks5_udp) },
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

/* Validate or apply one non-string config field from Lua stack top; not for CONF_STRING. */
static bool load_field(
	lua_State *restrict L, const struct metaconfig *restrict f,
	struct config *restrict conf, const bool apply)
{
	lua_getfield(L, -1, f->key);
	const bool isnil = lua_isnil(L, -1);
	bool ok = true;
	switch (f->type) {
	case CONF_STRING:
		/* String fields are handled in conf_loadfromtable. */
		break;
	case CONF_INT:
		if (!isnil && !lua_isinteger(L, -1)) {
			LOGE_F("boot: field `%s' must be an integer", f->key);
			ok = false;
			break;
		}
		if (isnil) {
			break;
		}
		{
			const lua_Integer v = lua_tointeger(L, -1);
			if (v < (lua_Integer)INT_MIN ||
			    v > (lua_Integer)INT_MAX) {
				LOGE_F("boot: field `%s' is out of range",
				       f->key);
				ok = false;
				break;
			}
			if (apply) {
				*(int *)((char *)conf + f->offset) = (int)v;
			}
		}
		break;
	case CONF_DOUBLE:
		/* lua_type, not lua_isnumber: the latter also accepts a numeric
		 * string, unlike the strict CONF_INT/CONF_BOOL checks. */
		if (!isnil && lua_type(L, -1) != LUA_TNUMBER) {
			LOGE_F("boot: field `%s' must be a number", f->key);
			ok = false;
			break;
		}
		if (!isnil && apply) {
			*(double *)((char *)conf + f->offset) =
				(double)lua_tonumber(L, -1);
		}
		break;
	case CONF_BOOL:
		if (!isnil && lua_type(L, -1) != LUA_TBOOLEAN) {
			LOGE_F("boot: field `%s' must be a boolean", f->key);
			ok = false;
			break;
		}
		if (!isnil && apply) {
			*(bool *)((char *)conf + f->offset) =
				lua_toboolean(L, -1) != 0;
		}
		break;
	}
	lua_pop(L, 1);
	return ok;
}

static const char *boot_errmsg(lua_State *restrict L);

/* Context for conf_fill_fields, passed as a light-userdata upvalue. */
struct conf_fill {
	struct config *conf;
	char *block;
	size_t total;
};

/* Apply the non-string fields and copy the string fields into the pre-measured
 * `block`. conf_loadfromtable runs this under lua_pcall so that a config-table
 * __index which raises on this second field-access pass is caught -- letting
 * the caller free `block` instead of leaking it through the longjmp. The
 * string field pointers are not repointed into `block` until the whole pass has
 * succeeded, so a mid-pass raise leaves `conf`'s existing pointers intact rather
 * than dangling into the block the caller then frees. The fill context is the
 * first argument (a light userdata); the config table is the second (stack
 * top). */
static int conf_fill_fields(lua_State *restrict L)
{
	const struct conf_fill *restrict const fill = lua_touserdata(L, 1);
	struct config *restrict const conf = fill->conf;

	/* Every field has now been validated; apply non-string fields. */
	for (const struct metaconfig *f = conf_fields; f->key != NULL; f++) {
		if (f->type == CONF_STRING) {
			continue;
		}
		(void)load_field(L, f, conf, true);
	}

	/* Copy string fields into the new block: a Lua-provided string replaces
	 * the field; a nil value carries the field's current string forward so it
	 * never dangles into the block freed on a failed load. The resulting
	 * pointers are staged and only committed to `conf` once the whole pass
	 * completes without raising. */
	if (fill->total > 0) {
		const char *newptr[ARRAY_SIZE(conf_fields)];
		char *pos = fill->block;
		char *const blockend = fill->block + fill->total;
		for (const struct metaconfig *f = conf_fields; f->key != NULL;
		     f++) {
			if (f->type != CONF_STRING) {
				continue;
			}
			const char **fptr =
				(const char **)((char *)conf + f->offset);
			newptr[f - conf_fields] = *fptr;
			lua_getfield(L, -1, f->key);
			const char *s;
			size_t len = 0;
			if (lua_type(L, -1) == LUA_TSTRING) {
				s = lua_tolstring(L, -1, &len);
			} else {
				s = *fptr;
				if (s != NULL) {
					len = strlen(s);
				}
			}
			if (s != NULL) {
				/* clamp to the measured block: a stateful __index
				 * could return a longer string on this second
				 * lua_getfield, which must not overflow `block` */
				const size_t avail = (size_t)(blockend - pos);
				if (avail == 0) {
					newptr[f - conf_fields] = "";
				} else {
					if (len + 1 > avail) {
						len = avail - 1;
					}
					memcpy(pos, s, len);
					pos[len] = '\0';
					newptr[f - conf_fields] = pos;
					pos += len + 1;
				}
			}
			lua_pop(L, 1);
		}
		/* the pass raised nowhere above; commit the staged pointers */
		for (const struct metaconfig *f = conf_fields; f->key != NULL;
		     f++) {
			if (f->type != CONF_STRING) {
				continue;
			}
			*(const char **)((char *)conf + f->offset) =
				newptr[f - conf_fields];
		}
	}
	return 0;
}

bool conf_loadfromtable(lua_State *restrict L, struct config *restrict conf)
{
	/* daemonize and user_name are consumed in main() before any boot config
	 * is loaded -- daemonization must precede thread creation -- so they can
	 * only take effect from the command line. Reject them rather than accept
	 * a setting that would silently do nothing (notably user_name, which
	 * would otherwise leave the process running as root). */
	static const char *const cli_only[] = { "daemonize", "user_name" };
	for (size_t i = 0; i < ARRAY_SIZE(cli_only); i++) {
		lua_getfield(L, -1, cli_only[i]);
		const bool present = !lua_isnil(L, -1);
		lua_pop(L, 1);
		if (present) {
			LOGE_F("boot: field `%s' can only be set on the command line",
			       cli_only[i]);
			return false;
		}
	}

	/* Validate every field first (read-only): non-string fields, then
	 * string fields together with measuring the replacement string
	 * block below. No field is mutated until all of them check out, so
	 * a failure anywhere never leaves the config partially updated. */
	for (const struct metaconfig *f = conf_fields; f->key != NULL; f++) {
		if (f->type == CONF_STRING) {
			continue;
		}
		if (!load_field(L, f, conf, false)) {
			return false;
		}
	}

	/* Measure the block size for string fields. A Lua-provided string
	 * needs room for its own bytes; a nil value carries the field's
	 * current string forward (if any) instead of leaving it pointing
	 * into the old block this call frees below, which would dangle the
	 * moment a later call's table nils out a field a prior call set. */
	size_t total = 0;
	for (const struct metaconfig *f = conf_fields; f->key != NULL; f++) {
		if (f->type != CONF_STRING) {
			continue;
		}
		lua_getfield(L, -1, f->key);
		if (lua_isnil(L, -1)) {
			const char *const *const fptr =
				(const char *const *)((const char *)conf +
						      f->offset);
			if (*fptr != NULL) {
				total += strlen(*fptr) + 1;
			}
		} else if (lua_type(L, -1) == LUA_TSTRING) {
			size_t len;
			lua_tolstring(L, -1, &len);
			total += len + 1;
		} else {
			LOGE_F("boot: field `%s' must be a string", f->key);
			lua_pop(L, 1);
			return false;
		}
		lua_pop(L, 1);
	}

	/* Allocate single block for all strings */
	char *restrict block = (total > 0) ? malloc(total) : NULL;
	if (total > 0 && block == NULL) {
		LOGE("boot: out of memory");
		return false;
	}

	/* Apply the non-string fields and fill `block` under a protected call:
	 * a config-table __index that raises on this second field-access pass
	 * must fail the load without leaking `block` or dangling a string field
	 * into it (conf_fill_fields defers the field pointers until it is done).
	 * The fill context rides in as a light-userdata argument and the body as a
	 * plain cfunction, so nothing between the malloc above and lua_pcall can
	 * raise: lua_pushcclosure would allocate its closure and could itself raise
	 * LUA_ERRMEM, leaking `block` through the caught longjmp, whereas these
	 * pushes cannot. */
	struct conf_fill fill = {
		.conf = conf,
		.block = block,
		.total = total,
	};
	lua_pushcfunction(L, conf_fill_fields);
	lua_pushlightuserdata(L, &fill);
	lua_pushvalue(L, -3); /* the config table, as the second argument */
	if (lua_pcall(L, 2, 0, 0) != LUA_OK) {
		LOGE_F("boot: %s", boot_errmsg(L));
		lua_pop(L, 1);
		free(block);
		return false;
	}

	free(conf->strings);
	conf->strings = block;
	return true;
}

/* Write a Lua double-quoted string literal for s. */
static bool print_string(const char *restrict s)
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
			/* zero-padded to exactly 3 digits: Lua's decimal escape
			 * greedily consumes up to 3 following digits, so an
			 * unpadded \7 followed by a literal '1' re-parses as
			 * the single escape \71 instead of \7 then '1' */
			if (fprintf(stdout, "\\%03u", (unsigned int)c) < 0) {
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
static bool print_field(
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
		} else if (!print_string(s)) {
			return false;
		}
	} break;
	case CONF_INT:
		if (fprintf(stdout, "%d", *(const int *)ptr) < 0) {
			return false;
		}
		break;
	case CONF_DOUBLE:
		/* %g's default 6 significant digits truncates the value;
		 * 17 significant digits always round-trip a double exactly */
		if (fprintf(stdout, "%.17g", *(const double *)ptr) < 0) {
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
		ok = print_field(field, conf);
	}
	if (ok) {
		ok = fputs("}\n", stdout) != EOF;
	}
	return ok;
}

/* Format the Lua error object on the stack top for logging. lua_tostring is
 * only safe on a string; a non-string error object (error({}), error(nil))
 * yields NULL, and passing NULL to slog's "%s" is undefined behavior. This
 * state installs no panic handler, so luaL_tolstring's __tostring dispatch
 * could itself raise and abort() -- mirror ruleset.c's l_panic instead. */
static const char *boot_errmsg(lua_State *restrict L)
{
	if (lua_type(L, -1) == LUA_TSTRING) {
		return lua_tostring(L, -1);
	}
	return "error object is not a string";
}

/* Protected body of conf_loadboot: guards against a `ruleset` field and applies
 * the config table. Run under lua_pcall so a raising __index metamethod on the
 * config table surfaces as a catchable error instead of aborting the process
 * (this luaL_newstate installs no panic handler). Arguments: the config table
 * and a light userdata pointing at the struct config to fill. */
static int conf_apply_boot(lua_State *restrict L)
{
	struct config *restrict const conf = lua_touserdata(L, 2);
	lua_settop(L, 1); /* conf_loadfromtable reads the table at the top */
	lua_getfield(L, 1, "ruleset");
	if (!lua_isnil(L, -1)) {
		return luaL_error(
			L,
			"`ruleset' field requires a build with ruleset support");
	}
	lua_pop(L, 1);
	if (!conf_loadfromtable(L, conf)) {
		return luaL_error(L, "failed to load config fields");
	}
	return 0;
}

bool conf_loadboot(struct config *restrict conf, const char *restrict filename)
{
	struct io_stream *restrict const s = codec_lua_reader(filename);
	if (s == NULL) {
		return false;
	}
	lua_State *restrict const L = luaL_newstate();
	if (L == NULL) {
		io_stream_close(s);
		LOGE("config: out of memory");
		return false;
	}
	luaL_openlibs(L);
	struct codec_lua_stream rs = { .stream = s,
				       .errlabel = "config: read error",
				       .err = 0 };
	const int status =
		lua_load(L, codec_lua_stream_read, &rs, "=config", "t");
	/* the close carries errors the reader cannot see, e.g. a codec
	 * detecting a truncated stream only as it finishes */
	const int closeerr = io_stream_close(s);
	if (status != LUA_OK) {
		LOGE_F("config: %s", boot_errmsg(L));
		lua_close(L);
		return false;
	}
	if (rs.err != 0 || closeerr != 0) {
		/* the chunk lua_load() compiled is truncated by a read error;
		 * codec_lua_stream_read already logged rs.err, so re-log only
		 * closeerr, which the reader never sees (e.g. a codec detecting
		 * a truncated stream as it finishes) */
		if (rs.err == 0) {
			LOGE_F("config: read error %d", closeerr);
		}
		lua_close(L);
		return false;
	}
	lua_pushliteral(L, "config");
	if (lua_pcall(L, 1, 1, 0) != LUA_OK) {
		LOGE_F("config: %s", boot_errmsg(L));
		lua_close(L);
		return false;
	}
	if (!lua_istable(L, -1)) {
		LOGE_F("config: expected table, got %s", luaL_typename(L, -1));
		lua_close(L);
		return false;
	}
	/* Extract the config fields under protection: lua_getfield can invoke an
	 * __index metamethod that raises, which without a protected frame would
	 * hit Lua's default panic and abort() the process. */
	lua_pushcfunction(L, conf_apply_boot);
	lua_insert(L, -2); /* [conf_apply_boot, config table] */
	lua_pushlightuserdata(L, conf); /* [conf_apply_boot, table, conf] */
	if (lua_pcall(L, 2, 0, 0) != LUA_OK) {
		LOGE_F("config: %s", boot_errmsg(L));
		lua_close(L);
		return false;
	}
	lua_close(L);
	return true;
}
#endif /* WITH_LUA */
