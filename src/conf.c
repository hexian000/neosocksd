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

#include <ctype.h>
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
#if WITH_THREADS
		.workers = 1,
#endif
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

static bool is_valid_resolve_pf(const int resolve_pf)
{
	return resolve_pf == PF_UNSPEC || resolve_pf == PF_INET ||
	       resolve_pf == PF_INET6;
}

/* Field domains: bounds that depend only on the config's own fields. */
static bool check_ranges(const struct config *restrict conf)
{
#if WITH_TCP_KEEPALIVE_PARAMS
	/* upper bounds are the kernel's MAX_TCP_KEEPIDLE/INTVL/CNT */
	if (!RANGE_CHECK("tcp_keepidle", conf->tcp_keepidle, 0, 32767) ||
	    !RANGE_CHECK("tcp_keepintvl", conf->tcp_keepintvl, 0, 32767) ||
	    !RANGE_CHECK("tcp_keepcnt", conf->tcp_keepcnt, 0, 127)) {
		return false;
	}
#endif
#if WITH_THREADS
	/* the lower bound keeps transfer_serve's `... % nworkers' from dividing
	 * by zero; the upper one keeps the worker array clear of SIZE_MAX */
	if (!RANGE_CHECK("workers", conf->workers, 1, 1024)) {
		return false;
	}
#endif
#if WITH_RULESET
	if (!RANGE_CHECK(
		    "memlimit", conf->memlimit, INT_MIN,
		    INT_LEAST32_MAX >> 10)) {
		return false;
	}
#endif
	if (!is_valid_resolve_pf(conf->resolve_pf)) {
		LOGE_F("resolve_pf is invalid: %d", conf->resolve_pf);
		return false;
	}
	if (!RANGE_CHECK("max_sessions", conf->max_sessions, 0, INT_MAX)) {
		return false;
	}
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

/* Cross-field rules and field domains: everything conf_check refuses. Logs the
 * first violation found and emits no advisory warning. */
static bool check_rules(const struct config *restrict conf)
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
	/* the ruleset requirement depends on what the load installs: main()
	 * checks it after its load, check_reload() on a reload */

	return check_ranges(conf);
}

bool conf_check(const struct config *restrict conf)
{
	if (!check_rules(conf)) {
		return false;
	}
	if (conf->tcp_sndbuf > 0 && conf->tcp_sndbuf < 16384) {
		LOGW("tcp send buffer may be too small");
	}
	if (conf->tcp_rcvbuf > 0 && conf->tcp_rcvbuf < 16384) {
		LOGW("tcp recv buffer may be too small");
	}
#if WITH_TCP_KEEPALIVE_PARAMS
	if (!conf->tcp_keepalive &&
	    (conf->tcp_keepidle > 0 || conf->tcp_keepintvl > 0 ||
	     conf->tcp_keepcnt > 0)) {
		LOGW("tcp keepalive timing is set but keepalive is disabled");
	}
#endif
	return true;
}

void conf_advise(const struct config *restrict conf, const bool has_ruleset)
{
	if (has_ruleset && conf->proxy != NULL) {
		LOGN("the ruleset extends the `-x' proxy chain instead of replacing it");
	}
	if (!has_ruleset && conf->forward != NULL &&
	    strcmp(conf->forward, CONF_FORWARD_ANY) == 0) {
		LOGW("`-f " CONF_FORWARD_ANY
		     "' names no destination, but no ruleset is loaded to choose one");
	}
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
		"                             `:' names no destination, leaving it to the ruleset\n"
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
#if WITH_THREADS
		"  --workers <n>              number of dedicated I/O worker threads (default: 1)\n"
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
	const char *digits = *s;
	while (isspace((unsigned char)*digits)) {
		digits++;
	}
	if (*digits == '-') {
		return false;
	}
	char *endptr;
	const uintmax_t value = strtoumax(*s, &endptr, 10);
	if (endptr == *s || value > INT_MAX) {
		return false;
	}
	*s = endptr;
	*out = (int)value;
	return true;
}

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
#if WITH_THREADS
		if (strcmp(argv[i], "--workers") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			++i;
			const char *s = argv[i];
			if (!opt_parse_int(&s, &conf->workers) || *s != '\0') {
				OPT_ARG_ERROR(argv, i);
			}
			continue;
		}
#endif /* WITH_THREADS */
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
			/* Split on ',' by hand rather than with the non-reentrant
			 * strtok() the project avoids elsewhere. Empty elements
			 * (adjacent or trailing commas) are skipped, matching
			 * strtok's token semantics. */
			for (char *tok = list; tok != NULL;) {
				char *const comma = strchr(tok, ',');
				char *const next =
					(comma != NULL) ? comma + 1 : NULL;
				if (comma != NULL) {
					*comma = '\0';
				}
				if (tok[0] == '\0') {
					tok = next;
					continue;
				}
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
				tok = next;
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
		/* A boot config's `listen' is applied after this point and
		 * would silently serve SOCKS instead; it can say
		 * `http_listen' directly. */
		if (conf->listen == NULL) {
			LOGF("`--http' without an address requires `-l'");
			return false;
		}
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
#if WITH_TCP_KEEPALIVE_PARAMS
	{ "tcp_keepidle", CONF_INT, offsetof(struct config, tcp_keepidle) },
	{ "tcp_keepintvl", CONF_INT, offsetof(struct config, tcp_keepintvl) },
	{ "tcp_keepcnt", CONF_INT, offsetof(struct config, tcp_keepcnt) },
#endif
	{ "max_sessions", CONF_INT, offsetof(struct config, max_sessions) },
	{ "startup_limit_start", CONF_INT,
	  offsetof(struct config, startup_limit_start) },
	{ "startup_limit_rate", CONF_INT,
	  offsetof(struct config, startup_limit_rate) },
	{ "startup_limit_full", CONF_INT,
	  offsetof(struct config, startup_limit_full) },
#if WITH_THREADS
	{ "workers", CONF_INT, offsetof(struct config, workers) },
#endif
	{ NULL, 0, 0 },
};

static void push_field(
	lua_State *restrict L, const struct config *restrict conf,
	const struct metaconfig *restrict field)
{
	const void *value = (const char *)conf + field->offset;
	switch (field->type) {
	case CONF_STRING:
		lua_pushstring(L, *(const char *const *)value);
		break;
	case CONF_INT:
		lua_pushinteger(L, *(const int *)value);
		break;
	case CONF_DOUBLE:
		lua_pushnumber(L, *(const double *)value);
		break;
	case CONF_BOOL:
		lua_pushboolean(L, *(const bool *)value);
		break;
	}
}

void conf_pushfield(
	lua_State *restrict L, const struct config *restrict conf,
	const char *restrict key)
{
	for (const struct metaconfig *f = conf_fields; f->key != NULL; f++) {
		if (strcmp(f->key, key) == 0) {
			push_field(L, conf, f);
			return;
		}
	}
	lua_pushnil(L);
}

void conf_pushtable(lua_State *restrict L, const struct config *restrict conf)
{
	lua_createtable(L, 0, (int)ARRAY_SIZE(conf_fields) - 1);
	for (const struct metaconfig *f = conf_fields; f->key != NULL; f++) {
		push_field(L, conf, f);
		lua_setfield(L, -2, f->key);
	}
}

/* Validate and stage the field value on top of the stack. String values stay
 * anchored there until load_table copies them into the config's own block. */
static bool load_field(
	lua_State *restrict L, const struct metaconfig *restrict f,
	struct config *restrict conf)
{
	if (lua_isnil(L, -1)) {
		return true;
	}
	void *const value = (char *)conf + f->offset;
	switch (f->type) {
	case CONF_STRING:
		if (lua_type(L, -1) != LUA_TSTRING) {
			LOGE_F("boot: field `%s' must be a string", f->key);
			return false;
		}
		{
			size_t len;
			const char *const str = lua_tolstring(L, -1, &len);
			if (memchr(str, '\0', len) != NULL) {
				LOGE_F("boot: field `%s' contains a NUL byte",
				       f->key);
				return false;
			}
			*(const char **)value = str;
		}
		break;
	case CONF_INT:
		if (!lua_isinteger(L, -1)) {
			LOGE_F("boot: field `%s' must be an integer", f->key);
			return false;
		}
		{
			const lua_Integer v = lua_tointeger(L, -1);
			if (v < (lua_Integer)INT_MIN ||
			    v > (lua_Integer)INT_MAX) {
				LOGE_F("boot: field `%s' is out of range",
				       f->key);
				return false;
			}
			*(int *)value = (int)v;
		}
		break;
	case CONF_DOUBLE:
		/* lua_isnumber also accepts numeric strings. */
		if (lua_type(L, -1) != LUA_TNUMBER) {
			LOGE_F("boot: field `%s' must be a number", f->key);
			return false;
		}
		*(double *)value = (double)lua_tonumber(L, -1);
		break;
	case CONF_BOOL:
		if (lua_type(L, -1) != LUA_TBOOLEAN) {
			LOGE_F("boot: field `%s' must be a boolean", f->key);
			return false;
		}
		*(bool *)value = lua_toboolean(L, -1) != 0;
		break;
	}
	return true;
}

static bool str_equal(const char *restrict a, const char *restrict b)
{
	if (a == NULL || b == NULL) {
		return a == b;
	}
	return strcmp(a, b) == 0;
}

/* Log a field the running server applied once at startup when a reload would
 * change it. Returns whether the field is unchanged. */
static bool keep_fixed(const char *restrict key, const bool changed)
{
	if (changed) {
		LOGE_F("reload: field `%s' only takes effect on restart", key);
	}
	return !changed;
}

/* The checks a reload runs on the staged config before it becomes live: the
 * same rules main() applies at startup, and no change to what the running
 * server applied only once -- the listener addresses and socket options that
 * server_bind() set, the serve mode it chose by whether `forward' is set, and
 * the worker threads main() started. */
static bool check_reload(
	const struct config *restrict running,
	const struct config *restrict staged, const bool has_ruleset)
{
	if (!check_rules(staged)) {
		return false;
	}
	if (staged->auth_required && !has_ruleset) {
		LOGE("authentication requires a ruleset");
		return false;
	}
	bool ok = keep_fixed(
			  "listen",
			  !str_equal(running->listen, staged->listen)) &&
		  keep_fixed(
			  "http_listen",
			  !str_equal(
				  running->http_listen, staged->http_listen)) &&
		  keep_fixed(
			  "restapi",
			  !str_equal(running->restapi, staged->restapi)) &&
		  keep_fixed(
			  "forward", (running->forward == NULL) !=
					     (staged->forward == NULL));
#if WITH_TPROXY
	ok = ok && keep_fixed(
			   "transparent",
			   running->transparent != staged->transparent);
#endif
#if WITH_REUSEPORT
	ok = ok &&
	     keep_fixed("reuseport", running->reuseport != staged->reuseport);
#endif
#if WITH_TCP_FASTOPEN
	ok = ok && keep_fixed(
			   "tcp_fastopen",
			   running->tcp_fastopen != staged->tcp_fastopen);
#endif
#if WITH_THREADS
	ok = ok && keep_fixed("workers", running->workers != staged->workers);
#endif
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

static bool load_table(
	lua_State *restrict L, struct config *restrict conf, const bool reload,
	const bool has_ruleset)
{
	/* Daemonization and the target user are command-line-only settings.
	 * Reject them in configuration tables to keep process identity and
	 * daemon mode under command-line control. */
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

	/* Read each field once. Keeping its value on the Lua stack anchors strings
	 * even if a later __index changes the source table or collects garbage.
	 * No C allocation exists while any Lua access can still raise. */
	const int top = lua_gettop(L);
	luaL_checkstack(
		L, (int)ARRAY_SIZE(conf_fields), "configuration fields");
	struct config staged = *conf;
	for (const struct metaconfig *f = conf_fields; f->key != NULL; f++) {
		lua_getfield(L, top, f->key);
		if (!load_field(L, f, &staged)) {
			lua_settop(L, top);
			return false;
		}
	}
	if (!(reload ? check_reload(conf, &staged, has_ruleset) :
		       check_ranges(&staged))) {
		lua_settop(L, top);
		return false;
	}

	/* Copy both supplied and retained strings, so none refers into the old
	 * block once it is freed. All remaining operations are non-raising. */
	size_t total = 0;
	for (const struct metaconfig *f = conf_fields; f->key != NULL; f++) {
		if (f->type != CONF_STRING) {
			continue;
		}
		const char *const str = *(
			const char *const *)((const char *)&staged + f->offset);
		if (str != NULL) {
			const size_t len = strlen(str);
			if (len >= SIZE_MAX - total) {
				LOGE("boot: configuration strings are too large");
				lua_settop(L, top);
				return false;
			}
			total += len + 1;
		}
	}
	char *const block = total > 0 ? malloc(total) : NULL;
	if (total > 0 && block == NULL) {
		LOGE("boot: out of memory");
		lua_settop(L, top);
		return false;
	}
	char *pos = block;
	for (const struct metaconfig *f = conf_fields; f->key != NULL; f++) {
		if (f->type != CONF_STRING) {
			continue;
		}
		const char **const str =
			(const char **)((char *)&staged + f->offset);
		if (*str != NULL) {
			const size_t len = strlen(*str) + 1;
			memcpy(pos, *str, len);
			*str = pos;
			pos += len;
		}
	}
	lua_settop(L, top);
	free(conf->strings);
	staged.strings = block;
	*conf = staged;
	return true;
}

bool conf_loadfromtable(lua_State *restrict L, struct config *restrict conf)
{
	return load_table(L, conf, false, false);
}

bool conf_reloadfromtable(
	lua_State *restrict L, struct config *restrict conf,
	const bool has_ruleset)
{
	return load_table(L, conf, true, has_ruleset);
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
	/* a redirected stdout is fully buffered and the whole dump fits in it, so
	 * the write errors that matter surface only here */
	return ok && fflush(stdout) == 0 && ferror(stdout) == 0;
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

static int boot_openlibs(lua_State *L)
{
	luaL_openlibs(L);
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
	lua_pushcfunction(L, boot_openlibs);
	if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
		LOGE_F("config: %s", boot_errmsg(L));
		io_stream_close(s);
		lua_close(L);
		return false;
	}
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
