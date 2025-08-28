/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file main.c
 * @brief Main entry point for neosocksd
 */

/* internal */
#include "api_server.h"
#include "conf.h"
#include "dialer.h"
#include "forward.h"
#include "http_proxy.h"
#include "resolver.h"
#include "ruleset.h"
#include "server.h"
#include "session.h"
#include "socks.h"
#include "sockutil.h"
#include "util.h"

/* contrib */
#include "utils/debug.h"
#include "utils/slog.h"

/* runtime */
#include <ev.h>
#include <sys/socket.h>
#if WITH_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

/* std */
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Global application state structure
 * 
 * Contains all the main components of the neosocksd application:
 * - Signal watchers for graceful shutdown and configuration reload
 * - Configuration settings parsed from command line
 * - Main proxy server instance
 * - Optional REST API server instance
 */
static struct {
	ev_signal w_sighup;
	ev_signal w_sigint;
	ev_signal w_sigterm;

	struct config conf; /**< Parsed configuration from command line */
	struct server server; /**< Main proxy server instance */
	struct server apiserver; /**< Optional REST API server instance */
} app = { 0 };

/**
 * @brief Signal handler callback
 * @param loop Event loop instance
 * @param watcher Signal watcher that triggered
 * @param revents Event flags (should be EV_SIGNAL)
 */
static void
signal_cb(struct ev_loop *loop, ev_signal *watcher, const int revents);

/**
 * @brief Print command line usage information and examples
 * @param argv0 Program name from argv[0]
 */
static void print_usage(const char *argv0)
{
	(void)fprintf(
		stderr, "%s",
		PROJECT_NAME " " PROJECT_VER "\n"
			     "  " PROJECT_HOMEPAGE "\n\n");
	(void)fprintf(stderr, "usage: %s <option>... \n", argv0);
	(void)fprintf(
		stderr, "%s",
		"  -h, --help                 show usage and exit\n"
		"  -4, -6                     resolve requested doamin name as IPv4/IPv6 only\n"
		"  -l, --listen <address>     proxy listen address\n"
		"  --http                     run a HTTP CONNECT server instead of SOCKS\n"
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
		"  --api <bind_address>       RESTful API listen address\n"
		"  -t, --timeout <seconds>    maximum time in seconds that a halfopen connection\n"
		"                             can take (default: 60.0)\n"
		"  --proto-timeout            keep the session in halfopen state until there is\n"
		"                             bidirectional traffic\n"
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
		"\n"
		"example:\n"
		"  neosocksd -l 0.0.0.0:1080                  # start a SOCKS 4/4a/5 server\n"
		"  neosocksd -l 0.0.0.0:80 -f 127.0.0.1:8080  # forward port 80 to 8080\n"
		"  neosocksd -l 127.0.0.1:1080 -x socks5://user:pass@gate.internal:1080\n"
		"  neosocksd -l 0.0.0.0:1080 --api 127.0.1.1:9080 -r ruleset.lua\n"
		"  neosocksd -l 0.0.0.0:10500 -f : -r lb.lua\n"
		"\n");
	(void)fflush(stderr);
}

/**
 * @brief Parse command line arguments and populate configuration
 * @param argc Number of command line arguments
 * @param argv Array of command line argument strings
 * 
 * Parses all supported command line options and stores the configuration
 * in the global app.conf structure. Exits the program on invalid arguments
 * or when help is requested.
 */
static void parse_args(const int argc, char *const *const restrict argv)
{
#define OPT_REQUIRE_ARG(argc, argv, i)                                         \
	do {                                                                   \
		if ((i) + 1 >= (argc)) {                                       \
			LOGF_F("option `%s' requires an argument",             \
			       (argv)[(i)]);                                   \
			exit(EXIT_FAILURE);                                    \
		}                                                              \
	} while (false)

#define OPT_ARG_ERROR(argv, i)                                                 \
	do {                                                                   \
		LOGF_F("argument error: %s `%s'", (argv)[(i) - 1],             \
		       (argv)[(i)]);                                           \
		exit(EXIT_FAILURE);                                            \
	} while (false)

	struct config *restrict conf = &app.conf;
	*conf = conf_default();
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 ||
		    strcmp(argv[i], "--help") == 0) {
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
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
			conf->http = true;
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
			++i;
			conf->netdev = argv[i];
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
		/* If "--fastopen-connect" is specified:
		 * 1. "--pipe" may not work
		 * 2. server first protocols may not work
		 * This option will not appear in "--help" */
		if (strcmp(argv[i], "--fastopen-connect") == 0) {
			conf->tcp_fastopen_connect = true;
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
			char *s = argv[++i];
			intmax_t soft = strtoimax(s, &s, 10);
			if (soft > INT_MAX) {
				OPT_ARG_ERROR(argv, i);
			} else if (soft < 0) {
				soft = 0;
			}
			conf->memlimit = (int)soft;
			continue;
		}
#endif
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
			conf->log_level = (int)value;
			continue;
		}
		if (strcmp(argv[i], "-d") == 0 ||
		    strcmp(argv[i], "--daemonize") == 0) {
			conf->daemonize = true;
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
			char *nptr = argv[i];
			const uintmax_t start = strtoumax(nptr, &nptr, 10);
			if (*nptr != ':' || start > INT_MAX) {
				OPT_ARG_ERROR(argv, i);
			}
			nptr++;
			const uintmax_t rate = strtoumax(nptr, &nptr, 10);
			if (*nptr != ':' || rate > INT_MAX) {
				OPT_ARG_ERROR(argv, i);
			}
			nptr++;
			const uintmax_t full = strtoumax(nptr, &nptr, 10);
			if (*nptr != '\0' || full > INT_MAX) {
				OPT_ARG_ERROR(argv, i);
			}
			conf->startup_limit_start = (int)start;
			conf->startup_limit_rate = (double)rate / 100.0;
			conf->startup_limit_full = (int)full;
			continue;
		}
		if (strcmp(argv[i], "--proto-timeout") == 0) {
			conf->proto_timeout = true;
			continue;
		}
		if (strcmp(argv[i], "--") == 0) {
			break;
		}
		LOGF_F("unknown argument: `%s', try \"%s --help\" for more information",
		       argv[i], argv[0]);
		exit(EXIT_FAILURE);
	}

#undef OPT_REQUIRE_ARG
#undef OPT_ARG_ERROR
	slog_setlevel(conf->log_level);
}

int main(int argc, char **argv)
{
	/* Initialize application and parse command line arguments */
	init(argc, argv);
	parse_args(argc, argv);

	/* Validate configuration */
	const struct config *restrict conf = &app.conf;
	if (!conf_check(conf)) {
		LOGF_F("configuration check failed, try \"%s --help\" for more information",
		       argv[0]);
		exit(EXIT_FAILURE);
	}
	G.conf = conf;
	loadlibs();

	/* Parse and validate outbound connection configuration */
	G.basereq = dialreq_parse(conf->forward, conf->proxy);
	if (G.basereq == NULL) {
		LOGF("unable to parse outbound configuration");
		exit(EXIT_FAILURE);
	}

	/* Initialize the main event loop */
	struct ev_loop *loop = ev_default_loop(0);
	CHECK(loop != NULL);

	/* Initialize DNS resolver */
	G.resolver = resolver_new(loop, conf);
	CHECKOOM(G.resolver);

	/* Initialize Lua ruleset if specified */
#if WITH_RULESET
	if (conf->ruleset != NULL) {
		G.ruleset = ruleset_new(loop);
		CHECKOOM(G.ruleset);
		const bool ok = ruleset_loadfile(G.ruleset, conf->ruleset);
		if (!ok) {
			LOGE_F("ruleset load: %s",
			       ruleset_geterror(G.ruleset, NULL));
			LOGF_F("unable to load ruleset: %s", conf->ruleset);
			exit(EXIT_FAILURE);
		}
	}
#endif

	/* Initialize and configure the main proxy server */
	struct server *restrict s = &app.server;
	server_init(s, loop, NULL, NULL);

	/* Select the appropriate protocol handler based on configuration */
	if (conf->forward != NULL) {
		s->serve = forward_serve; /* TCP port forwarding */
	}
#if WITH_TPROXY
	else if (conf->transparent) {
		s->serve = tproxy_serve; /* Transparent proxy */
	}
#endif
	else if (conf->http) {
		s->serve = http_proxy_serve; /* HTTP CONNECT proxy */
	} else {
		/* default to SOCKS server */
		s->serve = socks_serve; /* SOCKS4/4a/5 proxy */
	}

	/* Parse listen address and start the main server */
	{
		union sockaddr_max bindaddr;
		if (!parse_bindaddr(&bindaddr, conf->listen)) {
			LOGF_F("unable to parse address: %s", conf->listen);
			exit(EXIT_FAILURE);
		}
		if (!server_start(s, &bindaddr.sa)) {
			LOGF("failed to start server");
			exit(EXIT_FAILURE);
		}
		G.server = s;
	}

	/* Start optional REST API server if configured */
	struct server *api = NULL;
	if (conf->restapi != NULL) {
		union sockaddr_max apiaddr;
		if (!parse_bindaddr(&apiaddr, conf->restapi)) {
			LOGF_F("unable to parse address: %s", conf->restapi);
			exit(EXIT_FAILURE);
		}
		api = &app.apiserver;
		server_init(api, loop, api_serve, s);
		if (!server_start(api, &apiaddr.sa)) {
			LOGF("failed to start api server");
			exit(EXIT_FAILURE);
		}
	}

	/* Handle user identity changes and daemonization */
	{
		struct user_ident ident, *pident = NULL;
		if (conf->user_name != NULL) {
			if (!parse_user(&ident, conf->user_name)) {
				LOGF_F("failed to parse user ident: `%s'",
				       conf->user_name);
				exit(EXIT_FAILURE);
			}
			pident = &ident;
		}
		if (conf->daemonize) {
			daemonize(pident, true, false);
		} else if (pident != NULL) {
			drop_privileges(pident);
		}
	}

	/* Set up signal watchers for graceful shutdown and configuration reload */
	{
		/* SIGHUP: reload configuration */
		ev_signal *restrict w_sighup = &app.w_sighup;
		ev_signal_init(w_sighup, signal_cb, SIGHUP);
		ev_set_priority(w_sighup, EV_MAXPRI);
		ev_signal_start(loop, w_sighup);

		/* SIGINT: graceful shutdown (Ctrl+C) */
		ev_signal *restrict w_sigint = &app.w_sigint;
		ev_signal_init(w_sigint, signal_cb, SIGINT);
		ev_set_priority(w_sigint, EV_MAXPRI);
		ev_signal_start(loop, w_sigint);

		/* SIGTERM: graceful shutdown (service stop) */
		ev_signal *restrict w_sigterm = &app.w_sigterm;
		ev_signal_init(w_sigterm, signal_cb, SIGTERM);
		ev_set_priority(w_sigterm, EV_MAXPRI);
		ev_signal_start(loop, w_sigterm);
	}

#if WITH_SYSTEMD
	(void)sd_notify(0, "READY=1");
#endif

	/* Start the main event loop - this blocks until shutdown */
	LOGN("server start");
	ev_run(loop, 0);

	/* Graceful shutdown sequence */
	if (api != NULL) {
		server_stop(api);
		api = NULL;
	}
	server_stop(s);
	G.server = NULL;
	LOGN("server shutdown gracefully");

	/* Clean up global resources */
#if WITH_RULESET
	if (G.ruleset != NULL) {
		ruleset_free(G.ruleset);
		G.ruleset = NULL;
	}
#endif
	if (G.resolver != NULL) {
		resolver_free(G.resolver);
		G.resolver = NULL;
	}
	if (G.basereq != NULL) {
		dialreq_free(G.basereq);
		G.basereq = NULL;
	}

	/* Final cleanup and exit */
	session_closeall(loop); /* Close any remaining sessions */
	ev_loop_destroy(loop); /* Destroy the event loop */
	unloadlibs(); /* Unload dynamic libraries */

	LOGD("program terminated normally");
	return EXIT_SUCCESS;
}

void signal_cb(struct ev_loop *loop, ev_signal *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_SIGNAL);

	switch (watcher->signum) {
	case SIGHUP: {
#if WITH_RULESET
#if WITH_SYSTEMD
		(void)sd_notify(0, "RELOADING=1");
#endif
		const struct config *restrict conf = G.conf;
		if (conf->ruleset == NULL || G.ruleset == NULL) {
			LOGE_F("signal %d received, but ruleset not loaded",
			       watcher->signum);
			break;
		}
		/* Attempt to reload the Lua ruleset */
		const bool ok = ruleset_loadfile(G.ruleset, conf->ruleset);
		if (!ok) {
			LOGW_F("failed to reload ruleset: %s",
			       ruleset_geterror(G.ruleset, NULL));
			break;
		}
		LOGN("ruleset successfully reloaded");
#if WITH_SYSTEMD
		(void)sd_notify(0, "READY=1");
#endif
#else
		LOGW("reload is not supported in current build");
#endif
	} break;
	case SIGINT:
	case SIGTERM:
		LOGD_F("signal %d received, breaking", watcher->signum);
#if WITH_SYSTEMD
		(void)sd_notify(0, "STOPPING=1");
#endif
		/* Break out of the main event loop to initiate graceful shutdown */
		ev_break(loop, EVBREAK_ALL);
		break;
	default:
		/* Ignore other signals */
		break;
	}
}
