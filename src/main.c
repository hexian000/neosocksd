#include "utils/slog.h"
#include "utils/check.h"
#include "utils/minmax.h"
#include "forward.h"
#include "http.h"
#include "socks.h"
#include "ruleset.h"
#include "conf.h"
#include "server.h"
#include "sockutil.h"
#include "util.h"

#include <ev.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

static struct {
	const char *listen;
	const char *forward;
	const char *restapi;
	const char *ruleset;
#if WITH_NETDEVICE
	const char *netdev;
#endif
	bool http : 1;
	bool proto_timeout : 1;
#if WITH_REUSEPORT
	bool reuseport : 1;
#endif
#if WITH_FASTOPEN
	bool fastopen : 1;
#endif
#if WITH_TPROXY
	bool tproxy : 1;
#endif
	bool traceback : 1;
	bool daemonize : 1;
	int verbosity;
	int resolve_pf;
	const char *user_name;
	double timeout;

	size_t max_sessions;
	size_t startup_limit_start;
	size_t startup_limit_rate;
	size_t startup_limit_full;
} args = {
	.verbosity = LOG_LEVEL_INFO,
	.resolve_pf = PF_UNSPEC,
	.timeout = 60.0,

	.max_sessions = 4096,
	.startup_limit_start = 10,
	.startup_limit_rate = 30,
	.startup_limit_full = 100,
};

static struct {
	struct ev_signal w_sighup;
	struct ev_signal w_sigint;
	struct ev_signal w_sigterm;

	struct config conf;
	struct server server;

	struct {
		bool running : 1;
		struct server server;
	} api;

	/* ruleset is a singleton */
	struct ruleset *ruleset;
} app = {
	.api.running = false,
	.ruleset = NULL,
};

static void
signal_cb(struct ev_loop *loop, struct ev_signal *watcher, int revents);

static void print_usage(const char *argv0)
{
	fprintf(stderr, "%s",
		PROJECT_NAME " " PROJECT_VER "\n"
			     "  " PROJECT_HOMEPAGE "\n\n");
	fprintf(stderr, "usage: %s <option>... \n", argv0);
	fprintf(stderr, "%s",
		"  -h, --help                 show usage and exit\n"
		"  -4, -6                     resolve requested doamin name as IPv4/IPv6 only\n"
		"  -l, --listen <address>     proxy listen address\n"
		"  --http                     run a HTTP CONNECT server instead of SOCKS\n"
		"  -f, --forward <address>    run simple TCP port forwarding instead of SOCKS\n"
#if WITH_NETDEVICE
		"  -i, --netdev <name>        restrict network device used by outgoing connections\n"
#endif
#if WITH_REUSEPORT
		"  --reuseport                allow multiple instances to listen on the same address\n"
#endif
#if WITH_FASTOPEN
		"  --fastopen                 enable server-side TCP fast open (RFC 7413)\n"
#endif
#if WITH_TPROXY
		"  --tproxy                   operate as a transparent proxy\n"
#endif
		"  -r, --ruleset <file>       load ruleset from Lua file\n"
		"  --api <bind_address>       RESTful API for monitoring\n"
		"  --traceback                print ruleset error traceback (for debugging)\n"
		"  -t, --timeout <seconds>    maximum time in seconds that a halfopen connection\n"
		"                             can take (default: 60.0)\n"
		"  -d, --daemonize            run in background and discard all logs\n"
		"  -u, --user <name>          run as the specified limited user\n"
		"  -v, --verbose              increase logging verbosity, can be specified more\n"
		"                             than once. e.g. \"-v -v\" prints verbose messages\n"
		"  -s, --silence              decrease logging verbosity\n"
		"  -m, --max-sessions <n>     maximum number of concurrent connections\n"
		"                             (default: 4096, 0: unlimited)\n"
		"  --max-startups <start:rate:full>\n"
		"                             maximum number of concurrent halfopen connections\n"
		"                             (default: 10:30:100)\n"
		"  --proto-timeout            keep the session in halfopen state until there is\n"
		"                             bidirectional traffic\n"
		"\n"
		"example:\n"
		"  neosocksd -l 0.0.0.0:1080                  # start a SOCKS 4/4a/5 server\n"
		"  neosocksd -l 0.0.0.0:80 -f 127.0.0.1:8080  # forward port 80 to 8080\n"
		"\n");
	fflush(stderr);
}

static void parse_args(const int argc, char *const *const restrict argv)
{
#define OPT_REQUIRE_ARG(argc, argv, i)                                         \
	do {                                                                   \
		if ((i) + 1 >= (argc)) {                                       \
			LOGF_F("option \"%s\" requires an argument\n",         \
			       (argv)[(i)]);                                   \
			exit(EXIT_FAILURE);                                    \
		}                                                              \
	} while (false)

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 ||
		    strcmp(argv[i], "--help") == 0) {
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
		if (strcmp(argv[i], "-4") == 0) {
			args.resolve_pf = PF_INET;
			continue;
		}
		if (strcmp(argv[i], "-6") == 0) {
			args.resolve_pf = PF_INET6;
			continue;
		}
		if (strcmp(argv[i], "-l") == 0 ||
		    strcmp(argv[i], "--listen") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			args.listen = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "-f") == 0 ||
		    strcmp(argv[i], "--forward") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			args.forward = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "--http") == 0) {
			args.http = true;
			continue;
		}
		if (strcmp(argv[i], "--tproxy") == 0) {
#if WITH_TPROXY
			args.tproxy = true;
#else
			LOGF_F("unsupported argument: \"%s\"", argv[i]);
			exit(EXIT_FAILURE);
#endif
			continue;
		}
		if (strcmp(argv[i], "-i") == 0 ||
		    strcmp(argv[i], "--netdev") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
#if WITH_NETDEVICE
			args.netdev = argv[++i];
#else
			LOGW_F("unsupported argument: \"%s\"", argv[i]);
			i++;
#endif
			continue;
		}
		if (strcmp(argv[i], "--reuseport") == 0) {
#if WITH_REUSEPORT
			args.reuseport = true;
#else
			LOGW_F("unsupported argument: \"%s\"", argv[i]);
#endif
			continue;
		}
		if (strcmp(argv[i], "--fastopen") == 0) {
#if WITH_FASTOPEN
			args.fastopen = true;
#else
			LOGW_F("unsupported argument: \"%s\"", argv[i]);
#endif
			continue;
		}
		if (strcmp(argv[i], "--api") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			args.restapi = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "-r") == 0 ||
		    strcmp(argv[i], "--ruleset") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			args.ruleset = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "-u") == 0 ||
		    strcmp(argv[i], "--user") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			args.user_name = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "-t") == 0 ||
		    strcmp(argv[i], "--timeout") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			++i;
			if (sscanf(argv[i], "%lf", &args.timeout) != 1) {
				LOGF_F("can't parse \"%s\"\n", argv[i]);
				exit(EXIT_FAILURE);
			}
			if (!(1e-3 <= args.timeout && args.timeout <= 1e+9)) {
				LOGF_F("invalid timeout \"%s\"\n", argv[i]);
				exit(EXIT_FAILURE);
			}
			continue;
		}
		if (strcmp(argv[i], "-v") == 0 ||
		    strcmp(argv[i], "--verbose") == 0) {
			args.verbosity++;
			continue;
		}
		if (strcmp(argv[i], "-s") == 0 ||
		    strcmp(argv[i], "--silence") == 0) {
			args.verbosity--;
			continue;
		}
		if (strcmp(argv[i], "-d") == 0 ||
		    strcmp(argv[i], "--daemonize") == 0) {
			args.daemonize = true;
			continue;
		}
		if (strcmp(argv[i], "--traceback") == 0) {
			args.traceback = true;
			continue;
		}
		if (strcmp(argv[i], "-m") == 0 ||
		    strcmp(argv[i], "--max-sessions") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			++i;
			if (sscanf(argv[i], "%zu", &args.max_sessions) != 1) {
				LOGF_F("can't parse \"%s\"\n", argv[i]);
				exit(EXIT_FAILURE);
			}
			continue;
		}
		if (strcmp(argv[i], "--max-startups") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			++i;
			if (sscanf(argv[i], "%zu:%zu:%zu",
				   &args.startup_limit_start,
				   &args.startup_limit_rate,
				   &args.startup_limit_full) != 3) {
				LOGF_F("can't parse \"%s\"\n", argv[i]);
				exit(EXIT_FAILURE);
			}
			continue;
		}
		if (strcmp(argv[i], "--proto-timeout") == 0) {
			args.proto_timeout = true;
			continue;
		}
		if (strcmp(argv[i], "--") == 0) {
			break;
		}
		LOGF_F("unknown argument: \"%s\"", argv[i]);
		exit(EXIT_FAILURE);
	}

#undef OPT_REQUIRE_ARG
}

int main(int argc, char **argv)
{
	init();

	parse_args(argc, argv);
	slog_level =
		CLAMP(args.verbosity, LOG_LEVEL_SILENCE, LOG_LEVEL_VERBOSE);
	if (args.listen == NULL) {
		LOGF("listen address not specified");
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (args.daemonize) {
		daemonize();
	}

	struct ev_loop *loop = ev_default_loop(0);
	CHECK(loop != NULL);

	/* signal watchers */
	{
		struct ev_signal *restrict w_sighup = &app.w_sighup;
		ev_signal_init(w_sighup, signal_cb, SIGHUP);
		ev_signal_start(loop, w_sighup);
		struct ev_signal *restrict w_sigint = &app.w_sigint;
		ev_signal_init(w_sigint, signal_cb, SIGINT);
		ev_signal_start(loop, w_sigint);
		struct ev_signal *restrict w_sigterm = &app.w_sigterm;
		ev_signal_init(w_sigterm, signal_cb, SIGTERM);
		ev_signal_start(loop, w_sigterm);
	}

	app.conf = (struct config)
	{
		.forward = args.forward, .resolve_pf = args.resolve_pf,
#if WITH_NETDEVICE
		.netdev = args.netdev,
#endif
		.proto_timeout = args.proto_timeout,
#if WITH_REUSEPORT
		.reuseport = args.reuseport,
#endif
#if WITH_FASTOPEN
		.fastopen = args.fastopen,
#endif
#if WITH_TPROXY
		.transparent = args.tproxy,
#endif
		.traceback = args.traceback, .timeout = args.timeout,

		.max_sessions = args.max_sessions,
		.startup_limit_start = args.startup_limit_start,
		.startup_limit_rate = args.startup_limit_rate,
		.startup_limit_full = args.startup_limit_full,
	};
	if (args.ruleset != NULL) {
		app.ruleset = ruleset_new(loop, &app.conf);
		CHECKOOM(app.ruleset);
		const char *err = ruleset_loadfile(app.ruleset, args.ruleset);
		if (err != NULL) {
			LOGF_F("unable to load ruleset: %s", args.ruleset);
			exit(EXIT_FAILURE);
		}
	}

	sockaddr_max_t bindaddr;
	if (!parse_bindaddr(&bindaddr, args.listen)) {
		LOGF_F("unable to parse address: %s", args.listen);
		exit(EXIT_FAILURE);
	}

	server_init(&app.server, loop, &app.conf, app.ruleset, NULL, NULL);
	if (args.forward != NULL
#if WITH_TPROXY
	    || args.tproxy
#endif
	) {
		app.server.serve = forward_serve;
	} else if (args.http) {
		app.server.serve = http_proxy_serve;
	} else {
		/* default to SOCKS server */
		app.server.serve = socks_serve;
	}

	if (!server_start(&app.server, &bindaddr.sa)) {
		FAILMSG("failed to start server");
	}

	if (args.restapi != NULL) {
		sockaddr_max_t apiaddr;
		if (!parse_bindaddr(&apiaddr, args.restapi)) {
			LOGF_F("unable to parse address: %s", args.restapi);
			exit(EXIT_FAILURE);
		}
		server_init(
			&app.api.server, loop, &app.conf, app.ruleset,
			http_api_serve, &app.server);
		if (!server_start(&app.api.server, &apiaddr.sa)) {
			FAILMSG("failed to start api server");
		}
		app.api.running = true;
	}

	drop_privileges(args.user_name);
	/* start event loop */
	LOGI("server start");
	ev_run(loop, 0);

	LOGI("server stop");
	if (app.api.running) {
		server_stop(&app.api.server);
		app.api.running = false;
	}
	server_stop(&app.server);
	if (app.ruleset != NULL) {
		ruleset_free(app.ruleset);
		app.ruleset = NULL;
	}

	ev_signal_stop(loop, &app.w_sighup);
	ev_signal_stop(loop, &app.w_sigint);
	ev_signal_stop(loop, &app.w_sigterm);

	LOGI("program terminated normally.");
	return EXIT_SUCCESS;
}

static void
signal_cb(struct ev_loop *loop, struct ev_signal *watcher, int revents)
{
	UNUSED(revents);

	switch (watcher->signum) {
	case SIGHUP: {
		if (args.ruleset == NULL || app.ruleset == NULL) {
			LOGE_F("signal %d received, but ruleset not loaded",
			       watcher->signum);
			break;
		}
		const char *err = ruleset_loadfile(app.ruleset, args.ruleset);
		if (err != NULL) {
			LOGE_F("failed to reload ruleset: %s", err);
			break;
		}
		LOGI("ruleset successfully reloaded");
	} break;
	case SIGINT:
	case SIGTERM:
		LOGI_F("signal %d received, breaking", watcher->signum);
		ev_break(loop, EVBREAK_ALL);
		break;
	}
}
