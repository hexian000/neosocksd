/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "utils/slog.h"
#include "utils/check.h"
#include "utils/minmax.h"
#include "dialer.h"
#include "session.h"
#include "forward.h"
#include "http.h"
#include "socks.h"
#include "resolver.h"
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
	struct ev_signal w_sighup;
	struct ev_signal w_sigint;
	struct ev_signal w_sigterm;

	struct config conf;
	struct server server;
	struct server apiserver;
} app = { 0 };

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
		"  -f, --forward <address>[[[,proxyN],...],proxy1]\n"
		"                             run TCP port forwarding instead of SOCKS\n"
#if WITH_CARES
		"  --nameserver <address>     use specified nameserver instead of resolv.conf\n"
#endif
#if WITH_NETDEVICE
		"  -i, --netdev <name>        bind outgoing connections to network device\n"
#endif
#if WITH_REUSEPORT
		"  --reuseport                allow multiple instances to listen on the same address\n"
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
		"  --memlimit <limit>         set a soft limit on the Lua heap size in MiB\n"
#endif
		"  --api <bind_address>       RESTful API for monitoring\n"
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
			LOGF_F("option \"%s\" requires an argument",           \
			       (argv)[(i)]);                                   \
			exit(EXIT_FAILURE);                                    \
		}                                                              \
	} while (false)

#define OPT_ARG_ERROR(argv, i)                                                 \
	do {                                                                   \
		LOGF_F("argument error: %s \"%s\"", (argv)[(i)-1],             \
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
#if WITH_TCP_FASTOPEN
		if (strcmp(argv[i], "--no-fastopen") == 0) {
			conf->tcp_fastopen = false;
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
			if (sscanf(argv[i], "%zu", &conf->memlimit) != 1) {
				OPT_ARG_ERROR(argv, i);
			}
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
		if (strcmp(argv[i], "-v") == 0 ||
		    strcmp(argv[i], "--verbose") == 0) {
			conf->log_level++;
			continue;
		}
		if (strcmp(argv[i], "-s") == 0 ||
		    strcmp(argv[i], "--silence") == 0) {
			conf->log_level--;
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
			if (sscanf(argv[i], "%zu", &conf->max_sessions) != 1) {
				OPT_ARG_ERROR(argv, i);
			}
			continue;
		}
		if (strcmp(argv[i], "--max-startups") == 0) {
			OPT_REQUIRE_ARG(argc, argv, i);
			++i;
			if (sscanf(argv[i], "%zu:%zu:%zu",
				   &conf->startup_limit_start,
				   &conf->startup_limit_rate,
				   &conf->startup_limit_full) != 3) {
				OPT_ARG_ERROR(argv, i);
			}
			continue;
		}
		if (strcmp(argv[i], "--proto-timeout") == 0) {
			conf->proto_timeout = true;
			continue;
		}
		if (strcmp(argv[i], "--") == 0) {
			break;
		}
		LOGF_F("unknown argument: \"%s\"", argv[i]);
		exit(EXIT_FAILURE);
	}

#undef OPT_REQUIRE_ARG
#undef OPT_ARG_ERROR
}

int main(int argc, char **argv)
{
	setup(argc, argv);
	parse_args(argc, argv);
	const struct config *restrict conf = &app.conf;
	if (!conf_check(conf)) {
		LOGF_F("configuration check failed, try \"%s --help\" for more information",
		       argv[0]);
		exit(EXIT_FAILURE);
	}
	G.conf = conf;
	slog_level = conf->log_level;
	init();

	struct ev_loop *loop = ev_default_loop(0);
	CHECK(loop != NULL);

	G.resolver = resolver_new(loop, conf);
	CHECKOOM(G.resolver);

#if WITH_RULESET
	if (conf->ruleset != NULL) {
		G.ruleset = ruleset_new(loop);
		CHECKOOM(G.ruleset);
		const bool ok = ruleset_loadfile(G.ruleset, conf->ruleset);
		if (!ok) {
			LOGE_F("ruleset load: %s", ruleset_error(G.ruleset));
			LOGF_F("unable to load ruleset: %s", conf->ruleset);
			exit(EXIT_FAILURE);
		}
	}
#endif

	struct server *restrict s = &app.server;
	server_init(s, loop, NULL, NULL);
	if (conf->forward != NULL) {
		struct dialreq *req = dialreq_parse(conf->forward);
		if (req == NULL) {
			LOGF_F("unable to parse forward: \"%s\"",
			       conf->forward);
			exit(EXIT_FAILURE);
		}
		s->serve = forward_serve;
		s->data = req;
	}
#if WITH_TPROXY
	else if (conf->transparent) {
		s->serve = tproxy_serve;
	}
#endif
	else if (conf->http) {
		s->serve = http_proxy_serve;
	} else {
		/* default to SOCKS server */
		s->serve = socks_serve;
	}

	{
		sockaddr_max_t bindaddr;
		if (!parse_bindaddr(&bindaddr, conf->listen)) {
			LOGF_F("unable to parse address: %s", conf->listen);
			exit(EXIT_FAILURE);
		}
		if (!server_start(s, &bindaddr.sa)) {
			FAILMSG("failed to start server");
		}
	}

	struct server *api = NULL;
	if (conf->restapi != NULL) {
		sockaddr_max_t apiaddr;
		if (!parse_bindaddr(&apiaddr, conf->restapi)) {
			LOGF_F("unable to parse address: %s", conf->restapi);
			exit(EXIT_FAILURE);
		}
		api = &app.apiserver;
		server_init(api, loop, http_api_serve, s);
		if (!server_start(api, &apiaddr.sa)) {
			FAILMSG("failed to start api server");
		}
	}

	if (conf->daemonize) {
		daemonize(conf->user_name);
	} else if (conf->user_name != NULL) {
		drop_privileges(conf->user_name);
	}

	/* signal watchers */
	{
		struct ev_signal *restrict w_sighup = &app.w_sighup;
		ev_signal_init(w_sighup, signal_cb, SIGHUP);
		ev_set_priority(w_sighup, EV_MAXPRI);
		ev_signal_start(loop, w_sighup);
		struct ev_signal *restrict w_sigint = &app.w_sigint;
		ev_signal_init(w_sigint, signal_cb, SIGINT);
		ev_set_priority(w_sigint, EV_MAXPRI);
		ev_signal_start(loop, w_sigint);
		struct ev_signal *restrict w_sigterm = &app.w_sigterm;
		ev_signal_init(w_sigterm, signal_cb, SIGTERM);
		ev_set_priority(w_sigterm, EV_MAXPRI);
		ev_signal_start(loop, w_sigterm);
	}

	/* start event loop */
	LOGI("server start");
	ev_run(loop, 0);

	LOGI("server stop");
	if (api != NULL) {
		server_stop(api);
		api = NULL;
	}
	server_stop(s);
	if (s->serve == forward_serve) {
		dialreq_free(s->data);
		s->data = NULL;
	}

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
	ev_loop_destroy(loop);

	LOGI("program terminated normally.");
	return EXIT_SUCCESS;
}

static void
signal_cb(struct ev_loop *loop, struct ev_signal *watcher, int revents)
{
	UNUSED(revents);

	switch (watcher->signum) {
	case SIGHUP: {
#if WITH_RULESET
		const struct config *restrict conf = G.conf;
		if (conf->ruleset == NULL || G.ruleset == NULL) {
			LOGE_F("signal %d received, but ruleset not loaded",
			       watcher->signum);
			break;
		}
		const bool ok = ruleset_loadfile(G.ruleset, conf->ruleset);
		if (!ok) {
			LOGW_F("failed to reload ruleset: %s",
			       ruleset_error(G.ruleset));
			break;
		}
		LOGI("ruleset successfully reloaded");
#else
		LOGW("reload is not supported in current build");
#endif
	} break;
	case SIGINT:
	case SIGTERM:
		LOGI_F("signal %d received, breaking", watcher->signum);
		session_closeall(loop);
		ev_break(loop, EVBREAK_ALL);
		break;
	}
}
