#include "net/addr.h"
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

#include <sys/socket.h>
#include <ev.h>

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
#if WITH_REUSEPORT
	bool reuseport : 1;
#endif
#if WITH_TPROXY
	bool tproxy : 1;
#endif
	int verbosity;
	int resolve_pf;
	const char *user_name;

	struct ev_signal w_sighup;
	struct ev_signal w_sigint;
	struct ev_signal w_sigterm;
} args = {
	.verbosity = LOG_LEVEL_INFO,
	.resolve_pf = PF_UNSPEC,
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
#if WITH_TPROXY
		"  --tproxy                   operate as a transparent proxy\n"
#endif
		"  -r, --ruleset <file>       load ruleset from Lua file\n"
		"  --api <bind_address>       RESTful API for monitoring\n"
		"  -u, --user <name>          switch to the specified limited user, e.g. nobody\n"
		"  -v, --verbose              increase verbosity\n"
		"  -s, --silence              decrease verbosity\n"
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
			FAILMSGF(                                              \
				"option \"%s\" requires an argument\n",        \
				(argv)[(i)]);                                  \
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
#if WITH_TPROXY
		if (strcmp(argv[i], "--tproxy") == 0) {
			args.tproxy = true;
			continue;
		}
#endif
#if WITH_NETDEVICE
		if (strcmp(argv[i], "-i") == 0 ||
		    strcmp(argv[i], "--netdev") == 0) {
			args.tproxy = true;
			continue;
		}
#endif
#if WITH_REUSEPORT
		if (strcmp(argv[i], "--reuseport") == 0) {
			args.reuseport = true;
			continue;
		}
#endif
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
		if (strcmp(argv[i], "--") == 0) {
			continue;
		}
		FAILMSGF("unknown argument: \"%s\"", argv[i]);
	}

#undef OPT_REQUIRE_ARG
}

int main(int argc, char **argv)
{
	parse_args(argc, argv);
	slog_level =
		CLAMP(args.verbosity, LOG_LEVEL_SILENCE, LOG_LEVEL_VERBOSE);
	if (args.listen == NULL) {
		LOGF("listen address not specified");
		exit(EXIT_FAILURE);
	}

	struct ev_loop *loop = ev_default_loop(0);
	CHECK(loop != NULL);

	/* signal watchers */
	if (sigaction(
		    SIGPIPE,
		    &(struct sigaction){
			    .sa_handler = SIG_IGN,
		    },
		    NULL) != 0) {
		const int err = errno;
		LOGF(strerror(err));
		exit(EXIT_FAILURE);
	}
	{
		struct ev_signal *restrict w_sighup = &args.w_sighup;
		ev_signal_init(w_sighup, signal_cb, SIGHUP);
		ev_signal_start(loop, w_sighup);
		struct ev_signal *restrict w_sigint = &args.w_sigint;
		ev_signal_init(w_sigint, signal_cb, SIGINT);
		ev_signal_start(loop, w_sigint);
		struct ev_signal *restrict w_sigterm = &args.w_sigterm;
		ev_signal_init(w_sigterm, signal_cb, SIGTERM);
		ev_signal_start(loop, w_sigterm);
	}

	struct config conf = {
		.forward = args.forward,
		.resolve_pf = args.resolve_pf,
#if WITH_NETDEVICE
		.netdev = args.netdev,
#endif
#if WITH_REUSEPORT
		.reuseport = args.reuseport,
#endif
#if WITH_TPROXY
		.transparent = args.tproxy,
#endif
		.timeout = 60.0,
	};
	struct ruleset *ruleset = NULL;
	if (args.ruleset != NULL) {
		ruleset = ruleset_new(&conf);
		CHECKOOM(ruleset);
		if (!ruleset_loadfile(ruleset, args.ruleset)) {
			FAILMSGF("unable to load ruleset: %s", args.ruleset);
		}
	}

	sockaddr_max_t bindaddr;
	if (!parse_bindaddr(&bindaddr, args.listen)) {
		FAILMSGF("unable to parse address: %s", args.listen);
	}

	serve_fn serve_cb = socks_serve;
	if (args.forward != NULL || args.tproxy) {
		serve_cb = forward_serve;
	} else if (args.http) {
		serve_cb = http_proxy_serve;
	}

	struct server *s = server_new(&bindaddr.sa, &conf, ruleset, serve_cb);
	if (s == NULL) {
		FAILMSG("server initializing failed");
	}
	server_start(s, loop);

	struct server *apiserver = NULL;
	if (args.restapi != NULL) {
		sockaddr_max_t apiaddr;
		if (!parse_bindaddr(&apiaddr, args.restapi)) {
			LOGF_F("unable to parse address: %s", args.restapi);
			exit(EXIT_FAILURE);
		}
		apiserver =
			server_new(&apiaddr.sa, &conf, ruleset, http_api_serve);
		if (apiserver == NULL) {
			FAILMSG("api server initializing failed");
		}
		server_start(apiserver, loop);
	}

	drop_privileges(args.user_name);
	/* start event loop */
	LOGI("server start");
	ev_run(loop, 0);

	if (apiserver != NULL) {
		server_stop(apiserver, loop);
		server_free(apiserver);
	}
	server_stop(s, loop);
	server_free(s);
	if (ruleset != NULL) {
		ruleset_free(ruleset);
	}

	ev_signal_stop(loop, &args.w_sighup);
	ev_signal_stop(loop, &args.w_sigint);
	ev_signal_stop(loop, &args.w_sigterm);

	LOGI("program terminated normally.");
	return EXIT_SUCCESS;
}

static void
signal_cb(struct ev_loop *loop, struct ev_signal *watcher, int revents)
{
	UNUSED(revents);

	switch (watcher->signum) {
	case SIGPIPE:
	case SIGHUP: {
		LOGV_F("signal %d ignored", watcher->signum);
	} break;
	case SIGINT:
	case SIGTERM: {
		LOGI_F("signal %d received, breaking", watcher->signum);
		ev_break(loop, EVBREAK_ALL);
	} break;
	}
}
