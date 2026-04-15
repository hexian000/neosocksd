/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file main.c
 * @brief Main entry point for neosocksd
 */

#include "conf.h"
#include "dialer.h"
#include "resolver.h"
#include "ruleset.h"
#include "server.h"
#include "util.h"

#include "os/daemon.h"
#include "utils/debug.h"
#include "utils/gc.h"
#include "utils/slog.h"

#include <ev.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

/**
 * @brief Global application state structure
 */
static struct {
	/* Parsed configuration from command line */
	struct config conf;
	/* Global unified server instance */
	struct server server;
} app = { 0 };

int main(int argc, char *argv[])
{
	/* Initialize application and parse command line arguments */
	init(argc, argv);
	if (!conf_parseargs(&app.conf, argc, argv)) {
		exit(EXIT_FAILURE);
	}
	/* Validate configuration */
	struct config *restrict conf = &app.conf;
	if (!conf_check(conf)) {
		LOGF_F("configuration check failed, try \"%s --help\" for more information",
		       argv[0]);
		exit(EXIT_FAILURE);
	}
	loadlibs();

	/* Parse and validate outbound connection configuration */
	struct dialreq *basereq = dialreq_parse(conf->forward, conf->proxy);
	if (basereq == NULL) {
		LOGF("unable to parse outbound configuration");
		exit(EXIT_FAILURE);
	}

	/* Initialize the main event loop */
	struct ev_loop *loop = ev_default_loop(0);
	CHECK(loop != NULL);

	/* Initialize DNS resolver */
	struct resolver *resolver = resolver_new(loop, conf);
	CHECKOOM(resolver);

	/* Initialize Lua ruleset if specified */
#if WITH_RULESET
	struct ruleset *ruleset = NULL;
	if (conf->ruleset != NULL) {
		ruleset = ruleset_new(loop, conf, resolver, basereq);
		CHECKOOM(ruleset);
		const bool ok = ruleset_loadfile(ruleset, conf->ruleset);
		if (!ok) {
			LOGE_F("ruleset load: %s",
			       ruleset_geterror(ruleset, NULL));
			LOGF_F("unable to load ruleset: %s", conf->ruleset);
			exit(EXIT_FAILURE);
		}
	}
#else
	struct ruleset *ruleset = NULL;
#endif

	/* Initialize the global server and bind all listeners */
	struct server *s = &app.server;
	if (!server_init(s, loop, conf, resolver, basereq, ruleset)) {
		LOGF("failed to start server");
		exit(EXIT_FAILURE);
	}
#if WITH_RULESET
	if (ruleset != NULL) {
		ruleset_setserver(ruleset, s);
	}
#endif

	/* Handle user identity changes and daemonization */
	{
		if (conf->daemonize) {
			daemonize(conf->user_name, true, false);
			slog_setoutput(SLOG_OUTPUT_SYSLOG, PROJECT_NAME);
		} else if (conf->user_name != NULL) {
			drop_privileges(conf->user_name);
		}
	}

	(void)systemd_notify(SYSTEMD_STATE_READY);

	/* Start the main event loop - this blocks until shutdown */
	LOGD("starting the main event loop");
	ev_run(loop, 0);

	/* Graceful shutdown sequence */
	server_stop(s);
	LOGN("server shutdown gracefully");

	/* Clean up global resources */
#if WITH_RULESET
	if (ruleset != NULL) {
		ruleset_free(ruleset);
		ruleset = NULL;
	}
#endif
	if (resolver != NULL) {
		resolver_free(resolver);
		resolver = NULL;
	}
	if (basereq != NULL) {
		dialreq_free(basereq);
		basereq = NULL;
	}

	/* Close any remaining sessions */
	{
		const size_t num = gc_finalizeall();
		LOGD_F("%zu objects finalized", num);
	}
	ev_loop_destroy(loop); /* Destroy the event loop */
	unloadlibs(); /* Unload dynamic libraries */
	free(app.conf.strings);

	LOGD("program terminated normally");
	return EXIT_SUCCESS;
}
