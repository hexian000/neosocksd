/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"
#include "dialer.h"
#include "resolver.h"
#include "ruleset/ruleset.h"
#include "server.h"
#include "transfer.h"
#include "util.h"

#include "os/daemon.h"
#include "utils/debug.h"
#include "utils/gc.h"
#include "utils/slog.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

static struct {
	struct config conf;
	struct server server;
	ev_periodic w_timejump;
} app = { 0 };

/* Build *basereq from conf->forward/conf->proxy, replacing any previous
 * value (a boot config may change forward/proxy after the initial parse).
 * Exits the process on failure. */
static void rebuild_basereq(
	struct dialreq **restrict basereq, const struct config *restrict conf)
{
	if (!dialreq_replace(basereq, conf->forward, conf->proxy)) {
		LOGF("unable to parse outbound configuration");
		exit(EXIT_FAILURE);
	}
}

/* Run conf_check on a fully-populated config, exiting the process on failure. */
static void check_config_or_exit(
	const struct config *restrict conf, const char *restrict argv0)
{
	if (!conf_check(conf)) {
		LOGF_F("configuration check failed, try \"%s --help\" for more information",
		       argv0);
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	init(argc, argv);
	if (!conf_parseargs(&app.conf, argc, argv)) {
		exit(EXIT_FAILURE);
	}
	struct config *restrict conf = &app.conf;
#if WITH_LUA
	if (conf->dump_config) {
		if (!conf_check(conf) || !conf_print(conf)) {
			LOGF("dump configuration failed");
			exit(EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	}
#endif
#if WITH_LUA
	/* A boot config may fill in required fields, so defer the check. */
	const bool defer_check = (conf->boot != NULL);
#else
	const bool defer_check = false;
#endif
	if (!defer_check) {
		check_config_or_exit(conf, argv[0]);
	}
	loadlibs();

	struct dialreq *basereq = NULL;
	rebuild_basereq(&basereq, conf);

	struct ev_loop *loop = ev_default_loop(0);
	CHECK(loop != NULL);
	loop_watch_timejump(loop, &app.w_timejump);

	struct resolver *resolver = resolver_new(loop, conf);
	CHECKOOM(resolver);

	/* Load the ruleset/boot config (a boot config may change
	 * forward/proxy/listen) and bind the listeners (server_bind() below)
	 * before the privilege drop, so both run as the original user. */
#if WITH_RULESET
	struct ruleset *ruleset = NULL;
	if (conf->ruleset != NULL || conf->boot != NULL) {
		ruleset = ruleset_new(loop, conf, resolver, basereq);
		CHECKOOM(ruleset);
		if (conf->boot != NULL) {
			const bool ok = ruleset_loadconfig(ruleset, conf->boot);
			if (!ok) {
				LOGE_F("config load: %s",
				       ruleset_geterror(ruleset, NULL));
				LOGF_F("unable to load config: %s", conf->boot);
				exit(EXIT_FAILURE);
			}
			rebuild_basereq(&basereq, conf);
			ruleset_setbasereq(ruleset, basereq);
		}
		if (conf->ruleset != NULL) {
			const bool ok =
				ruleset_loadfile(ruleset, conf->ruleset);
			if (!ok) {
				LOGE_F("ruleset load: %s",
				       ruleset_geterror(ruleset, NULL));
				LOGF_F("unable to load ruleset: %s",
				       conf->ruleset);
				exit(EXIT_FAILURE);
			}
		}
		if (defer_check) {
			check_config_or_exit(conf, argv[0]);
		}
		/* drop the engine if no ruleset was installed */
		if (!ruleset_isvalid(ruleset)) {
			ruleset_free(ruleset);
			ruleset = NULL;
		}
	}
	if (conf->auth_required && ruleset == NULL) {
		LOGF("authentication requires a ruleset");
		exit(EXIT_FAILURE);
	}
#else /* WITH_RULESET */
	struct ruleset *ruleset = NULL;
#if WITH_LUA
	if (conf->boot != NULL) {
		if (!conf_loadboot(conf, conf->boot)) {
			LOGF_F("unable to load config: %s", conf->boot);
			exit(EXIT_FAILURE);
		}
		rebuild_basereq(&basereq, conf);
		check_config_or_exit(conf, argv[0]);
	}
#endif /* WITH_LUA */
#endif /* WITH_RULESET */

	/* loglevel and nameserver are latched from CLI values before any boot
	 * config loads (slog in conf_parseargs, c-ares in resolver_new); re-apply
	 * here only for a value a boot config may have changed. */
#if WITH_LUA
	if (conf->boot != NULL) {
		slog_setlevel(conf->loglevel);
		resolver_setnameserver(resolver, conf);
	}
#endif /* WITH_LUA */

	conf_advise(conf, ruleset != NULL);

	struct server *s = &app.server;
	if (!server_bind(s, loop, conf, resolver, basereq, ruleset)) {
		LOGF("failed to start server");
		exit(EXIT_FAILURE);
	}

	/* Drop privileges / daemonize now that the listeners are bound. Must
	 * precede thread creation: fork() keeps only the calling thread. */
	{
		if (conf->daemonize) {
			daemonize(conf->user_name, true, false);
			slog_setoutput(SLOG_OUTPUT_SYSLOG, PROJECT_NAME, NULL);
			/* daemonize() double-forks; the already-created
			 * default loop must be notified in the surviving
			 * child before it runs */
			ev_loop_fork(loop);
		} else if (conf->user_name != NULL) {
			drop_privileges(conf->user_name);
		}
	}

#if WITH_THREADS
	struct transfer *xfer =
		transfer_create(loop, (unsigned int)conf->workers);
#else
	struct transfer *xfer = transfer_create(loop, 1);
#endif
	CHECKOOM(xfer);

	/* register the accept/signal watchers now that privileges are dropped and
	 * the I/O worker exists */
	server_start(s, xfer);
#if WITH_RULESET
	if (ruleset != NULL) {
		ruleset_setserver(ruleset, s);
	}
#endif

	(void)systemd_notify(DAEMON_SYSTEMD_STATE_READY);

	/* The startup is complete here: server_start() has registered the
	 * signal watchers, so SIGTERM now reaches the loop instead of
	 * terminating the process by its default disposition. The bootstrap
	 * test waits for this line before it signals. */
	LOGD("starting the main event loop");
	ev_run(loop, 0);

	server_stop(s);
	LOGN("server shutdown gracefully");

	/* the server owns the ruleset once server_init() stores it:
	 * server_stop() frees it, and a SIGHUP reload may have replaced or
	 * cleared it, so this local must not be freed here */

	/* Finalize live sessions before freeing the resolver: a session still
	 * mid-resolution cancels its own query during finalize, and
	 * resolve_cancel writes into that query. transfer_join() stays last. */
	{
		const size_t num = gc_finalizeall();
		LOGD_F("%zu objects finalized", num);
	}
	if (resolver != NULL) {
		resolver_free(resolver);
		resolver = NULL;
	}
	if (xfer != NULL) {
		transfer_join(xfer);
		xfer = NULL;
	}
	ev_loop_destroy(loop);
	unloadlibs();
	free(app.conf.strings);

	LOGD("program terminated normally");
	return EXIT_SUCCESS;
}
