/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "util.h"

#include "resolver.h"

#include "math/rand.h"
#if WITH_CRASH_HANDLER
#include "os/signal.h"
#endif
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#if WITH_RULESET
#include <lua.h>
#endif

#include <errno.h>
#include <inttypes.h>
#include <locale.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#if defined(WIN32)
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

void init(int argc, char *const restrict argv[])
{
	(void)argc;
	(void)argv;
	(void)setlocale(LC_ALL, "");
	(void)setvbuf(stderr, NULL, _IONBF, 0);
	slog_setoutput(SLOG_OUTPUT_FILE, stderr);
	{
		static char prefix[] = __FILE__;
		char *s = strrchr(prefix, PATH_SEPARATOR);
		if (s != NULL) {
			s[1] = '\0';
		}
		slog_setfileprefix(prefix);
	}
	slog_setlevel(LOG_LEVEL_VERBOSE);

	const struct sigaction ignore = { .sa_handler = SIG_IGN };
	if (sigaction(SIGPIPE, &ignore, NULL) != 0) {
		const int err = errno;
		FAILMSGF("sigaction: (%d) %s", err, strerror(err));
	}
#if WITH_CRASH_HANDLER
	crashhandler_install();
#endif
}

void loadlibs(void)
{
	srand64((uint_fast64_t)time(NULL));

	LOGI_F("%s %s", PROJECT_NAME, PROJECT_VER);
	LOGI_F("libev %d.%d", ev_version_major(), ev_version_minor());
	resolver_init();
#if WITH_RULESET
	LOGI("ruleset interpreter: " LUA_RELEASE);
#endif
}

void unloadlibs(void)
{
	resolver_cleanup();
}

void modify_io_events(
	struct ev_loop *restrict loop, ev_io *restrict watcher,
	const int events)
{
	const int fd = watcher->fd;
	ASSERT(fd != -1);
	const int ioevents = events & (EV_READ | EV_WRITE);
	if (ioevents == EV_NONE) {
		if (ev_is_active(watcher)) {
			LOGV_F("io: [fd:%d] stop", fd);
			ev_io_stop(loop, watcher);
		}
		return;
	}
	if (ioevents != (watcher->events & (EV_READ | EV_WRITE))) {
		ev_io_stop(loop, watcher);
#ifdef ev_io_modify
		ev_io_modify(watcher, ioevents);
#else
		ev_io_set(watcher, fd, ioevents);
#endif
	}
	if (!ev_is_active(watcher)) {
		LOGV_F("io: [fd:%d] events=0x%x", fd, ioevents);
		ev_io_start(loop, watcher);
	}
}

void socket_bind_netdev(int fd, const char *restrict netdev)
{
#ifdef SO_BINDTODEVICE
	char ifname[IFNAMSIZ];
	(void)strncpy(ifname, netdev, sizeof(ifname) - 1);
	ifname[sizeof(ifname) - 1] = '\0';
	if (setsockopt(
		    fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, sizeof(ifname))) {
		const int err = errno;
		LOGW_F("[fd:%d] SO_BINDTODEVICE: (%d) %s", fd, err,
		       strerror(err));
	}
#else
	(void)fd;
	if (netdev[0] != '\0') {
		LOGW_F("SO_BINDTODEVICE: %s", "not supported in current build");
	}
#endif /* SO_BINDTODEVICE */
}

void socket_set_transparent(int fd, bool tproxy)
{
#ifdef IP_TRANSPARENT
	int val = tproxy ? 1 : 0;
	if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &val, sizeof(val))) {
		/* this is a fatal error */
		const int err = errno;
		FAILMSGF("IP_TRANSPARENT: (%d) %s", err, strerror(err));
	}
#else
	(void)fd;
	CHECKMSGF(
		!tproxy, "IP_TRANSPARENT: %s",
		"not supported in current build");
#endif /* IP_TRANSPARENT */
}
