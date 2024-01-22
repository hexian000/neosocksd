/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "util.h"
#include "resolver.h"

#include "math/rand.h"
#include "utils/debug.h"
#include "utils/posixtime.h"
#include "utils/slog.h"

#include <ev.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#if _BSD_SOURCE || _GNU_SOURCE
#include <grp.h>
#endif

#include <assert.h>
#include <locale.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct globals G = { 0 };

void init(int argc, char **argv)
{
	UNUSED(argc);
	UNUSED(argv);

	(void)setlocale(LC_ALL, "");
	slog_setoutput(SLOG_OUTPUT_FILE, stdout);

	struct sigaction ignore = {
		.sa_handler = SIG_IGN,
	};
	if (sigaction(SIGPIPE, &ignore, NULL) != 0) {
		const int err = errno;
		FAILMSGF("sigaction: %s", strerror(err));
	}
}

static void unloadlibs(void);

void loadlibs(void)
{
	{
		static bool loaded = false;
		if (loaded) {
			return;
		}
		loaded = true;

		const int ret = atexit(unloadlibs);
		if (ret != 0) {
			FAILMSGF("atexit: %d", ret);
		}
	}
	srand64((uint64_t)clock_realtime());

	LOGD_F("%s: %s", PROJECT_NAME, PROJECT_VER);
	LOGD_F("libev: %d.%d", ev_version_major(), ev_version_minor());
	resolver_init();
}

void unloadlibs(void)
{
	resolver_cleanup();
}

void modify_io_events(
	struct ev_loop *loop, struct ev_io *restrict watcher, const int events)
{
	const int fd = watcher->fd;
	assert(fd != -1);
	const int ioevents = events & (EV_READ | EV_WRITE);
	if (ioevents == EV_NONE) {
		if (ev_is_active(watcher)) {
			LOGV_F("io: fd=%d stop", fd);
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
		LOGV_F("io: fd=%d events=0x%x", fd, ioevents);
		ev_io_start(loop, watcher);
	}
}

void drop_privileges(const char *user)
{
	if (getuid() != 0) {
		return;
	}
	struct passwd *restrict pw = getpwnam(user);
	if (pw == NULL) {
		LOGW_F("su: user \"%s\" does not exist ", user);
		return;
	}
	if (pw->pw_uid == 0) {
		return;
	}
	LOGI_F("su: user=%s uid=%jd gid=%jd", user, (intmax_t)pw->pw_uid,
	       (intmax_t)pw->pw_gid);
#if _BSD_SOURCE || _GNU_SOURCE
	if (setgroups(0, NULL) != 0) {
		const int err = errno;
		LOGW_F("unable to drop supplementary group privileges: %s",
		       strerror(err));
	}
#endif
	if (setgid(pw->pw_gid) != 0 || setegid(pw->pw_gid) != 0) {
		const int err = errno;
		LOGW_F("unable to drop group privileges: %s", strerror(err));
	}
	if (setuid(pw->pw_uid) != 0 || seteuid(pw->pw_uid) != 0) {
		const int err = errno;
		LOGW_F("unable to drop user privileges: %s", strerror(err));
	}
}

void daemonize(const char *user, const bool nochdir, const bool noclose)
{
	/* Create an anonymous pipe for communicating with daemon process. */
	int fd[2];
	if (pipe(fd) == -1) {
		const int err = errno;
		FAILMSGF("pipe: %s", strerror(err));
	}
	/* First fork(). */
	{
		const pid_t pid = fork();
		if (pid < 0) {
			const int err = errno;
			FAILMSGF("fork: %s", strerror(err));
		} else if (pid > 0) {
			(void)close(fd[1]);
			char buf[256];
			/* Wait for the daemon process to be started. */
			const ssize_t nread = read(fd[0], buf, sizeof(buf));
			CHECK(nread > 0);
			LOGI_F("%.*s", (int)nread, buf);
			/* Finally, call exit() in the original process. */
			exit(EXIT_SUCCESS);
		} else {
			(void)close(fd[0]);
		}
	}
	/* In the child, call setsid(). */
	if (setsid() < 0) {
		const int err = errno;
		LOGW_F("setsid: %s", strerror(err));
	}
	/* In the child, call fork() again. */
	{
		const pid_t pid = fork();
		if (pid < 0) {
			const int err = errno;
			FAILMSGF("fork: %s", strerror(err));
		} else if (pid > 0) {
			/* Call exit() in the first child. */
			exit(EXIT_SUCCESS);
		}
	}
	/* In the daemon process, connect /dev/null to standard input, output, and error. */
	if (!noclose) {
		FILE *f;
		f = freopen("/dev/null", "r", stdin);
		assert(f == stdin);
		f = freopen("/dev/null", "w", stdout);
		assert(f == stdout);
		f = freopen("/dev/null", "w", stderr);
		assert(f == stderr);
		(void)f;
	}
	/* In the daemon process, reset the umask to 0. */
	(void)umask(0);
	/* In the daemon process, change the current directory to the
           root directory (/), in order to avoid that the daemon
           involuntarily blocks mount points from being unmounted. */
	if (!nochdir) {
		if (chdir("/") != 0) {
			const int err = errno;
			LOGW_F("chdir: %s", strerror(err));
		}
	}
	/* In the daemon process, drop privileges */
	if (user != NULL) {
		drop_privileges(user);
	}
	/* From the daemon process, notify the original process started
           that initialization is complete. */
	{
		char buf[256];
		const int n = snprintf(
			buf, sizeof(buf),
			"daemon process has started with pid %jd",
			(intmax_t)getpid());
		assert(n > 0 && (size_t)n < sizeof(buf));
		const ssize_t nwritten = write(fd[1], buf, n);
		assert(nwritten == n);
		(void)nwritten;
	}
	/* Close the anonymous pipe. */
	(void)close(fd[1]);

	/* Set logging output to syslog. */
	slog_setoutput(SLOG_OUTPUT_SYSLOG, "neosocksd");
}
