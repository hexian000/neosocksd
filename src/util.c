/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "util.h"

#include "resolver.h"
#include "ruleset.h"

#include "math/rand.h"
#include "utils/arraysize.h"
#include "utils/debug.h"
#include "utils/intbound.h"
#include "utils/slog.h"

#include <ev.h>

#if WITH_SPLICE
#include <fcntl.h>
#endif
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if WITH_RULESET
#include "lua.h"
#endif

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <locale.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct globals G = { 0 };

#if WITH_SPLICE
struct pipe_cache pipe_cache = { .cap = PIPE_MAXCACHED, .len = 0 };

void pipe_close(struct splice_pipe *restrict pipe)
{
	if (pipe->fd[0] != -1) {
		CLOSE_FD(pipe->fd[0]);
	}
	if (pipe->fd[1] != -1) {
		CLOSE_FD(pipe->fd[1]);
	}
}

bool pipe_new(struct splice_pipe *restrict pipe)
{
	if (pipe2(pipe->fd, O_NONBLOCK | O_CLOEXEC) != 0) {
		LOGW_F("pipe2: %s", strerror(errno));
		return false;
	}
	const int pipe_cap = fcntl(pipe->fd[0], F_SETPIPE_SZ, PIPE_BUFSIZE);
	if (pipe_cap < 0) {
		LOGW_F("fcntl: %s", strerror(errno));
		pipe_close(pipe);
		return false;
	}
	if (pipe_cap < PIPE_BUFSIZE) {
		LOGW_F("pipe: insufficient capacity %d", pipe_cap);
		pipe_close(pipe);
		return false;
	}
	pipe->cap = (size_t)pipe_cap;
	pipe->len = 0;
	return true;
}

void pipe_shrink(const size_t count)
{
	size_t n = pipe_cache.len;
	const size_t stop = count < n ? n - count : 0;
	while (n > stop) {
		pipe_close(&pipe_cache.pipes[--n]);
	}
	pipe_cache.len = n;
}
#endif

#if WITH_CRASH_HANDLER
static struct {
	int signo;
	struct sigaction oact;
} sighandlers[] = {
	{ SIGQUIT, { .sa_handler = SIG_DFL } },
	{ SIGILL, { .sa_handler = SIG_DFL } },
	{ SIGTRAP, { .sa_handler = SIG_DFL } },
	{ SIGABRT, { .sa_handler = SIG_DFL } },
	{ SIGBUS, { .sa_handler = SIG_DFL } },
	{ SIGFPE, { .sa_handler = SIG_DFL } },
	{ SIGSEGV, { .sa_handler = SIG_DFL } },
	{ SIGSYS, { .sa_handler = SIG_DFL } },
};

static void crash_handler(const int signo)
{
	LOG_STACK_F(FATAL, 2, "FATAL ERROR: %s", strsignal(signo));
	struct sigaction *act = NULL;
	for (size_t i = 0; i < ARRAY_SIZE(sighandlers); i++) {
		if (sighandlers[i].signo == signo) {
			act = &sighandlers[i].oact;
			break;
		}
	}
	if (sigaction(signo, act, NULL) != 0) {
		LOGE_F("sigaction: %s", strerror(errno));
		_Exit(EXIT_FAILURE);
	}
}

static void set_crash_handler(void)
{
	struct sigaction act = {
		.sa_handler = crash_handler,
	};
	for (size_t i = 0; i < ARRAY_SIZE(sighandlers); i++) {
		const int signo = sighandlers[i].signo;
		struct sigaction *oact = &sighandlers[i].oact;
		if (sigaction(signo, &act, oact) != 0) {
			LOGE_F("sigaction: %s", strerror(errno));
		}
	}
}
#endif /* WITH_CRASH_HANDLER */

#if defined(WIN32)
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

void init(int argc, char **argv)
{
	UNUSED(argc);
	UNUSED(argv);
	(void)setlocale(LC_ALL, "");
	slog_setoutput(SLOG_OUTPUT_FILE, stdout);
	{
		static char prefix[] = __FILE__;
		char *s = strrchr(prefix, PATH_SEPARATOR);
		if (s != NULL) {
			s[1] = '\0';
		}
		slog_setfileprefix(prefix);
	}
	slog_setlevel(LOG_LEVEL_VERBOSE);

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
#if WITH_CRASH_HANDLER
	set_crash_handler();
#endif
	srand64((uint64_t)time(NULL));

	LOGD_F("%s: %s", PROJECT_NAME, PROJECT_VER);
	LOGD_F("libev: %d.%d", ev_version_major(), ev_version_minor());
	resolver_init();
#if WITH_RULESET
	LOGD("ruleset interpreter: " LUA_RELEASE);
#endif
}

void unloadlibs(void)
{
	resolver_cleanup();
#if WITH_SPLICE
	pipe_shrink(SIZE_MAX);
#endif
}

void modify_io_events(
	struct ev_loop *loop, struct ev_io *restrict watcher, const int events)
{
	const int fd = watcher->fd;
	ASSERT(fd != -1);
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

bool parse_user(struct user_ident *ident, const char *s)
{
	const size_t len = strlen(s);
	if (len >= 1024) {
		LOGE_F("user name is too long: `%s'", s);
		return false;
	}
	char buf[len + 1];
	memcpy(buf, s, len + 1);

	const char *user = NULL, *group = NULL;
	char *const colon = strchr(buf, ':');
	if (colon != NULL) {
		if (colon != buf) {
			user = buf;
		}
		*colon = '\0';
		if (colon[1] != '\0') {
			group = &colon[1];
		}
	} else {
		user = buf;
		group = NULL;
	}

	uid_t uid = (uid_t)-1;
	gid_t gid = (gid_t)-1;
	const struct passwd *pw = NULL;
	if (user != NULL) {
		char *endptr;
		const intmax_t uidvalue = strtoimax(user, &endptr, 10);
		if (*endptr || !BOUNDCHECK_INT(uid, uidvalue)) {
			/* search user database for user name */
			pw = getpwnam(user);
			if (pw == NULL) {
				LOGE_F("passwd: name `%s' does not exist",
				       user);
				return false;
			}
			LOGD_F("passwd: `%s' uid=%jd gid=%jd", user,
			       (intmax_t)pw->pw_uid, (intmax_t)pw->pw_gid);
			uid = pw->pw_uid;
		} else {
			uid = (uid_t)uidvalue;
		}
	}

	if (group != NULL) {
		char *endptr;
		const intmax_t gidvalue = strtoimax(group, &endptr, 10);
		if (*endptr || !BOUNDCHECK_INT(gid, gidvalue)) {
			/* search group database for group name */
			const struct group *gr = getgrnam(group);
			if (gr == NULL) {
				LOGE_F("group: name `%s' does not exist",
				       group);
				return false;
			}
			LOGD_F("group: `%s' gid=%jd", group,
			       (intmax_t)gr->gr_gid);
			gid = gr->gr_gid;
		} else {
			gid = (gid_t)gidvalue;
		}
	} else if (user != NULL && colon != NULL) {
		/* group is not specified, search from user database */
		if (pw == NULL) {
			pw = getpwuid(uid);
			if (pw == NULL) {
				LOGE_F("passwd: user `%s' does not exist",
				       user);
				return false;
			}
			LOGD_F("passwd: `%s' uid=%jd gid=%jd", user,
			       (intmax_t)pw->pw_uid, (intmax_t)pw->pw_gid);
		}
		gid = pw->pw_gid;
	}
	if (ident != NULL) {
		*ident = (struct user_ident){
			.uid = uid,
			.gid = gid,
		};
	}
	return true;
}

void drop_privileges(const struct user_ident *restrict ident)
{
#if _BSD_SOURCE || _GNU_SOURCE
	if (setgroups(0, NULL) != 0) {
		const int err = errno;
		LOGW_F("unable to drop supplementary group privileges: %s",
		       strerror(err));
	}
#endif
	if (ident->gid != (gid_t)-1) {
		LOGD_F("setgid: %jd", (intmax_t)ident->gid);
		if (setgid(ident->gid) != 0 || setegid(ident->gid) != 0) {
			const int err = errno;
			LOGW_F("unable to drop group privileges: %s",
			       strerror(err));
		}
	}
	if (ident->uid != (uid_t)-1) {
		LOGD_F("setuid: %jd", (intmax_t)ident->uid);
		if (setuid(ident->uid) != 0 || seteuid(ident->uid) != 0) {
			const int err = errno;
			LOGW_F("unable to drop user privileges: %s",
			       strerror(err));
		}
	}
}

void daemonize(
	const struct user_ident *ident, const bool nochdir, const bool noclose)
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
	if (ident != NULL) {
		drop_privileges(ident);
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
