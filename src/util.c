/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file util.c
 * @brief Implementation of utility routines and globals for neosocksd.
 *
 * Contains initialization/teardown helpers, libev watcher utilities,
 * privilege and daemon helpers, optional splice-based pipe cache utilities,
 * and basic timing/load measurement functions.
 */
#include "util.h"

#include "dialer.h"
#include "resolver.h"

#if WITH_RULESET
#include "algo/luahash.h"
#include "lua.h"
#endif
#include "math/rand.h"
#include "os/clock.h"
#if WITH_CRASH_HANDLER
#include "os/signal.h"
#endif
#include "os/socket.h"
#include "utils/arraysize.h"
#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include <ev.h>
#if WITH_SPLICE
#include <fcntl.h>
#endif
#include <grp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

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

#if WITH_SPLICE
struct pipe_cache pipe_cache = { .cap = PIPE_MAXCACHED, .len = 0 };

void pipe_close(struct splice_pipe *restrict pipe)
{
	if (pipe->fd[0] != -1) {
		CLOSE_FD(pipe->fd[0]);
		pipe->fd[0] = -1;
	}
	if (pipe->fd[1] != -1) {
		CLOSE_FD(pipe->fd[1]);
		pipe->fd[1] = -1;
	}
}

#define PIPE_BUFSIZE 262144

bool pipe_new(struct splice_pipe *restrict pipe)
{
	if (pipe2(pipe->fd, O_NONBLOCK | O_CLOEXEC) != 0) {
		const int err = errno;
		LOGW_F("pipe2: (%d) %s", err, strerror(err));
		return false;
	}
	const int pipe_cap = fcntl(pipe->fd[0], F_SETPIPE_SZ, PIPE_BUFSIZE);
	if (pipe_cap < 0) {
		const int err = errno;
		LOGW_F("fcntl: (%d) %s", err, strerror(err));
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

struct conn_cache conn_cache = { .len = 0 };

static void conn_cache_init(void)
{
	conn_cache.len = 0;
	conn_cache.seed = 0xbf16972e;
	conn_cache.freelist = 0;
	for (int i = 0; i < CONN_CACHE_CAPACITY; i++) {
		conn_cache.buckets[i] = -1;
		conn_cache.entries[i] = (struct conn_cache_entry){
			.fd = -1,
			.bucket = -1,
			.next = (i + 1 < CONN_CACHE_CAPACITY) ? i + 1 : -1,
		};
	}
}

static int
conn_cache_take(struct ev_loop *loop, struct conn_cache_entry *restrict entry)
{
	ev_io_stop(loop, &entry->w_close);
	ev_timer_stop(loop, &entry->w_expire);
	ASSERT(entry->bucket != -1);
	ASSERT(entry >= conn_cache.entries);
	ASSERT(entry < conn_cache.entries + ARRAY_SIZE(conn_cache.entries));
	const int index = (int)(entry - conn_cache.entries);
	int *last_next = &conn_cache.buckets[entry->bucket];
	while (*last_next != -1) {
		if (*last_next == index) {
			*last_next = entry->next;
			entry->bucket = -1;
			entry->next = -1;
			break;
		}
		last_next = &conn_cache.entries[*last_next].next;
	}
	const int fd = entry->fd;
	entry->fd = -1;
	entry->hash = 0;
	entry->key[0] = '\0';
	conn_cache.len--;
	entry->next = conn_cache.freelist;
	conn_cache.freelist = index;
	return fd;
}

static void
conn_cache_idle_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct conn_cache_entry *restrict entry = watcher->data;
	LOGV_F("conn_cache: [fd:%d] server closed idle `%s'", entry->fd,
	       entry->key);
	const int fd = conn_cache_take(loop, entry);
	CLOSE_FD(fd);
}

static void
conn_cache_expire_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct conn_cache_entry *restrict entry = watcher->data;
	LOGV_F("conn_cache: [fd:%d] expire `%s'", entry->fd, entry->key);
	const int fd = conn_cache_take(loop, entry);
	CLOSE_FD(fd);
}

#define GET_HASH(s, n) (luahash((s), (n), conn_cache.seed))

void conn_cache_put(
	struct ev_loop *loop, const int fd,
	const struct dialreq *restrict dialreq, const bool enable_conn_cache)
{
	if (!enable_conn_cache) {
		LOGV_F("conn_cache: [fd:%d] disabled, closing", fd);
		CLOSE_FD(fd);
		return;
	}
	if (conn_cache.len >= CONN_CACHE_CAPACITY) {
		LOGV_F("conn_cache: [fd:%d] full, discarding", fd);
		CLOSE_FD(fd);
		return;
	}
	ASSERT(conn_cache.freelist != -1);
	const int index = conn_cache.freelist;
	struct conn_cache_entry *restrict entry = &conn_cache.entries[index];
	const int nkey =
		dialreq_format(entry->key, sizeof(entry->key), dialreq);
	if (nkey < 0 || (size_t)nkey >= sizeof(entry->key)) {
		LOGV_F("conn_cache: [fd:%d] key too long, discarding", fd);
		CLOSE_FD(fd);
		return;
	}
	conn_cache.freelist = entry->next;
	entry->hash = GET_HASH(entry->key, (size_t)nkey);
	entry->fd = fd;
	const int bucket = (int)(entry->hash % ARRAY_SIZE(conn_cache.buckets));
	entry->bucket = bucket;
	entry->next = conn_cache.buckets[bucket];
	conn_cache.buckets[bucket] = index;
	ev_io_init(&entry->w_close, conn_cache_idle_cb, fd, EV_READ);
	entry->w_close.data = entry;
	ev_timer_init(
		&entry->w_expire, conn_cache_expire_cb, CONN_CACHE_TIMEOUT,
		0.0);
	entry->w_expire.data = entry;
	ev_io_start(loop, &entry->w_close);
	ev_timer_start(loop, &entry->w_expire);
	conn_cache.len++;
	LOGV_F("conn_cache: [fd:%d] put `%s' num=%zu", fd, entry->key,
	       conn_cache.len);
}

int conn_cache_get(
	struct ev_loop *loop, const struct dialreq *restrict req,
	const bool enable_conn_cache)
{
	if (!enable_conn_cache) {
		return -1;
	}
	char key[256];
	const int nkey = dialreq_format(key, sizeof(key), req);
	if (nkey < 0 || (size_t)nkey >= sizeof(key)) {
		return -1;
	}
	const unsigned hash = GET_HASH(key, (size_t)nkey);
	const int bucket = (int)(hash % ARRAY_SIZE(conn_cache.buckets));
	for (int i = conn_cache.buckets[bucket]; i != -1;
	     i = conn_cache.entries[i].next) {
		struct conn_cache_entry *restrict entry =
			&conn_cache.entries[i];
		if (entry->hash != hash || strcmp(entry->key, key) != 0) {
			continue;
		}
		const int fd = conn_cache_take(loop, entry);
		LOGV_F("conn_cache: [fd:%d] get `%s' num=%zu", fd, key,
		       conn_cache.len);
		return fd;
	}
	return -1;
}

#if defined(WIN32)
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

void init(int argc, char *const restrict argv[])
{
	UNUSED(argc);
	UNUSED(argv);
	(void)setlocale(LC_ALL, "");
	(void)setvbuf(stdout, NULL, _IONBF, 0);
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
		FAILMSGF("sigaction: (%d) %s", err, strerror(err));
	}
#if WITH_CRASH_HANDLER
	crashhandler_install();
#endif
}

void loadlibs(void)
{
	srand64((uint_fast64_t)time(NULL));

	LOGD_F("%s: %s", PROJECT_NAME, PROJECT_VER);
	LOGD_F("libev: %d.%d", ev_version_major(), ev_version_minor());
	resolver_init();
	conn_cache_init();
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

double thread_load(void)
{
	static _Thread_local struct {
		struct timespec monotime, cputime;
		bool set;
	} last = { .set = false };
	double load = -1;
	struct timespec monotime, cputime;
	if (!clock_monotonic(&monotime)) {
		return load;
	}
	if (!clock_thread(&cputime)) {
		return load;
	}
	if (last.set) {
		const intmax_t total = TIMESPEC_DIFF(monotime, last.monotime);
		const intmax_t busy = TIMESPEC_DIFF(cputime, last.cputime);
		if (busy > 0 && total > 0 && busy <= total) {
			load = (double)busy / (double)total;
		}
	}
	last.monotime = monotime;
	last.cputime = cputime;
	last.set = true;
	return load;
}

void socket_bind_netdev(const int fd, const char *netdev)
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
#endif
}

void socket_set_transparent(const int fd, const bool tproxy)
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
#endif
}
