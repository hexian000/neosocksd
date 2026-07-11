/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "ruleset/await.h"

#include "api_client.h"
#include "conf.h"
#include "dialer.h"
#include "resolver.h"
#include "ruleset/base.h"
#include "ruleset/cfunc.h"
#include "ruleset/ruleset.h"
#include "server.h"
#include "util.h"

#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>
#include <lauxlib.h>
#include <lua.h>

#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#ifdef _GNU_SOURCE
#include <sys/syscall.h>
#endif
#include <sys/types.h>
#include <unistd.h>

#define MT_AWAIT_SLEEP "await.sleep"
#define MT_AWAIT_RESOLVE "await.resolve"
#define MT_AWAIT_INVOKE "await.invoke"
#define MT_AWAIT_EXECUTE "await.execute"
#define MT_AWAIT_FORWARD "await.forward"

#define AWAIT_CHECK_YIELDABLE(L)                                               \
	do {                                                                   \
		if (!lua_isyieldable((L))) {                                   \
			lua_pushliteral((L), ERR_NOT_ASYNC_ROUTINE);           \
			return lua_error((L));                                 \
		}                                                              \
	} while (0)

/* [-0, +0, m] */
static void pin_context(lua_State *restrict L, const void *p)
{
	aux_getregtable(L, RIDX_AWAIT_CONTEXT);
	/* lua_pushthread pushes the coroutine and returns true only for the
	 * main thread; every caller runs after AWAIT_CHECK_YIELDABLE, which
	 * already rejects the (non-yieldable) main thread */
	const int ismain = lua_pushthread(L);
	ASSERT(!ismain);
	(void)ismain;
	lua_rawsetp(L, -2, p);
	lua_pop(L, 1);
}

/* [-0, +0, -] */
static void unpin_context(lua_State *restrict L, const void *p)
{
	aux_getregtable(L, RIDX_AWAIT_CONTEXT);
	lua_pushnil(L);
	lua_rawsetp(L, -2, p);
	lua_pop(L, 1);
}

struct await_sleep_userdata {
	struct ruleset *ruleset;
	ev_timer w_timer;
	ev_idle w_idle;
};

static int await_sleep_close(lua_State *restrict L)
{
	struct await_sleep_userdata *restrict ud = lua_touserdata(L, 1);
	struct ev_loop *loop = ud->ruleset->loop;
	ev_timer_stop(loop, &ud->w_timer);
	ev_idle_stop(loop, &ud->w_idle);
	unpin_context(L, ud);
	return 0;
}

static void sleep_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	ev_timer_stop(loop, watcher);
	struct await_sleep_userdata *restrict ud = watcher->data;
	ev_idle_start(loop, &ud->w_idle);
}

static void
sleep_finish_cb(struct ev_loop *loop, ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct await_sleep_userdata *restrict ud = watcher->data;
	ruleset_resume(ud->ruleset, ud, 0);
}

static int
await_sleep_k(lua_State *restrict L, const int status, const lua_KContext ctx)
{
	ASSERT(status == LUA_YIELD);
	(void)status;
	(void)ctx;
	/* lua stack: ud */
	ASSERT(lua_gettop(L) == 1);
	aux_close(L, 1);
	return 0;
}

/* await.sleep(n) */
static int await_sleep(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	const lua_Number n = luaL_checknumber(L, 1);
	luaL_argcheck(
		L, isfinite(n) && 0 <= n && n <= 1e+9, 1,
		"n must be finite and in [0, 1e9]");
	lua_settop(L, 0);

	struct ruleset *restrict r = aux_getruleset(L);
	struct await_sleep_userdata *restrict ud =
		lua_newuserdata(L, sizeof(struct await_sleep_userdata));
	ud->ruleset = r;
	ev_timer_init(&ud->w_timer, sleep_cb, n, 0.0);
	ud->w_timer.data = ud;
	ev_idle_init(&ud->w_idle, sleep_finish_cb);
	ud->w_idle.data = ud;
	aux_toclose(L, -1, MT_AWAIT_SLEEP, await_sleep_close);

	if (n > 0) {
		ev_timer_start(r->loop, &ud->w_timer);
	} else {
		ev_idle_start(r->loop, &ud->w_idle);
	}

	pin_context(L, ud);
	/* lua stack: ud */
	ASSERT(lua_gettop(L) == 1);
	lua_yieldk(L, 0, 0, await_sleep_k);
	lua_pushliteral(L, ERR_NOT_ASYNC_ROUTINE);
	return lua_error(L);
}

struct await_resolve_userdata {
	struct ruleset *ruleset;
	struct resolve_query *query;
	ev_idle w_idle;
	bool ok;
	union sockaddr_max sa;
};

static int await_resolve_close(lua_State *restrict L)
{
	struct await_resolve_userdata *restrict ud = lua_touserdata(L, 1);
	if (ud->query != NULL) {
		resolve_cancel(ud->query);
		ud->query = NULL;
	}
	ev_idle_stop(ud->ruleset->loop, &ud->w_idle);
	unpin_context(L, ud);
	return 0;
}

static void resolve_cb(
	struct resolve_query *q, struct ev_loop *loop, void *data,
	const struct sockaddr *restrict sa)
{
	struct await_resolve_userdata *restrict ud = data;
	ASSERT(ud->query == q);
	(void)q;
	ud->query = NULL;
	/* sa is NULL when name resolution fails */
	ud->ok = (sa != NULL);
	if (ud->ok) {
		sa_copy(&ud->sa.sa, sa);
	}
	ev_idle_start(loop, &ud->w_idle);
}

static void
resolve_finish_cb(struct ev_loop *loop, ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct await_resolve_userdata *restrict ud = watcher->data;
	const struct sockaddr *sa = ud->ok ? &ud->sa.sa : NULL;
	ruleset_resume(ud->ruleset, ud, 1, (void *)sa);
}

static int
await_resolve_k(lua_State *restrict L, const int status, const lua_KContext ctx)
{
	ASSERT(status == LUA_YIELD);
	(void)status;
	(void)ctx;
	/* lua stack: hostname ud sa */
	ASSERT(lua_gettop(L) == 3);
	aux_close(L, 2);
	return aux_format_addr(L);
}

/* await.resolve(host) */
static int await_resolve(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	const char *restrict name = luaL_checkstring(L, 1);
	lua_settop(L, 1);
	struct await_resolve_userdata *restrict ud =
		lua_newuserdata(L, sizeof(struct await_resolve_userdata));
	ud->ruleset = aux_getruleset(L);
	ud->query = NULL;
	ud->ok = false;
	ev_idle_init(&ud->w_idle, resolve_finish_cb);
	ud->w_idle.data = ud;
	aux_toclose(L, -1, MT_AWAIT_RESOLVE, await_resolve_close);

	ud->query = resolve_do(
		ud->ruleset->resolver,
		(struct resolve_cb){
			.func = resolve_cb,
			.data = ud,
		},
		name, NULL, ud->ruleset->conf->resolve_pf);
	if (ud->query == NULL) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}

	pin_context(L, ud);
	/* lua stack: hostname ud */
	ASSERT(lua_gettop(L) == 2);
	lua_yieldk(L, 0, 0, await_resolve_k);
	lua_pushliteral(L, ERR_NOT_ASYNC_ROUTINE);
	return lua_error(L);
}

struct await_invoke_userdata {
	struct ruleset *ruleset;
	struct api_client_ctx *ctx;
	size_t errlen;
};

static int await_invoke_close(lua_State *restrict L)
{
	struct await_invoke_userdata *restrict ud = lua_touserdata(L, 1);
	if (ud->ctx != NULL) {
		api_client_cancel(ud->ruleset->loop, ud->ctx);
		ud->ctx = NULL;
	}
	unpin_context(L, ud);
	return 0;
}

static void invoke_cb(
	struct api_client_ctx *ctx, struct ev_loop *loop, void *data,
	const char *err, const size_t errlen, struct stream *stream)
{
	(void)loop;
	struct await_invoke_userdata *restrict ud = data;
	ASSERT(ud->ctx == ctx);
	(void)ctx;
	ud->ctx = NULL;
	/* store errlen in the userdata: passing &errlen (this frame's stack)
	 * through ruleset_resume would dangle if resume were ever async */
	ud->errlen = errlen;
	ruleset_resume(ud->ruleset, ud, 2, (void *)err, (void *)stream);
}

static int
await_invoke_k(lua_State *restrict L, const int status, const lua_KContext ctx)
{
	ASSERT(status == LUA_YIELD);
	(void)status;
	(void)ctx;
	/* lua stack: code ud *err *stream */
	ASSERT(lua_gettop(L) == 4);
	const struct await_invoke_userdata *restrict ud = lua_touserdata(L, 2);
	const size_t errlen = ud->errlen;
	aux_close(L, 2);
	const char *const errmsg = lua_touserdata(L, 3);
	struct stream *const stream = lua_touserdata(L, 4);
	lua_settop(L, 0);

	if (errmsg != NULL) {
		lua_pushboolean(L, 0);
		lua_pushlstring(L, errmsg, errlen);
		return 2;
	}
	lua_pushboolean(L, 1);
	if (aux_load(L, stream, "=(rpc)")) {
		return lua_error(L);
	}
	aux_setsandboxenv(L);
	return 2;
}

/* ok, ... = await.invoke(code, addr, proxyN, ..., proxy1) */
static int await_invoke(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	size_t len;
	const char *restrict const code = luaL_checklstring(L, 1, &len);
	const int n = lua_gettop(L) - 1;
	if (n <= 0 || !aux_todialreq(L, n)) {
		lua_pushliteral(L, ERR_INVALID_ADDR);
		return lua_error(L);
	}
	struct dialreq *const req = lua_touserdata(L, -1);
	if (req == NULL) {
		lua_pushliteral(L, ERR_INVALID_ADDR);
		return lua_error(L);
	}
	lua_settop(L, 1);
	/* lua stack: code */
	struct ruleset *restrict r = aux_getruleset(L);
	struct await_invoke_userdata *restrict ud =
		lua_newuserdata(L, sizeof(struct await_invoke_userdata));
	*ud = (struct await_invoke_userdata){
		.ruleset = r,
		.ctx = NULL,
	};
	aux_toclose(L, -1, MT_AWAIT_INVOKE, await_invoke_close);

	const struct api_client_cb cb = {
		.func = invoke_cb,
		.data = ud,
	};
	const bool ok = api_client_rpcall(
		r->loop, &ud->ctx, req, code, len, &cb, r->conf, r->resolver,
		r->server != NULL ? &r->server->stats : NULL);
	if (!ok) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}

	pin_context(L, ud);
	/* lua stack: code ud */
	ASSERT(lua_gettop(L) == 2);
	lua_yieldk(L, 0, 0, await_invoke_k);
	lua_pushliteral(L, ERR_NOT_ASYNC_ROUTINE);
	return lua_error(L);
}

struct await_forward_userdata {
	struct ruleset *ruleset;
	struct ruleset_state *state;
	struct dialreq *req;
	struct dialer dialer;
	ev_timer w_timeout;
	int fd;
	bool dialing;
	bool timed_out;
};

static int await_forward_close(lua_State *restrict L)
{
	struct await_forward_userdata *restrict ud = lua_touserdata(L, 1);
	struct ev_loop *loop = ud->ruleset->loop;
	ev_timer_stop(loop, &ud->w_timeout);
	if (ud->dialing) {
		dialer_cancel(&ud->dialer, loop);
		ud->dialing = false;
	}
	if (ud->fd != -1) {
		/* fd not handed off to a session: drop it */
		socket_close(ud->fd);
		ud->fd = -1;
	}
	if (ud->req != NULL) {
		dialreq_free(ud->req);
		ud->req = NULL;
	}
	unpin_context(L, ud);
	return 0;
}

static void forward_dialer_cb(struct ev_loop *loop, void *data, const int fd)
{
	struct await_forward_userdata *restrict ud = data;
	ev_timer_stop(loop, &ud->w_timeout);
	ud->dialing = false;
	ud->fd = fd;
	ruleset_resume(ud->ruleset, ud, 0);
}

/* No kernel timeout during proxy handshake; bound it here. */
static void
forward_timeout_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	ev_timer_stop(loop, watcher);
	struct await_forward_userdata *restrict ud = watcher->data;
	if (ud->dialing) {
		dialer_cancel(&ud->dialer, loop);
		ud->dialing = false;
	}
	ud->fd = -1;
	ud->timed_out = true;
	ruleset_resume(ud->ruleset, ud, 0);
}

static int
await_forward_k(lua_State *restrict L, const int status, const lua_KContext ctx)
{
	ASSERT(status == LUA_YIELD);
	(void)status;
	(void)ctx;
	/* lua stack: ud */
	ASSERT(lua_gettop(L) == 1);
	struct await_forward_userdata *restrict ud = lua_touserdata(L, 1);
	struct ruleset_state *restrict state = ud->state;
	struct ruleset_callback *restrict cb = state->cb;

	bool ok = false;
	const char *err = NULL;
	if (ud->fd < 0) {
		/* dial failed (or timed out): report the error to the routine */
		if (ud->timed_out) {
			err = "timeout";
		} else {
			err = dialer_strerror(ud->dialer.err);
		}
	} else if (cb != NULL) {
		/* forward() may free cb; don't touch it afterwards */
		const int fd = ud->fd;
		ud->fd = -1;
		cb->forward(ud->ruleset->loop, cb, fd);
		state->cb = NULL;
		ok = true;
	} else {
		/* session cancelled */
		err = "request cancelled";
	}

	aux_close(L, 1);
	lua_settop(L, 0);
	lua_pushboolean(L, ok);
	if (err != NULL) {
		lua_pushstring(L, err);
		return 2;
	}
	return 1;
}

/* ok, err = await.forward(addr, proxyN, ..., proxy1) */
static int await_forward(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	struct ruleset_state *restrict const state = aux_getforward(L);
	if (state == NULL) {
		lua_pushliteral(
			L,
			"await.forward must be called from a ruleset request handler");
		return lua_error(L);
	}
	struct ruleset_callback *restrict const cb = state->cb;
	if (cb == NULL || cb->forward == NULL) {
		lua_pushliteral(
			L, "await.forward: the request is not forwardable");
		return lua_error(L);
	}

	const int n = lua_gettop(L);
	if (n < 1) {
		/* reject: nothing to forward */
		lua_pushnil(L);
		return 1;
	}
	if (!aux_todialreq(L, n)) {
		lua_pushliteral(L, ERR_INVALID_ADDR);
		return lua_error(L);
	}
	struct dialreq *restrict const req = lua_touserdata(L, -1);
	if (req == NULL) {
		/* reject: nil address */
		lua_settop(L, 0);
		lua_pushnil(L);
		return 1;
	}
	lua_settop(L, 0);

	struct ruleset *restrict r = aux_getruleset(L);
	struct await_forward_userdata *restrict ud =
		lua_newuserdata(L, sizeof(struct await_forward_userdata));
	*ud = (struct await_forward_userdata){
		.ruleset = r,
		.state = state,
		.req = req,
		.fd = -1,
		.dialing = false,
		.timed_out = false,
	};
	ev_timer_init(
		&ud->w_timeout, forward_timeout_cb, r->conf->timeout, 0.0);
	ud->w_timeout.data = ud;
	aux_toclose(L, -1, MT_AWAIT_FORWARD, await_forward_close);

	struct server *restrict server = r->server;
	const struct dialer_cb dcb = {
		.func = forward_dialer_cb,
		.data = ud,
	};
	dialer_init(
		&ud->dialer, &dcb,
		server != NULL ? &server->stats.byt_dial_send : NULL,
		server != NULL ? &server->stats.byt_dial_recv : NULL);
	ud->dialing = true;
	dialer_do(&ud->dialer, r->loop, ud->req, r->conf, r->resolver, server);
	ev_timer_start(r->loop, &ud->w_timeout);

	pin_context(L, ud);
	/* lua stack: ud */
	ASSERT(lua_gettop(L) == 1);
	lua_yieldk(L, 0, 0, await_forward_k);
	lua_pushliteral(L, ERR_NOT_ASYNC_ROUTINE);
	return lua_error(L);
}

struct await_execute_userdata {
	struct ruleset *ruleset;
	ev_child w_child;
	ev_idle w_idle;
};

static int await_execute_close(lua_State *restrict L)
{
	struct await_execute_userdata *restrict ud = lua_touserdata(L, 1);
	const pid_t pid = ud->w_child.pid;
	struct ev_loop *loop = ud->ruleset->loop;
	ev_child_stop(loop, &ud->w_child);
	ev_idle_stop(loop, &ud->w_idle);
	if (pid > 0) {
		if (kill(pid, SIGKILL) != 0) {
			LOG_PERROR("kill");
		}
		ud->w_child.pid = 0;
	}
	unpin_context(L, ud);
	return 0;
}

static void child_cb(struct ev_loop *loop, ev_child *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_CHILD);
	ev_child_stop(loop, watcher);
	watcher->pid = 0;
	struct await_execute_userdata *restrict ud = watcher->data;
	ev_idle_start(loop, &ud->w_idle);
}

static void
child_finish_cb(struct ev_loop *loop, ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct await_execute_userdata *restrict ud = watcher->data;
	ruleset_resume(ud->ruleset, ud, 0);
}

static int
await_execute_k(lua_State *restrict L, const int status, const lua_KContext ctx)
{
	ASSERT(status == LUA_YIELD);
	(void)status;
	(void)ctx;
	/* lua stack: command ud */
	ASSERT(lua_gettop(L) == 2);
	const struct await_execute_userdata *restrict ud = lua_touserdata(L, 2);
	int stat = ud->w_child.rstatus;
	aux_close(L, 2);
	lua_settop(L, 0);

	if (WIFSIGNALED(stat)) {
		lua_pushnil(L);
		lua_pushliteral(L, "signal");
		lua_pushinteger(L, WTERMSIG(stat));
		return 3;
	}
	bool ok = false;
	if (WIFEXITED(stat)) {
		stat = WEXITSTATUS(stat);
		ok = (stat == 0);
	}
	if (ok) {
		lua_pushboolean(L, 1);
	} else {
		lua_pushnil(L);
	}
	lua_pushliteral(L, "exit");
	lua_pushinteger(L, stat);
	return 3;
}

/* Close every inherited descriptor above stderr in the forked child before
 * exec. Our own sockets are CLOEXEC, but descriptors we do not control (e.g.
 * the resolver's) would otherwise leak into the spawned process tree and keep
 * connections open for its lifetime. */
static void close_inherited_fds(void)
{
	const int minfd = STDERR_FILENO + 1;
#if defined(_GNU_SOURCE) && defined(SYS_close_range)
	if (syscall(SYS_close_range, (unsigned int)minfd, ~0U, 0) == 0) {
		return;
	}
#endif
	long maxfd = sysconf(_SC_OPEN_MAX);
	if (maxfd < minfd) {
		maxfd = 1L << 16;
	}
	for (long fd = minfd; fd < maxfd; fd++) {
		(void)close((int)fd);
	}
}

/* status = await.execute(command) */
static int await_execute(lua_State *restrict L)
{
	AWAIT_CHECK_YIELDABLE(L);
	size_t len;
	const char *const command = luaL_checklstring(L, 1, &len);
	lua_settop(L, 1);

	struct ruleset *restrict r = aux_getruleset(L);
	struct await_execute_userdata *restrict ud =
		lua_newuserdata(L, sizeof(struct await_execute_userdata));
	ud->ruleset = r;
	ev_child_init(&ud->w_child, child_cb, 0, 0);
	ud->w_child.data = ud;
	ev_idle_init(&ud->w_idle, child_finish_cb);
	ud->w_idle.data = ud;
	aux_toclose(L, -1, MT_AWAIT_EXECUTE, await_execute_close);

	const pid_t pid = fork();
	if (pid < 0) {
		const int err = errno;
		const char *const errmsg = strerror(err);
		LOGW_F("fork: (%d) %s", err, errmsg);
		lua_pushstring(L, errmsg);
		return lua_error(L);
	}
	if (pid == 0) {
		if (setsid() < 0) {
			const int err = errno;
			LOGW_F("setsid: (%d) %s", err, strerror(err));
		}
		/* restore the default SIGPIPE disposition: util.c ignores it
		 * process-wide and an ignored disposition survives execv(),
		 * unlike a normal shell, breaking pipelines that rely on
		 * SIGPIPE to stop a writer (e.g. `yes | head`) */
		const struct sigaction dfl = { .sa_handler = SIG_DFL };
		(void)sigaction(SIGPIPE, &dfl, NULL);
		close_inherited_fds();
		const char *argv[] = { "sh", "-c", command, NULL };
		execv("/bin/sh", (char *const *)argv);
		const int err = errno;
		FAILMSGF("execv: (%d) %s", err, strerror(err));
	}
	ev_child_set(&ud->w_child, pid, 0);
	ev_child_start(r->loop, &ud->w_child);

	pin_context(L, ud);
	/* lua stack: command ud */
	ASSERT(lua_gettop(L) == 2);
	lua_yieldk(L, 0, 0, await_execute_k);
	lua_pushliteral(L, ERR_NOT_ASYNC_ROUTINE);
	return lua_error(L);
}

int luaopen_await(lua_State *restrict L)
{
	const luaL_Reg awaitlib[] = {
		{ "execute", await_execute }, { "forward", await_forward },
		{ "invoke", await_invoke },   { "resolve", await_resolve },
		{ "sleep", await_sleep },     { NULL, NULL },
	};
	luaL_newlib(L, awaitlib);
	return 1;
}
