/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RULESET_BASE_H
#define RULESET_BASE_H

#include "ruleset.h"

#include <ev.h>

#include <lauxlib.h>
#include <lua.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>

static_assert(LUA_VERSION_NUM >= 503, "ruleset requires Lua >= 5.3");

/* luaL_intop performs wrap-around integer arithmetic; it is only provided by
 * lauxlib.h since Lua 5.4, so define a fallback for Lua 5.3 compatibility. */
#ifndef luaL_intop
#define luaL_intop(op, v1, v2)                                                 \
	((lua_Integer)((lua_Unsigned)(v1)op(lua_Unsigned)(v2)))
#endif

struct config;
struct dialreq;
struct resolver;
struct server;

/** @brief Main ruleset structure */
struct ruleset {
	struct ev_loop *loop;
	struct ruleset_vmstats vmstats;
#if WITH_ALLOC_CACHE
	struct mmcache *vmcache;
#endif
	struct {
		int_least32_t memlimit_kb;
		bool traceback;
	} config;
	struct config *conf;
	struct resolver *resolver;
	struct server *server;
	struct dialreq *basereq;
	lua_State *L;
	ev_timer w_ticker;
	ev_idle w_idle;
};

/** @brief Registry indices for Lua registry tables */
enum ruleset_ridx {
	/* t[idx] = short string */
	RIDX_CONSTANT = LUA_RIDX_LAST + 1,
	/* last error */
	RIDX_LASTERROR,
	/* t[lightuserdata] = thread */
	RIDX_AWAIT_CONTEXT,
	/* t[thread] = true */
	RIDX_IDLE_THREAD,
	/* t[thread] = request state, for await.forward() */
	RIDX_FORWARD_CONTEXT,
};

#define ERR_MEMORY "out of memory"
#define ERR_BAD_REGISTRY "Lua registry is corrupted"
#define ERR_INVALID_ADDR "invalid address"
#define ERR_NOT_ASYNC_ROUTINE "not in asynchronous routine"

/** @brief Feature check: Lua to-be-closed variables (Lua 5.4+) */
#define HAVE_LUA_TOCLOSE (LUA_VERSION_NUM >= 504)
/** @brief Feature check: Lua warning system (Lua 5.4+) */
#define HAVE_LUA_WARNING (LUA_VERSION_NUM >= 504)

/**
 * @brief Get ruleset instance from Lua state
 * @param L Lua state
 * @return Ruleset instance
 */
struct ruleset *aux_getruleset(lua_State *restrict L);

/**
 * @brief Create a new weak table
 * @param L Lua state
 * @param mode Weak reference mode ("k", "v", or "kv")
 */
void aux_newweaktable(lua_State *restrict L, const char *mode);

/**
 * @brief Mark value as to-be-closed (Lua 5.4+)
 * @param L Lua state
 * @param idx Stack index
 * @param tname Type name for error messages
 * @param close Close function
 */
void aux_toclose(
	lua_State *restrict L, int idx, const char *tname, lua_CFunction close);

/**
 * @brief Close a to-be-closed value
 * @param L Lua state
 * @param idx Stack index
 */
void aux_close(lua_State *restrict L, int idx);

/**
 * @brief Get registry table by index
 *
 * Stack effect: [-0, +1, v]
 *
 * @param L Lua state
 * @param ridx Registry index
 */
void aux_getregtable(lua_State *restrict L, int ridx);

/**
 * @brief Get or create thread for async operations
 *
 * Stack effect: [-0, +1, v]
 *
 * @param L Lua state
 * @return Thread state
 */
lua_State *aux_getthread(lua_State *restrict L);

/**
 * @brief Stream reader function for Lua
 * @param L Lua state
 * @param ud User data (stream pointer)
 * @param sz Output parameter for chunk size
 * @return Pointer to data chunk, or NULL on EOF
 */
const char *aux_reader(lua_State *restrict L, void *ud, size_t *restrict sz);

/**
 * @brief Format address for display
 *
 * Stack effect: [-1, +1, v]
 *
 * @param L Lua state
 * @return Number of results (1)
 */
int aux_format_addr(lua_State *restrict L);

/**
 * @brief Convert Lua values to dial request
 *
 * Stack effect: [-n, +(0|1), -]
 *
 * @param L Lua state
 * @param n Number of arguments to convert
 * @return true on success, false on error
 */
bool aux_todialreq(lua_State *restrict L, int n);

/**
 * @brief Generate Lua stack traceback
 *
 * Stack effect: [-0, +1, m]
 *
 * @param L Lua state
 * @return Number of results (1)
 */
int aux_traceback(lua_State *restrict L);

/**
 * @brief Resume Lua coroutine
 *
 * Stack effect: [-narg, +0, -]
 *
 * @param L Thread to resume
 * @param from Calling thread
 * @param narg Number of arguments
 * @return Lua result code
 */
int aux_resume(lua_State *restrict L, lua_State *restrict from, int narg);

/**
 * @brief Set (or clear, when @p state is NULL) coroutine @p co's request state
 * @param L Any thread sharing the ruleset registry
 * @param co Coroutine running the request handler
 * @param state Request state pointer, or NULL to clear
 */
void aux_setforward(lua_State *L, lua_State *co, void *state);

/**
 * @brief Get the request state of the running coroutine @p L, or NULL
 */
void *aux_getforward(lua_State *restrict L);

/**
 * @brief Start asynchronous operation
 *
 * Stack effect: [-(narg+1), +(0|1), -]
 *
 * @param L Lua state
 * @param from Calling thread
 * @param narg Number of arguments
 * @param finishidx Finish callback index
 * @return Lua result code
 */
int aux_async(
	lua_State *restrict L, lua_State *restrict from, int narg,
	int finishidx);

/**
 * @brief Protected call into a Lua C function (synchronous operations)
 * @param r Ruleset instance
 * @param func C function to call
 * @param nargs Number of arguments
 * @param nresults Number of expected results
 * @param ... Variable arguments to pass
 * @return true on success, false on error
 */
bool ruleset_pcall(
	struct ruleset *restrict r, lua_CFunction func, int nargs, int nresults,
	...);

/**
 * @brief Resume a suspended async Lua coroutine after I/O completion
 * @param r Ruleset instance
 * @param ctx Operation context
 * @param narg Number of arguments
 * @param ... Variable arguments to pass
 */
void ruleset_resume(struct ruleset *restrict r, void *ctx, int narg, ...);

#endif /* RULESET_BASE_H */
