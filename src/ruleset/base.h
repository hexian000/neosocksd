/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RULESET_BASE_H
#define RULESET_BASE_H

#include "ruleset.h"

#include "lua.h"

_Static_assert(LUA_VERSION_NUM >= 503, "ruleset requires Lua >= 5.3");

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>

/**
 * @brief Main ruleset structure
 *
 * Contains the complete state of a ruleset instance, including the
 * Lua virtual machine, event loop integration, and configuration.
 */
struct ruleset {
	struct ev_loop *loop;
	struct ruleset_vmstats vmstats;
	struct {
		int memlimit_kb;
		bool traceback;
	} config;
	lua_State *L;
	ev_timer w_ticker;
	ev_idle w_idle;
};

/**
 * @brief Registry indices for Lua registry tables
 *
 * These indices are used to store various tables and values in the
 * Lua registry for efficient access during ruleset operations.
 */
enum ruleset_ridx {
	/* t[idx] = short string */
	RIDX_CONSTANT = LUA_RIDX_LAST + 1,
	/* last error */
	RIDX_LASTERROR,
	/* t[lightuserdata] = thread */
	RIDX_AWAIT_CONTEXT,
	/* t[thread] = true */
	RIDX_IDLE_THREAD,
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
struct ruleset *aux_getruleset(lua_State *L);

/**
 * @brief Create a new weak table
 * @param L Lua state
 * @param mode Weak reference mode ("k", "v", or "kv")
 */
void aux_newweaktable(lua_State *L, const char *mode);

/**
 * @brief Mark value as to-be-closed (Lua 5.4+)
 * @param L Lua state
 * @param idx Stack index
 * @param tname Type name for error messages
 * @param close Close function
 */
void aux_toclose(lua_State *L, int idx, const char *tname, lua_CFunction close);

/**
 * @brief Close a to-be-closed value
 * @param L Lua state
 * @param idx Stack index
 */
void aux_close(lua_State *L, int idx);

/**
 * @brief Get registry table by index
 *
 * Stack effect: [-0, +1, v]
 *
 * @param L Lua state
 * @param ridx Registry index
 */
void aux_getregtable(lua_State *L, int ridx);

/**
 * @brief Get or create thread for async operations
 *
 * Stack effect: [-0, +1, v]
 *
 * @param L Lua state
 * @return Thread state
 */
lua_State *aux_getthread(lua_State *L);

/**
 * @brief Stream reader function for Lua
 * @param L Lua state
 * @param ud User data (stream pointer)
 * @param sz Output parameter for chunk size
 * @return Pointer to data chunk, or NULL on EOF
 */
const char *aux_reader(lua_State *L, void *ud, size_t *sz);

/**
 * @brief Format address for display
 *
 * Stack effect: [-1, +1, v]
 *
 * @param L Lua state
 * @return Number of results (1)
 */
int aux_format_addr(lua_State *L);

/**
 * @brief Convert Lua values to dial request
 *
 * Stack effect: [-n, +(0|1), -]
 *
 * @param L Lua state
 * @param n Number of arguments to convert
 * @return true on success, false on error
 */
bool aux_todialreq(lua_State *L, int n);

/**
 * @brief Generate Lua stack traceback
 *
 * Stack effect: [-0, +1, m]
 *
 * @param L Lua state
 * @return Number of results (1)
 */
int aux_traceback(lua_State *L);

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
int aux_resume(lua_State *L, lua_State *from, int narg);

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
int aux_async(lua_State *L, lua_State *from, int narg, int finishidx);

/**
 * @brief Call Lua function with protected call
 *
 * Main routine for synchronous operations.
 *
 * @param r Ruleset instance
 * @param func C function to call
 * @param nargs Number of arguments
 * @param nresults Number of expected results
 * @param ... Variable arguments to pass
 * @return true on success, false on error
 */
bool ruleset_pcall(
	struct ruleset *r, lua_CFunction func, int nargs, int nresults, ...);

/**
 * @brief Resume asynchronous Lua operation
 *
 * Used for continuing async operations after I/O completion.
 *
 * @param r Ruleset instance
 * @param ctx Operation context
 * @param narg Number of arguments
 * @param ... Variable arguments to pass
 */
void ruleset_resume(struct ruleset *r, void *ctx, int narg, ...);

#endif /* RULESET_BASE_H */
