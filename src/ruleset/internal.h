/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RULESET_INTERNAL_H
#define RULESET_INTERNAL_H

#include "ruleset.h"
#include "conf.h"

#include "lua.h"

#include <ev.h>

struct ruleset {
	struct ev_loop *loop;
	struct ruleset_vmstats vmstats;
	lua_State *L;
	struct ev_timer w_ticker;
};

enum ruleset_ridx {
	RIDX_ERRORS = LUA_RIDX_LAST + 1,
	RIDX_FUNCTIONS = LUA_RIDX_LAST + 2,
	RIDX_CONTEXTS = LUA_RIDX_LAST + 3,
};

#define ERR_MEMORY "out of memory"
#define ERR_BAD_REGISTRY "Lua registry is corrupted"
#define ERR_NOT_YIELDABLE "await cannot be used in non-yieldable context"
#define ERR_INVALID_ROUTE "unable to parse route"

enum ruleset_functions {
	FUNC_REQUEST = 1,
	FUNC_LOADFILE,
	FUNC_INVOKE,
	FUNC_UPDATE,
	FUNC_STATS,
	FUNC_TICK,
	FUNC_TRACEBACK,
	FUNC_XPCALL,
	FUNC_RPCALL,
};

#define CONST_LSTRING(s, len)                                                  \
	((len) != NULL ? (*(len) = sizeof(s) - 1, "" s) : ("" s))

static inline struct ruleset *find_ruleset(lua_State *L)
{
	void *ud;
	(void)lua_getallocf(L, &ud);
	return ud;
}

int format_addr(lua_State *L);

void check_memlimit(struct ruleset *r);

struct reader_status {
	struct stream *s;
	const char *prefix;
	size_t prefixlen;
};

const char *read_stream(lua_State *L, void *ud, size_t *sz);

struct dialreq *pop_dialreq(lua_State *L, const int n);

#endif /* RULESET_INTERNAL_H */
