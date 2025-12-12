/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file marshal.c
 * @brief Lua value marshalling implementation
 *
 * This module provides functionality to marshal Lua values into string
 * representations that can be later loaded back into Lua. It supports
 * basic types (nil, boolean, number, string, table) and handles special
 * cases like circular references, floating point edge cases, and proper
 * string escaping.
 */

#include "marshal.h"

#include "base.h"

#include "utils/ascii.h"
#include "utils/buffer.h"
#include "utils/debug.h"

#include "util.h"

#include "lauxlib.h"
#include "lua.h"

#include <stddef.h>
#include <stdint.h>
#include <tgmath.h>

#define MT_MARSHAL_BUFFER "marshal_buffer"

/**
 * @brief Cleanup function for marshal buffer userdata
 * @param L Lua state
 * @return Number of return values (always 0)
 *
 * This function is called when a marshal buffer userdata is garbage collected
 * or explicitly closed. It frees the associated vbuffer memory.
 */
static int marshal_buffer_close(lua_State *restrict L)
{
	struct vbuffer **pvbuf = lua_touserdata(L, 1);
	*pvbuf = VBUF_FREE(*pvbuf);
	return 0;
}

/**
 * @brief Marshal a Lua string value into buffer
 * @param L Lua state (string at index 1)
 * @param pvbuf Pointer to variable buffer pointer
 *
 * Converts a Lua string into a properly escaped string literal that can be
 * parsed back by Lua. The marshalling process:
 * 1. Wraps the string in double quotes
 * 2. Escapes special characters: ", \, and newline with backslash
 * 3. Converts control characters to octal escape sequences (\000-\377)
 * 4. Leaves other characters unchanged
 *
 * Stack effect: [-0, +0, -] (no stack changes, no errors)
 */
static void
marshal_string(lua_State *restrict L, struct vbuffer *restrict *restrict pvbuf)
{
	const int idx = 1;
	size_t len;
	const char *restrict str = lua_tolstring(L, idx, &len);

	/* Start with opening quote */
	*pvbuf = VBUF_APPENDSTR(*pvbuf, "\"");

	/* Process each character */
	while (len--) {
		const unsigned char ch = *str;

		/* Handle special characters that need backslash escaping */
		if (ch == '"' || ch == '\\' || ch == '\n') {
			const unsigned char buf[2] = { '\\', ch };
			*pvbuf = VBUF_APPEND(*pvbuf, buf, sizeof(buf));
		}
		/* Convert control characters to octal escape sequences */
		else if (iscntrl(ch)) {
			unsigned char buf[4];
			unsigned char *s = &buf[sizeof(buf)];
			uint_fast8_t x = ch;

			/* Build octal representation backwards: \ddd */
			*--s = '0' + x % 10, x /= 10;
			*--s = '0' + x % 10, x /= 10;
			*--s = '0' + x % 10;
			*--s = '\\'; /* escape prefix */

			*pvbuf = VBUF_APPEND(*pvbuf, buf, sizeof(buf));
		}
		/* Regular characters pass through unchanged */
		else {
			*pvbuf = VBUF_APPEND(*pvbuf, &ch, sizeof(ch));
		}
		str++;
	}

	/* End with closing quote */
	*pvbuf = VBUF_APPENDSTR(*pvbuf, "\"");
}

/**
 * @brief Marshal a Lua number value into buffer
 * @param L Lua state (number at index 1)
 * @param pvbuf Pointer to variable buffer pointer
 *
 * Converts a Lua number into a string representation that preserves exact
 * value when parsed back. The function handles both integers and floating
 * point numbers with special optimizations:
 *
 * For integers:
 * - Zero is represented as "0"
 * - Small integers (≤999999999999) use decimal notation
 * - Large integers use hexadecimal notation (0x...) for compactness
 * - Handles LUA_MININTEGER edge case properly
 *
 * For floating point:
 * - NaN is represented as "0/0"
 * - Infinity as "1/0" or "-1/0"
 * - Zero as "0"
 * - Other values use hexadecimal floating point notation (-0x1.23p+4)
 *   which preserves exact binary representation
 *
 * Stack effect: [-0, +0, -] (no stack changes, no errors)
 */
static void
marshal_number(lua_State *restrict L, struct vbuffer *restrict *restrict pvbuf)
{
	const int idx = 1;
	static const char prefix[] = "-0x";
	static const char xdigits[] = "0123456789abcdef";
	unsigned char buf[120];

	/* Handle integer values */
	if (lua_isinteger(L, idx)) {
		lua_Integer x = lua_tointeger(L, idx);
		unsigned char *const bufend = &buf[sizeof(buf)];
		unsigned char *s = bufend;

		if (x == 0) {
			*pvbuf = VBUF_APPENDSTR(*pvbuf, "0");
			return;
		}

		/* Determine sign and prefix */
		const char *p = prefix;
		const char *pend = prefix + sizeof(prefix) - 1;
		if (x < 0 && x != LUA_MININTEGER) {
			x = -x; /* Make positive, keep negative prefix */
		} else {
			p++; /* Skip negative sign */
		}

		lua_Unsigned y = x;

		/* Choose decimal vs hexadecimal based on size */
		if (y <= UINTMAX_C(999999999999)) {
			/* Use decimal notation for smaller numbers */
			pend -= 2; /* Skip "0x" prefix */
			do {
				*--s = '0' + y % 10;
				y /= 10;
			} while (y);
		} else {
			/* Use hexadecimal for large numbers (more compact) */
			do {
				*--s = xdigits[(y & 0xf)];
				y >>= 4;
			} while (y);
		}

		*pvbuf = VBUF_APPEND(*pvbuf, p, pend - p);
		*pvbuf = VBUF_APPEND(*pvbuf, s, bufend - s);
		return;
	}

	/* Handle floating point values */
	lua_Number x = lua_tonumber(L, idx);

	/* Handle special floating point values */
	switch (fpclassify(x)) {
	case FP_NAN:
		*pvbuf = VBUF_APPENDSTR(*pvbuf, "0/0");
		return;
	case FP_INFINITE:
		if (signbit(x)) {
			*pvbuf = VBUF_APPENDSTR(*pvbuf, "-1/0");
			return;
		}
		*pvbuf = VBUF_APPENDSTR(*pvbuf, "1/0");
		return;
	case FP_ZERO:
		*pvbuf = VBUF_APPENDSTR(*pvbuf, "0");
		return;
	default:
		break;
	}

	/* Generate hexadecimal floating point representation */
	unsigned char *s = buf;

	/* Handle sign prefix */
	const char *p = prefix;
	const char *pend = prefix + sizeof(prefix) - 1;
	if (signbit(x)) {
		x = -x; /* Make positive, keep negative prefix */
	} else {
		p++; /* Skip negative sign */
	}

	/* Extract exponent using frexp, then adjust for hex format */
	int e2 = 0;
	x = frexp(x, &e2) * 2; /* frexp gives [0.5,1), we want [1,2) */
	if (x) {
		e2--; /* Adjust exponent for [1,2) range */
	}

	/* Build exponent string backwards */
	unsigned char *const bufend = &buf[sizeof(buf)];
	unsigned char *estr = bufend;
	for (int r = e2 < 0 ? -e2 : e2; r; r /= 10) {
		*--estr = '0' + r % 10;
	}
	if (estr == bufend) {
		*--estr = '0'; /* Exponent is 0 */
	}
	*--estr = (e2 < 0 ? '-' : '+');
	*--estr = 'p'; /* Binary exponent marker */

	/* Build mantissa in hexadecimal */
	do {
		const int i = (int)x;
		*s++ = xdigits[i];
		x = 16 * (x - i); /* Extract next hex digit */

		/* Add decimal point after first digit if more digits follow */
		if (s - buf == 1 && x) {
			*s++ = '.';
		}
	} while (x);

	/* Combine all parts: prefix + mantissa + exponent */
	*pvbuf = VBUF_APPEND(*pvbuf, p, pend - p);
	*pvbuf = VBUF_APPEND(*pvbuf, buf, s - buf);
	*pvbuf = VBUF_APPEND(*pvbuf, estr, bufend - estr);
}

#define IDX_BUFFER (lua_upvalueindex(1))
#define IDX_VISITED (lua_upvalueindex(2))
#define IDX_MARSHAL (lua_upvalueindex(3))

/**
 * @brief Marshal a Lua table into buffer
 * @param L Lua state (table at index 1)
 * @param pvbuf Pointer to variable buffer pointer
 *
 * Converts a Lua table into a table constructor syntax that can be parsed
 * back by Lua. The marshalling process:
 *
 * 1. Detects circular references and throws error if found
 * 2. Marks table as visited to prevent infinite recursion
 * 3. Iterates through all key-value pairs
 * 4. Uses array syntax for consecutive integer keys starting from 1
 * 5. Uses [key]=value syntax for non-consecutive or non-integer keys
 * 6. Recursively marshals both keys and values
 *
 * Output format: {value1,value2,[key]=value,...}
 *
 * Stack effect: [-0, +0, m] (no net stack change, may throw error)
 */
static void
marshal_table(lua_State *restrict L, struct vbuffer *restrict *restrict pvbuf)
{
	const int idx = 1;

	/* Check for circular references */
	lua_pushvalue(L, idx);
	if (lua_rawget(L, IDX_VISITED) != LUA_TNIL) {
		lua_pushliteral(
			L, "circular referenced table is not marshallable");
		lua_error(L);
		return;
	}

	/* Mark table as visited to detect cycles */
	lua_pushvalue(L, idx);
	lua_pushboolean(L, 1);
	lua_rawset(L, IDX_VISITED);

	/* Start table constructor */
	*pvbuf = VBUF_APPENDSTR(*pvbuf, "{");

	/* Track consecutive integer indices starting from 1 */
	lua_Integer i = 1;

	/* Iterate through all table entries */
	while (lua_next(L, idx) != 0) {
		/* Check if this is a consecutive integer key */
		if (lua_isinteger(L, -2) && lua_tointeger(L, -2) == i) {
			/* Use array syntax: just the value */
			i = luaL_intop(+, i, 1); /* Increment expected index */
		} else {
			/* Use explicit key syntax: [key]=value */
			*pvbuf = VBUF_APPENDSTR(*pvbuf, "[");

			/* Marshal the key */
			lua_pushvalue(L, IDX_MARSHAL);
			lua_pushvalue(L, -3); /* Push key */
			lua_call(L, 1, 0);

			*pvbuf = VBUF_APPENDSTR(*pvbuf, "]=");
		}

		/* Marshal the value */
		lua_pushvalue(L, IDX_MARSHAL);
		lua_pushvalue(L, -2); /* Push value */
		lua_call(L, 1, 0);

		*pvbuf = VBUF_APPENDSTR(*pvbuf, ",");
		lua_pop(L, 1); /* Remove value, keep key for next iteration */
	}

	/* End table constructor */
	*pvbuf = VBUF_APPENDSTR(*pvbuf, "}");
}

/**
 * @brief Main marshal dispatch function
 * @param L Lua state (value to marshal at index 1)
 * @return Always 0 (or throws error)
 *
 * This is the core marshalling function that dispatches to appropriate
 * type-specific marshalling functions. It handles all basic Lua types:
 * - nil: "nil"
 * - boolean: "true" or "false"
 * - number: handled by marshal_number()
 * - string: handled by marshal_string()
 * - table: handled by marshal_table() with metatable warning
 *
 * For tables with metatables, it issues a warning but continues marshalling
 * (the metatable itself is not marshalled, only the table contents).
 *
 * Unsupported types (functions, userdata, threads) cause an error.
 *
 * Stack effect: [-0, +0, v] (no net stack change, may throw error)
 */
static int marshal_value(lua_State *restrict L)
{
	const int idx = 1;
	struct vbuffer *restrict *restrict pvbuf =
		lua_touserdata(L, IDX_BUFFER);
	const int type = lua_type(L, idx);

	switch (type) {
	case LUA_TNIL:
		*pvbuf = VBUF_APPENDSTR(*pvbuf, "nil");
		break;

	case LUA_TBOOLEAN:
		if (lua_toboolean(L, idx)) {
			*pvbuf = VBUF_APPENDSTR(*pvbuf, "true");
		} else {
			*pvbuf = VBUF_APPENDSTR(*pvbuf, "false");
		}
		break;

	case LUA_TNUMBER:
		marshal_number(L, pvbuf);
		break;

	case LUA_TSTRING:
		marshal_string(L, pvbuf);
		break;

	case LUA_TTABLE:
#if HAVE_LUA_WARNING
		/* Warn if table has a metatable (which won't be marshalled) */
		if (lua_getmetatable(L, idx)) {
			lua_warning(L, "marshal: ", 1);
			lua_warning(L, luaL_tolstring(L, idx, NULL), 1);
			lua_warning(L, " has a metatable", 0);
			lua_pop(L, 1);
		}
#endif
		marshal_table(L, pvbuf);
		break;

	default:
		/* Unsupported types: functions, userdata, threads */
		return luaL_error(
			L, "%s is not marshallable",
			luaL_tolstring(L, idx, NULL));
	}

	/* Check for memory allocation failure */
	/* VBUF_APPEND* will always reserve 1 extra byte */
	if (VBUF_REMAINING(*pvbuf) == 0) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}

	return 0;
}

/**
 * @brief Public API function to marshal multiple Lua values
 * @param L Lua state (values to marshal as arguments)
 * @return 1 (marshalled string on stack)
 *
 * This is the main entry point for the marshal functionality. It takes
 * zero or more arguments and marshals them into a single comma-separated
 * string that can be parsed back by Lua.
 *
 * The marshalling process:
 * 1. Creates a managed buffer for output
 * 2. Builds a closure containing the marshal_value function with upvalues:
 *    - Buffer pointer for output
 *    - Visited table for cycle detection
 *    - Self-reference for recursive calls
 * 3. Marshals each argument, separated by commas
 * 4. Returns the final marshalled string
 *
 * Memory management: Uses aux_toclose for automatic buffer cleanup.
 */
int api_marshal(lua_State *restrict L)
{
	const int n = lua_gettop(L);

	/* Handle empty argument list */
	if (n < 1) {
		lua_pushliteral(L, "");
		return 1;
	}

	/* Create managed buffer userdata */
	struct vbuffer *restrict *restrict pvbuf =
		lua_newuserdata(L, sizeof(struct vbuffer *));
	*pvbuf = NULL;
	aux_toclose(L, -1, MT_MARSHAL_BUFFER, marshal_buffer_close);

	/* Allocate initial buffer */
	*pvbuf = VBUF_NEW(1024);
	if (*pvbuf == NULL) {
		lua_pushliteral(L, ERR_MEMORY);
		return lua_error(L);
	}

	/* lua stack: args... buffer */

	/* Build marshal closure with upvalues */
	lua_pushvalue(L, -1); /* IDX_BUFFER: buffer userdata */
	lua_createtable(L, 0, 16); /* IDX_VISITED: visited table */
	lua_pushnil(L); /* IDX_MARSHAL: placeholder for self-ref */
	lua_pushcclosure(L, marshal_value, 3);

	/* Set up self-reference for recursive calls */
	lua_pushvalue(L, -1);
	const char *upvalue = lua_setupvalue(L, -2, 3);
	ASSERT(upvalue != NULL);
	UNUSED(upvalue);

	/* lua stack: args... buffer closure */

	/* Marshal arguments with comma separation */
	int i = 1;
	for (; i < n; i++) {
		/* Marshal argument i */
		lua_pushvalue(L, -1); /* Push closure */
		lua_pushvalue(L, i); /* Push argument */
		lua_call(L, 1, 0);

		/* Add comma separator */
		*pvbuf = VBUF_APPENDSTR(*pvbuf, ",");
	}

	/* Marshal final argument without trailing comma */
	if (i == n) {
		lua_pushvalue(L, i); /* Push argument */
		lua_call(L, 1, 0); /* Call closure with argument */
	}

	/* Return marshalled string */
	lua_pushlstring(L, VBUF_DATA(*pvbuf), VBUF_LEN(*pvbuf));
	aux_close(L, n + 1); /* Clean up buffer */
	return 1;
}

/**
 * @brief Lua module initialization function
 * @param L Lua state
 * @return 1 (marshal function on stack)
 *
 * Standard Lua module loader function. Pushes the marshal function
 * onto the stack to be returned as the module's main function.
 */
int luaopen_marshal(lua_State *restrict L)
{
	lua_pushcfunction(L, api_marshal);
	return 1;
}
