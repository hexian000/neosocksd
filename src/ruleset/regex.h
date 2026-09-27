/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef RULESET_REGEX_H
#define RULESET_REGEX_H

#include <lua.h>

#include <stddef.h>

/**
 * @brief Convert a Lua string index to a 0-based C offset clamped to [0, len].
 *
 * Lua indices are 1-based, with negatives counting from the end (-1 = last
 * char) and 0 clamping to the start. size_t and lua_Integer have no fixed
 * width relation -- either can be the wider one -- and neither operand is
 * narrowed to the other, so the result is in [0, len] at every target width.
 * Declared here so the width-portable arithmetic can be unit-tested with a
 * synthetic length.
 */
size_t regex_cstrpos(lua_Integer pos, size_t len);

int luaopen_regex(lua_State *restrict L);

#endif /* RULESET_REGEX_H */
