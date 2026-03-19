-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ test_regex.lua: tests for the built-in regex module ]] --

return function(T)
    T:test("regex.compile", function()
        local reg = regex.compile("a(a)(a)")
        assert(reg ~= nil)
    end)

    T:test("regex.find returns 1-based positions", function()
        local reg = regex.compile("a(a)(a)")
        -- "aaaaa": first match of "aaa" is at positions 1-3
        local s, e = reg:find("aaaaa")
        assert(s == 1 and e == 3, string.format("got s=%s e=%s", s, e))
    end)

    T:test("regex.find no match returns nothing", function()
        local reg = regex.compile("xyz")
        local s = reg:find("aaaaaa")
        assert(s == nil)
    end)

    T:test("regex.match returns full match then captures", function()
        local reg = regex.compile("a(a)(a)")
        -- nmatch = re_nsub + 1 = 3: full match + 2 groups
        local m0, m1, m2 = reg:match("aaaaa")
        assert(m0 == "aaa", string.format("full match: got %q", tostring(m0)))
        assert(m1 == "a",   string.format("group1: got %q", tostring(m1)))
        assert(m2 == "a",   string.format("group2: got %q", tostring(m2)))
    end)

    T:test("regex.match no match returns nothing", function()
        local reg = regex.compile("xyz")
        local m = reg:match("aaaaaa")
        assert(m == nil)
    end)

    T:test("regex.gmatch full match then captures each iteration", function()
        local reg = regex.compile("a(a)(a)")
        local results = {}
        for m0, m1, m2 in reg:gmatch("aaaaaa") do
            table.insert(results, { m0, m1, m2 })
        end
        -- "aaaaaa" has two non-overlapping matches of "aaa"
        assert(#results == 2, string.format("expected 2 matches, got %d", #results))
        assert(results[1][1] == "aaa" and results[1][2] == "a" and results[1][3] == "a")
        assert(results[2][1] == "aaa" and results[2][2] == "a" and results[2][3] == "a")
    end)

    T:test("regex.compat with EXTENDED and NEWLINE flags", function()
        local reg = regex.compile(
            regex.compat("(\\w+)=(\\w+)"),
            regex.EXTENDED | regex.NEWLINE)
        local found = {}
        for _, key, value in reg:gmatch("from=world, to=Lua") do
            table.insert(found, { key, value })
        end
        assert(#found == 2, string.format("expected 2 matches, got %d", #found))
        assert(found[1][1] == "from"  and found[1][2] == "world")
        assert(found[2][1] == "to"    and found[2][2] == "Lua")
    end)

    T:test("regex.gmatch matches string.gmatch captures", function()
        local reg = regex.compile("a(a)(a)")
        local lua_results = {}
        for a, b in string.gmatch("aaaaaa", "a(a)(a)") do
            table.insert(lua_results, { a, b })
        end
        -- string.gmatch returns only captures (no full match)
        assert(#lua_results == 2)
        assert(lua_results[1][1] == "a" and lua_results[1][2] == "a")
        assert(lua_results[2][1] == "a" and lua_results[2][2] == "a")
        -- regex.gmatch returns full match first; captures match string.gmatch
        local reg_results = {}
        for _, c1, c2 in reg:gmatch("aaaaaa") do
            table.insert(reg_results, { c1, c2 })
        end
        assert(#reg_results == #lua_results)
        for i = 1, #lua_results do
            assert(reg_results[i][1] == lua_results[i][1])
            assert(reg_results[i][2] == lua_results[i][2])
        end
    end)
end
