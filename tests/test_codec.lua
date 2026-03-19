-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ test_codec.lua: tests for marshal/unmarshal and zlib ]] --

return function(T)
    T:test("marshal/unmarshal round-trip", function()
        local s = marshal(
            { [9] = 99, 1, 0, math.pi, -3, 999999999999, 1000000000000, ["a"] = "b" },
            "e\"cho", "e",
            { "c", ["h"] = "🍌\n\0" },
            math.mininteger)
        assert(type(s) == "string" and #s > 0)
        local s2 = marshal(unmarshal(s))
        assert(s == s2, string.format(
            "remarshal mismatch\n  original: %s\n  got:      %s", s, s2))
    end)

    T:test("marshal special float values", function()
        local nan_s  = marshal(0 / 0)
        local inf_s  = marshal(1 / 0)
        local ninf_s = marshal(-1 / 0)
        assert(type(nan_s)  == "string" and #nan_s  > 0)
        assert(type(inf_s)  == "string" and #inf_s  > 0)
        assert(type(ninf_s) == "string" and #ninf_s > 0)
        -- special floats round-trip through unmarshal
        local nan_rt  = marshal(unmarshal(nan_s))
        local inf_rt  = marshal(unmarshal(inf_s))
        local ninf_rt = marshal(unmarshal(ninf_s))
        assert(nan_rt  == nan_s,  string.format("nan mismatch: %s vs %s",  nan_s,  nan_rt))
        assert(inf_rt  == inf_s,  string.format("inf mismatch: %s vs %s",  inf_s,  inf_rt))
        assert(ninf_rt == ninf_s, string.format("-inf mismatch: %s vs %s", ninf_s, ninf_rt))
    end)

    T:test("zlib compress/uncompress round-trip", function()
        local s = marshal(
            { [9] = 99, 1, 0, math.pi, -3, 999999999999, 1000000000000, ["a"] = "b" },
            "e\"cho", "e",
            { "c", ["h"] = "🍌\n\0" })
        local z = zlib.compress(s)
        assert(type(z) == "string" and #z > 0)
        assert(#z < #s, string.format(
            "compress should reduce size: %d -> %d", #s, #z))
        local s2 = zlib.uncompress(z)
        assert(s == s2, "zlib round-trip failed")
    end)

    T:test("zlib compress reduces repetitive data", function()
        local s = string.rep("a", 1024)
        local z = zlib.compress(s)
        assert(#z < #s / 4, string.format(
            "1KB of 'a' should compress well: %d -> %d bytes", #s, #z))
        assert(zlib.uncompress(z) == s)
    end)
end
