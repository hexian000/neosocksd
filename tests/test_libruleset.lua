-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ test_libruleset.lua: tests for libruleset.lua utilities ]] --

return function(T)

    -- [[ string extensions ]] --

    T:test("string.startswith true", function()
        assert(string.startswith("hello world", "hello"))
        assert(string.startswith("hello", "hello"))
        assert(string.startswith("hello", ""))
    end)

    T:test("string.startswith false", function()
        assert(not string.startswith("hello world", "world"))
        assert(not string.startswith("hello", "hello world"))
    end)

    T:test("string.endswith true", function()
        assert(string.endswith("hello world", "world"))
        assert(string.endswith("hello", "hello"))
    end)

    T:test("string.endswith false", function()
        assert(not string.endswith("hello world", "hello"))
        assert(not string.endswith("hello", "hello world"))
    end)

    -- [[ table.get ]] --

    T:test("table.get no args returns table", function()
        local t = { x = 1 }
        assert(table.get(t) == t)
    end)

    T:test("table.get single key", function()
        assert(table.get({ x = 42 }, "x") == 42)
        assert(table.get({ x = 42 }, "y") == nil)
    end)

    T:test("table.get nested path", function()
        local t = { a = { b = { c = 99 } } }
        assert(table.get(t, "a", "b", "c") == 99)
        assert(table.get(t, "a", "x", "c") == nil)
        assert(table.get(t, "x") == nil)
    end)

    -- [[ list ]] --

    T:test("list:new empty", function()
        local l = list:new()
        assert(#l == 0)
        assert(list:check(l) == l)
    end)

    T:test("list:new with table", function()
        local l = list:new({ 10, 20, 30 })
        assert(#l == 3 and l[1] == 10 and l[2] == 20 and l[3] == 30)
    end)

    T:test("list:check rejects plain table and nil", function()
        assert(list:check({}) == nil)
        assert(list:check(nil) == nil)
    end)

    T:test("list:totable removes metatable", function()
        local l = list:new({ 1, 2 })
        local t = l:totable()
        assert(list:check(t) == nil)
        assert(t[1] == 1 and t[2] == 2)
    end)

    T:test("list:insertf formats string", function()
        local l = list:new()
        l:insertf("%d+%d=%d", 1, 2, 3)
        assert(l[1] == "1+2=3")
    end)

    T:test("list:append copies elements", function()
        local l = list:new({ 1, 2 })
        l:append({ 3, 4 })
        assert(#l == 4 and l[3] == 3 and l[4] == 4)
    end)

    T:test("list:map transforms in place", function()
        local l = list:new({ 1, 2, 3 })
        l:map(function(v) return v * 2 end)
        assert(l[1] == 2 and l[2] == 4 and l[3] == 6)
    end)

    T:test("list:reverse", function()
        local l = list:new({ 1, 2, 3, 4 })
        l:reverse()
        assert(l[1] == 4 and l[2] == 3 and l[3] == 2 and l[4] == 1)
    end)

    T:test("list:sort default order", function()
        local l = list:new({ 3, 1, 4, 1, 5 })
        l:sort()
        assert(l[1] == 1 and l[2] == 1 and l[3] == 3 and l[4] == 4 and l[5] == 5)
    end)

    -- [[ rlist ]] --

    T:test("rlist:new empty", function()
        local r = rlist:new(3)
        assert(r.len == 0 and r.cap == 3)
    end)

    T:test("rlist:new with initial data", function()
        local r = rlist:new(5, { 10, 20, 30 })
        assert(r.len == 3)
        -- get(1) is newest, get(3) is oldest
        assert(r:get(1) == 30 and r:get(2) == 20 and r:get(3) == 10)
    end)

    T:test("rlist:check positive and negative", function()
        local r = rlist:new(3)
        assert(rlist:check(r) == r)
        assert(rlist:check({}) == nil)
        assert(rlist:check(nil) == nil)
    end)

    T:test("rlist:push and get", function()
        local r = rlist:new(3)
        r:push("a")
        r:push("b")
        r:push("c")
        assert(r.len == 3)
        assert(r:get(1) == "c" and r:get(2) == "b" and r:get(3) == "a")
    end)

    T:test("rlist:push evicts oldest when full", function()
        local r = rlist:new(3)
        r:push("a")
        r:push("b")
        r:push("c")
        r:push("d")
        assert(r.len == 3)
        assert(r:get(1) == "d" and r:get(2) == "c" and r:get(3) == "b")
    end)

    T:test("rlist:get negative index", function()
        local r = rlist:new(3)
        r:push("a")
        r:push("b")
        r:push("c")
        -- negative: -1 is oldest, -3 is newest
        assert(r:get(-1) == "a" and r:get(-2) == "b" and r:get(-3) == "c")
    end)

    T:test("rlist:get out of bounds returns nil", function()
        local r = rlist:new(3)
        r:push("a")
        assert(r:get(0) == nil)
        assert(r:get(2) == nil)
        assert(r:get(-2) == nil)
    end)

    T:test("rlist:iter yields newest-first", function()
        local r = rlist:new(5)
        r:push(10)
        r:push(20)
        r:push(30)
        local result = {}
        for i, v in r:iter() do
            result[i] = v
        end
        assert(#result == 3)
        assert(result[1] == 30 and result[2] == 20 and result[3] == 10)
    end)

    -- [[ format_timestamp ]] --

    T:test("format_timestamp produces fixed-length ISO 8601 string", function()
        local s = format_timestamp(os.time())
        assert(type(s) == "string" and #s == 25,
            string.format("expected 25 chars, got %d: %q", #s, s))
        assert(s:match("^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d[+-]%d%d:%d%d$"),
            string.format("not ISO 8601: %q", s))
    end)

    -- [[ parse_cidr ]] --

    T:test("parse_cidr valid subnet", function()
        local subnet, shift = parse_cidr("192.168.1.0/24")
        assert(shift == 24)
        assert(subnet == neosocksd.parse_ipv4("192.168.1.0"))
    end)

    T:test("parse_cidr errors on prefix > 32", function()
        local ok = pcall(parse_cidr, "192.168.1.0/33")
        assert(not ok, "expected error for prefix > 32")
    end)

    T:test("parse_cidr errors on misaligned subnet", function()
        local ok = pcall(parse_cidr, "192.168.1.1/24")
        assert(not ok, "expected error for misaligned subnet")
    end)

    -- [[ parse_cidr6 ]] --

    T:test("parse_cidr6 valid subnet", function()
        local s1, s2, shift = parse_cidr6("2001:db8::/32")
        assert(shift == 32)
        local e1, e2 = neosocksd.parse_ipv6("2001:db8::")
        assert(s1 == e1 and s2 == e2)
    end)

    T:test("parse_cidr6 errors on prefix > 128", function()
        local ok = pcall(parse_cidr6, "2001:db8::/129")
        assert(not ok, "expected error for prefix > 128")
    end)

    T:test("parse_cidr6 errors on misaligned subnet", function()
        local ok = pcall(parse_cidr6, "2001:db8::1/32")
        assert(not ok, "expected error for misaligned subnet")
    end)

    -- [[ inet.subnet ]] --

    T:test("inet.subnet single CIDR match and no-match", function()
        local m = inet.subnet("192.168.0.0/16")
        assert(m(neosocksd.parse_ipv4("192.168.1.100")))
        assert(not m(neosocksd.parse_ipv4("10.0.0.1")))
    end)

    T:test("inet.subnet table of CIDRs", function()
        local m = inet.subnet({ "10.0.0.0/8", "192.168.0.0/16" })
        assert(m(neosocksd.parse_ipv4("192.168.1.1")))
        assert(m(neosocksd.parse_ipv4("10.255.255.255")))
        assert(not m(neosocksd.parse_ipv4("172.16.0.1")))
    end)

    -- [[ inet6.subnet ]] --

    T:test("inet6.subnet single CIDR match and no-match (shift <= 64)", function()
        local m = inet6.subnet("2001:db8::/32")
        local ip1, ip2 = neosocksd.parse_ipv6("2001:db8::1")
        assert(m(ip1, ip2))
        local ip3, ip4 = neosocksd.parse_ipv6("2001:db9::1")
        assert(not m(ip3, ip4))
    end)

    T:test("inet6.subnet single CIDR match and no-match (shift > 64)", function()
        local m = inet6.subnet("2001:db8::/96")
        local ip1, ip2 = neosocksd.parse_ipv6("2001:db8::1")
        assert(m(ip1, ip2))
        -- same high 64 bits but different top-32 of low half
        local ip3, ip4 = neosocksd.parse_ipv6("2001:db8:0:0:1::1")
        assert(not m(ip3, ip4))
    end)

    T:test("inet6.subnet table of CIDRs", function()
        local m = inet6.subnet({ "2001:db8::/32", "fc00::/7" })
        local ip1, ip2 = neosocksd.parse_ipv6("2001:db8::1")
        assert(m(ip1, ip2))
        local ip3, ip4 = neosocksd.parse_ipv6("fd00::1")
        assert(m(ip3, ip4))
        local ip5, ip6 = neosocksd.parse_ipv6("2001:db9::1")
        assert(not m(ip5, ip6))
    end)

    -- [[ match.any ]] --

    T:test("match.any always returns true", function()
        local m = match.any()
        assert(m("anything:80"))
        assert(m(""))
    end)

    -- [[ match.exact ]] --

    T:test("match.exact single string", function()
        local m = match.exact("example.com:80")
        assert(m("example.com:80"))
        assert(not m("example.com:443"))
        assert(not m("other.com:80"))
    end)

    T:test("match.exact table of strings", function()
        local m = match.exact({ "example.com:80", "other.com:443" })
        assert(m("example.com:80"))
        assert(m("other.com:443"))
        assert(not m("example.com:443"))
    end)

    -- [[ match.host ]] --

    T:test("match.host single string", function()
        local m = match.host("example.com")
        assert(m("example.com:80"))
        assert(m("example.com:443"))
        assert(not m("other.com:80"))
    end)

    T:test("match.host table of strings", function()
        local m = match.host({ "example.com", "other.com" })
        assert(m("example.com:80"))
        assert(m("other.com:443"))
        assert(not m("third.com:80"))
    end)

    -- [[ match.port ]] --

    T:test("match.port single value", function()
        local m = match.port(80)
        assert(m("example.com:80"))
        assert(not m("example.com:443"))
    end)

    T:test("match.port range", function()
        local m = match.port(1024, 65535)
        assert(m("example.com:8080"))
        assert(not m("example.com:80"))
    end)

    T:test("match.port table of ports", function()
        local m = match.port({ 80, 443, 8080 })
        assert(m("example.com:80"))
        assert(m("example.com:8080"))
        assert(not m("example.com:8888"))
    end)

    -- [[ match.domain ]] --

    T:test("match.domain matches exact and subdomains", function()
        local m = match.domain("example.com")
        assert(m("example.com:80"))
        assert(m("sub.example.com:80"))
        assert(not m("notexample.com:80"))
        assert(not m("other.com:80"))
    end)

    T:test("match.domain with leading dot", function()
        local m = match.domain(".example.com")
        assert(m("example.com:80"))
        assert(m("sub.example.com:80"))
        assert(not m("other.com:80"))
    end)

    T:test("match.domain table of domains", function()
        local m = match.domain({ "example.com", "other.org" })
        assert(m("example.com:80"))
        assert(m("sub.example.com:80"))
        assert(m("other.org:443"))
        assert(not m("third.net:80"))
    end)

    -- [[ match.domaintree ]] --

    T:test("match.domaintree manual tree", function()
        local tree = {
            com = { example = true },
            org = { other = { sub = true } },
        }
        local m = match.domaintree(tree)
        assert(m("example.com:80"))
        assert(m("sub.other.org:443"))
        assert(not m("other.com:80"))
        -- "other.org" itself is not in the tree, only "sub.other.org" is
        assert(not m("other.org:80"))
    end)

    -- [[ match.pattern ]] --

    T:test("match.pattern single Lua pattern", function()
        local m = match.pattern("^192%.168%.")
        assert(m("192.168.1.1:80"))
        assert(not m("10.0.0.1:80"))
    end)

    T:test("match.pattern table of patterns", function()
        local m = match.pattern({ "^192%.168%.", "^10%." })
        assert(m("192.168.1.1:80"))
        assert(m("10.0.0.1:80"))
        assert(not m("172.16.0.1:80"))
    end)

    -- [[ match.regex ]] --

    T:test("match.regex single regex", function()
        local m = match.regex("^192\\.168\\.")
        assert(m("192.168.1.1:80"))
        assert(not m("10.0.0.1:80"))
    end)

    T:test("match.regex table of regexes", function()
        local m = match.regex({ "^192\\.168\\.", "^10\\." })
        assert(m("192.168.1.1:80"))
        assert(m("10.0.0.1:80"))
        assert(not m("172.16.0.1:80"))
    end)

    -- [[ regex.compat ]] --

    T:test("regex.compat substitutes known escape sequences", function()
        local s = regex.compat("\\d+\\.\\w+\\s*\\S+")
        assert(s == "[0-9]+\\.[a-zA-Z0-9_]+[[:space:]]*[^[:space:]]+",
            string.format("unexpected result: %q", s))
    end)

    T:test("regex.compat substitutes all defined escapes", function()
        local cases = {
            { "\\d", "[0-9]" },
            { "\\D", "[^0-9]" },
            { "\\w", "[a-zA-Z0-9_]" },
            { "\\W", "[^a-zA-Z0-9_]" },
            { "\\s", "[[:space:]]" },
            { "\\S", "[^[:space:]]" },
        }
        for _, c in ipairs(cases) do
            local got = regex.compat(c[1])
            assert(got == c[2],
                string.format("compat(%q): expected %q, got %q", c[1], c[2], got))
        end
    end)

    T:test("regex.compat preserves unknown escape sequences", function()
        local s = regex.compat("\\n\\t\\.")
        assert(s == "\\n\\t\\.", string.format("unexpected: %q", s))
    end)

    -- [[ composite matchers ]] --

    T:test("composite.inverse negates matcher", function()
        local f = function(x) return x > 0 end
        local g = composite.inverse(f)
        assert(g(0) and g(-1))
        assert(not g(1))
    end)

    T:test("composite.anyof matches when any matcher passes", function()
        local m = composite.anyof({
            function(x) return x == 1 end,
            function(x) return x == 2 end,
        })
        assert(m(1) and m(2))
        assert(not m(3))
    end)

    T:test("composite.allof matches only when all matchers pass", function()
        local m = composite.allof({
            function(x) return x > 0 end,
            function(x) return x < 10 end,
        })
        assert(m(5))
        assert(not m(0) and not m(10))
    end)

    T:test("composite.maybe with key present", function()
        local t = { foo = function(x) return x == 42 end }
        local m = composite.maybe(t, "foo")
        assert(m(42))
        assert(not m(0))
    end)

    T:test("composite.maybe with key absent returns false", function()
        local m = composite.maybe({}, "foo")
        assert(not m(42))
    end)

    T:test("composite.subchain with key present runs chain", function()
        local action = function(addr) return addr end
        local chain = { { function() return true end, action, "TAG" } }
        local m = composite.subchain({ foo = chain }, "foo")
        local a, tag = m("test:80")
        assert(a == action and tag == "TAG")
    end)

    T:test("composite.subchain with key absent returns nil", function()
        local m = composite.subchain({}, "foo")
        assert(m("test:80") == nil)
    end)

    -- [[ rule actions ]] --

    T:test("rule.direct returns addr unchanged", function()
        local f = rule.direct()
        assert(f("example.com:80") == "example.com:80")
    end)

    T:test("rule.reject returns nil", function()
        local f = rule.reject()
        assert(f("example.com:80") == nil)
    end)

    T:test("rule.redirect full destination", function()
        local f = rule.redirect("10.0.0.1:8080")
        assert(f("example.com:80") == "10.0.0.1:8080")
    end)

    T:test("rule.redirect port-only replaces port", function()
        local f = rule.redirect(":8080")
        local dst = f("example.com:80")
        assert(dst == "example.com:8080",
            string.format("expected 'example.com:8080', got %q", tostring(dst)))
    end)

    T:test("rule.redirect host-only replaces host", function()
        local f = rule.redirect("10.0.0.1:")
        local dst = f("example.com:80")
        assert(dst == "10.0.0.1:80",
            string.format("expected '10.0.0.1:80', got %q", tostring(dst)))
    end)

    T:test("rule.redirect with proxy chain reverses order", function()
        local dst, p2, p1 = rule.redirect("10.0.0.1:8080", "proxy1:1080", "proxy2:1080")("addr:80")
        assert(dst == "10.0.0.1:8080",
            string.format("expected '10.0.0.1:8080', got %q", tostring(dst)))
        assert(p1 == "proxy1:1080",
            string.format("expected 'proxy1:1080', got %q", tostring(p1)))
        assert(p2 == "proxy2:1080",
            string.format("expected 'proxy2:1080', got %q", tostring(p2)))
    end)

    T:test("rule.proxy returns addr with reversed proxy chain", function()
        local dst, p2, p1 = rule.proxy("proxy1:1080", "proxy2:1080")("example.com:80")
        assert(dst == "example.com:80",
            string.format("expected 'example.com:80', got %q", tostring(dst)))
        assert(p1 == "proxy1:1080")
        assert(p2 == "proxy2:1080")
    end)

    T:test("rule.rewrite rewrites addr with pattern", function()
        local f = rule.rewrite("^(.+):%d+$", "%1:443")
        local dst = f("example.com:80")
        assert(dst == "example.com:443",
            string.format("expected 'example.com:443', got %q", tostring(dst)))
    end)

    T:test("rule.maybe with key present applies action", function()
        local action = function(addr) return addr end
        local f = rule.maybe({ foo = action }, "foo")
        assert(f("test:80") == "test:80")
    end)

    T:test("rule.maybe with key absent returns nil", function()
        local f = rule.maybe({}, "foo")
        assert(f("test:80") == nil)
    end)

    -- [[ load balancing ]] --

    T:test("lb.roundrobin cycles through all actions evenly", function()
        local calls = { 0, 0, 0 }
        local f = lb.roundrobin({
            function() calls[1] = calls[1] + 1 end,
            function() calls[2] = calls[2] + 1 end,
            function() calls[3] = calls[3] + 1 end,
        })
        for _ = 1, 6 do f() end
        assert(calls[1] == 2 and calls[2] == 2 and calls[3] == 2,
            string.format("expected {2,2,2}, got {%d,%d,%d}",
                calls[1], calls[2], calls[3]))
    end)

    T:test("lb.iwrr distributes proportionally to weights", function()
        local calls = { 0, 0 }
        local f = lb.iwrr({
            { 2, function() calls[1] = calls[1] + 1 end },
            { 1, function() calls[2] = calls[2] + 1 end },
        }, 3)
        for _ = 1, 3 do f() end
        -- 2:1 weights over 3 calls gives {2, 1}
        assert(calls[1] == 2 and calls[2] == 1,
            string.format("expected {2,1}, got {%d,%d}", calls[1], calls[2]))
    end)

    -- [[ ruleset callbacks (integration) ]] --

    T:test("ruleset.route passthrough when no tables set", function()
        local saved_redirect      = _G.redirect
        local saved_route         = _G.route
        local saved_route_default = _G.route_default
        _G.redirect      = nil
        _G.route         = nil
        _G.route_default = nil
        local dst = libruleset.route("example.com:80")
        _G.redirect      = saved_redirect
        _G.route         = saved_route
        _G.route_default = saved_route_default
        assert(dst == "example.com:80",
            string.format("expected passthrough, got %q", tostring(dst)))
    end)

    T:test("ruleset.route applies redirect table", function()
        local saved_redirect      = _G.redirect
        local saved_route         = _G.route
        local saved_route_default = _G.route_default
        _G.redirect = {
            { match.exact("example.com:80"), rule.redirect("10.0.0.1:8080") },
        }
        _G.route         = nil
        _G.route_default = nil
        local dst = libruleset.route("example.com:80")
        _G.redirect      = saved_redirect
        _G.route         = saved_route
        _G.route_default = saved_route_default
        assert(dst == "10.0.0.1:8080",
            string.format("expected '10.0.0.1:8080', got %q", tostring(dst)))
    end)

    T:test("ruleset.route6 applies redirect6 table", function()
        local saved_redirect6     = _G.redirect6
        local saved_route6        = _G.route6
        local saved_route_default = _G.route_default
        _G.redirect6 = {
            { match.exact("[::1]:80"), rule.redirect("10.0.0.1:8080") },
        }
        _G.route6        = nil
        _G.route_default = nil
        local dst = libruleset.route6("[::1]:80")
        _G.redirect6     = saved_redirect6
        _G.route6        = saved_route6
        _G.route_default = saved_route_default
        assert(dst == "10.0.0.1:8080",
            string.format("expected '10.0.0.1:8080', got %q", tostring(dst)))
    end)

    T:test("ruleset.resolve performs hosts table lookup", function()
        local saved_hosts         = _G.hosts
        local saved_redirect_name = _G.redirect_name
        local saved_route         = _G.route
        local saved_route_default = _G.route_default
        _G.hosts         = { ["myhost"] = "192.168.1.1" }
        _G.redirect_name = nil
        _G.route         = nil
        _G.route_default = nil
        local dst = libruleset.resolve("myhost:80")
        _G.hosts         = saved_hosts
        _G.redirect_name = saved_redirect_name
        _G.route         = saved_route
        _G.route_default = saved_route_default
        assert(dst == "192.168.1.1:80",
            string.format("expected '192.168.1.1:80', got %q", tostring(dst)))
    end)

    T:test("ruleset.resolve applies redirect_name table", function()
        local saved_redirect_name = _G.redirect_name
        local saved_route_default = _G.route_default
        _G.redirect_name = {
            { match.host("blocked.example"), rule.reject() },
        }
        _G.route_default = nil
        local dst = libruleset.resolve("blocked.example:80")
        _G.redirect_name = saved_redirect_name
        _G.route_default = saved_route_default
        assert(dst == nil,
            string.format("expected nil for rejected host, got %q", tostring(dst)))
    end)

    T:test("ruleset.tick advances stat_requests", function()
        local before = stat_requests.len
        libruleset.tick()
        local after = stat_requests.len
        assert(after == math.min(before + 1, stat_requests.cap),
            string.format("tick: expected len to grow, was %d now %d", before, after))
    end)

    T:test("ruleset.stats returns non-empty string", function()
        local s = libruleset.stats(0)
        assert(type(s) == "string" and #s > 0, "expected non-empty stats string")
        -- stats output always includes the recent events header
        assert(s:find("> Recent Events", 1, true),
            string.format("missing events header in stats: %q", s))
    end)

end
