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

    T:test("rlist:new clamps a longer-than-capacity seed to the newest", function()
        -- Regression: len was stored unclamped, so the wrap arithmetic in
        -- get/next addressed the wrong slot for every index.
        local r = rlist:new(3, { 1, 2, 3, 4 })
        assert(r.len == 3 and r.cap == 3,
            string.format("expected len=3 cap=3, got len=%d cap=%d", r.len, r.cap))
        -- seeding is equivalent to pushing 1..4 in order: 1 is evicted
        assert(r:get(1) == 4 and r:get(2) == 3 and r:get(3) == 2,
            string.format("expected 4,3,2 newest-first, got %s,%s,%s",
                tostring(r:get(1)), tostring(r:get(2)), tostring(r:get(3))))
        assert(r:get(4) == nil, "nothing beyond the capacity is retained")
        -- the evicted slot must be gone, not left dangling past the ring
        assert(rawget(r, 4) == nil, "stale element left beyond the capacity")
        r:push(5)
        assert(r:get(1) == 5 and r:get(2) == 4 and r:get(3) == 3,
            string.format("expected 5,4,3 after push, got %s,%s,%s",
                tostring(r:get(1)), tostring(r:get(2)), tostring(r:get(3))))
    end)

    T:test("rlist:new with an exactly-full seed", function()
        local r = rlist:new(3, { 1, 2, 3 })
        assert(r.len == 3)
        assert(r:get(1) == 3 and r:get(2) == 2 and r:get(3) == 1,
            string.format("expected 3,2,1 newest-first, got %s,%s,%s",
                tostring(r:get(1)), tostring(r:get(2)), tostring(r:get(3))))
        r:push(4)
        assert(r:get(1) == 4 and r:get(3) == 2)
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

    T:test("format_timestamp handles float timestamps (time.unix)", function()
        -- time.unix() returns float seconds with nanosecond precision;
        -- format_timestamp must floor to integer before calling os.date.
        local t = os.time() + 0.123456789
        local s = format_timestamp(t)
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

    T:test("match.exact is case-insensitive", function()
        -- Regression: a request must not dodge an exact-match rule (e.g. a
        -- reject) by varying the hostname's case.
        local m = match.exact("example.com:80")
        assert(m("EXAMPLE.COM:80"))
        assert(m("Example.Com:80"))
        local mt = match.exact({ "example.com:80" })
        assert(mt("EXAMPLE.COM:80"))
    end)

    T:test("match.exact ignores the trailing root dot", function()
        -- Regression: a trailing dot only spells out the implicit root label
        -- (RFC 1034), so "example.com." is the same name as "example.com" --
        -- appending one must not dodge an exact-match rule either. The rule
        -- may spell it out too, so both sides fold.
        for _, rule_addr in ipairs({ "example.com:80", "example.com.:80" }) do
            local m = match.exact(rule_addr)
            local mt = match.exact({ rule_addr })
            for _, addr in ipairs({
                "example.com:80", "example.com.:80",
                "EXAMPLE.COM:80", "EXAMPLE.COM.:80",
            }) do
                assert(m(addr), string.format(
                    "match.exact(%q) must match %q", rule_addr, addr))
                assert(mt(addr), string.format(
                    "match.exact({%q}) must match %q", rule_addr, addr))
            end
            -- folding must not widen the rule
            for _, addr in ipairs({
                "example.com:443", "notexample.com:80", "example.com.org:80",
                "sub.example.com:80", "example.co:80", "example.com..:80",
            }) do
                assert(not m(addr), string.format(
                    "match.exact(%q) must not match %q", rule_addr, addr))
                assert(not mt(addr), string.format(
                    "match.exact({%q}) must not match %q", rule_addr, addr))
            end
        end
    end)

    T:test("match.exact keeps working on IP literals", function()
        -- The port and an IP literal's digits, dots, colons and brackets must
        -- survive the fold untouched.
        local m4 = match.exact({ "192.0.2.1:80" })
        assert(m4("192.0.2.1:80"))
        assert(not m4("192.0.2.10:80"))
        local m6 = match.exact({ "[2001:db8::1]:80" })
        assert(m6("[2001:DB8::1]:80"), "an IPv6 literal folds by case")
        assert(not m6("[2001:db8::2]:80"))
        local m46 = match.exact("[::ffff:192.0.2.1]:80")
        assert(m46("[::ffff:192.0.2.1]:80"),
            "a v4-mapped literal's embedded dots must not be touched")
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

    T:test("match.host is case-insensitive", function()
        local m = match.host("example.com")
        assert(m("EXAMPLE.COM:80"))
        local mt = match.host({ "example.com" })
        assert(mt("EXAMPLE.COM:80"))
    end)

    T:test("match.host ignores the trailing root dot", function()
        -- Regression: "example.com." names the same host as "example.com"
        for _, name in ipairs({ "example.com", "example.com." }) do
            local m = match.host(name)
            local mt = match.host({ name })
            for _, addr in ipairs({
                "example.com:80", "example.com.:443",
                "EXAMPLE.COM:80", "Example.Com.:80",
            }) do
                assert(m(addr), string.format(
                    "match.host(%q) must match %q", name, addr))
                assert(mt(addr), string.format(
                    "match.host({%q}) must match %q", name, addr))
            end
            for _, addr in ipairs({
                "notexample.com:80", "sub.example.com:80", "example.com..:80",
            }) do
                assert(not m(addr), string.format(
                    "match.host(%q) must not match %q", name, addr))
                assert(not mt(addr), string.format(
                    "match.host({%q}) must not match %q", name, addr))
            end
        end
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

    T:test("match.domain is case-insensitive", function()
        -- Regression: e.g. ruleset_ingress.lua/ruleset_egress.lua reject
        -- ".internal"/".lan"/".local" via match.domain; requesting
        -- "foo.INTERNAL" instead of "foo.internal" must not dodge that.
        local m = match.domain("example.com")
        assert(m("EXAMPLE.COM:80"))
        assert(m("sub.EXAMPLE.com:80"))
        local mt = match.domain({ "example.com" })
        assert(mt("EXAMPLE.COM:80"))
        assert(mt("sub.Example.Com:80"))
    end)

    T:test("match.domain ignores the trailing root dot", function()
        -- Regression: rulesets reject ".internal"/".lan"/".local" through
        -- match.domain; "foo.lan." must not walk past such a rule. Both the
        -- single-string form (a suffix compare) and the table form (a domain
        -- tree) fold, and so does the rule's own spelling.
        for _, entry in ipairs({
            "example.com", "example.com.", ".example.com", ".example.com.",
        }) do
            local m = match.domain(entry)
            local mt = match.domain({ entry })
            for _, addr in ipairs({
                "example.com:80", "example.com.:80",
                "sub.example.com:80", "sub.example.com.:80",
                "EXAMPLE.COM.:80", "Sub.Example.Com.:80",
            }) do
                assert(m(addr), string.format(
                    "match.domain(%q) must match %q", entry, addr))
                assert(mt(addr), string.format(
                    "match.domain({%q}) must match %q", entry, addr))
            end
            -- folding must not widen the rule to a neighbouring name
            for _, addr in ipairs({
                "notexample.com:80", "notexample.com.:80",
                "example.com.org:80", "example.co:80", "other.com:80",
            }) do
                assert(not m(addr), string.format(
                    "match.domain(%q) must not match %q", entry, addr))
                assert(not mt(addr), string.format(
                    "match.domain({%q}) must not match %q", entry, addr))
            end
        end
    end)

    T:test("match.domain accepts overlapping entries in either order", function()
        -- Regression: the tree builder wrote a terminal `true` for the
        -- shorter suffix and then descended straight through it, raising
        -- "attempt to index a boolean value" -- a redundant but legitimate
        -- list (concatenated from several sources) aborted ruleset loading.
        for _, entries in ipairs({
            { "example.com", "test.example.com" },
            { "test.example.com", "example.com" },
            { "cn", "com.cn" },
            { "internal", "svc.internal" },
        }) do
            local ok, m = pcall(match.domain, entries)
            assert(ok, string.format("match.domain({%q, %q}) raised: %s",
                entries[1], entries[2], tostring(m)))
            -- the shorter suffix subsumes the longer entry either way
            for _, v in ipairs(entries) do
                assert(m(v .. ":80"), string.format(
                    "%q not matched by {%q, %q}", v, entries[1], entries[2]))
                assert(m("host." .. v .. ":80"), string.format(
                    "sub-domain of %q not matched by {%q, %q}",
                    v, entries[1], entries[2]))
            end
        end
        local m = match.domain({ "example.com", "test.example.com" })
        assert(not m("notexample.com:80"))
        assert(not m("other.com:80"))
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

    T:test("match.domaintree lowercases the queried address", function()
        -- The tree itself is expected to already use lowercase keys (as
        -- match.domain() above always produces); the incoming address is
        -- still normalized so a mixed-case request still matches.
        local tree = { com = { example = true } }
        local m = match.domaintree(tree)
        assert(m("EXAMPLE.COM:80"))
        assert(m("Sub.Example.Com:80"))
    end)

    T:test("match.domaintree ignores the trailing root dot", function()
        -- Splitting into labels already drops the empty root label, so this
        -- matcher tolerated the dot before the fold existed; it must stay
        -- that way, and must not start matching a neighbouring name.
        local tree = { com = { example = true } }
        local m = match.domaintree(tree)
        assert(m("example.com.:80"))
        assert(m("EXAMPLE.COM.:80"))
        assert(m("sub.example.com.:80"))
        assert(not m("notexample.com.:80"))
        assert(not m("example.com.org.:80"))
        assert(not m("example.org.:80"))
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

    T:test("match.regex reports an invalid pattern in a table", function()
        -- Regression: the diagnostic went through logf, which log_ drops
        -- below loglevel 6, so a typo'd pattern in a reject list was
        -- discarded with no output at all and the rule silently failed open.
        local m = match.regex({ "^bad(", "^10\\." })
        local entry = recent_events:get(1)
        assert(entry and entry.msg:find("^bad(", 1, true), string.format(
            "the invalid pattern was not reported, newest event is %q",
            entry and entry.msg or "<none>"))
        -- the remaining patterns still compile and match
        assert(m("10.0.0.1:80"))
        assert(not m("192.168.1.1:80"))
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

    T:test("rule.default calls route_default's action, not the table itself", function()
        local saved_route_default = _G.route_default
        _G.route_default = { rule.direct(), "tag" }
        local ok, dst = pcall(rule.default(), "example.com:80")
        _G.route_default = saved_route_default
        assert(ok, string.format("rule.default() raised: %s", tostring(dst)))
        assert(dst == "example.com:80",
            string.format("expected 'example.com:80', got %q", tostring(dst)))
    end)

    T:test("rule.default falls back to addr when route_default is nil", function()
        local saved_route_default = _G.route_default
        _G.route_default = nil
        local dst = rule.default()("example.com:80")
        _G.route_default = saved_route_default
        assert(dst == "example.com:80",
            string.format("expected 'example.com:80', got %q", tostring(dst)))
    end)

    T:test("rule.redirect keeps per-request values out of its upvalues", function()
        -- Regression: both partial-destination closures assigned
        -- splithostport's result back to the constructor's locals, so every
        -- invocation rewrote state shared by all of them. Nothing between the
        -- assignment and the use can yield, so only the captured value shows
        -- the difference -- read it back directly.
        local function assert_unwritten(f, name, want)
            for i = 1, math.huge do
                local k, v = debug.getupvalue(f, i)
                if not k then return end
                assert(k ~= name or v == want, string.format(
                    "the rule wrote %s=%q back into its upvalue", k, tostring(v)))
            end
        end
        local f = rule.redirect(":8080")
        assert(f("example.com:80") == "example.com:8080")
        assert(f("other.example:443") == "other.example:8080")
        assert_unwritten(f, "host", "")
        local g = rule.redirect("10.0.0.1:")
        assert(g("example.com:80") == "10.0.0.1:80")
        assert(g("other.example:443") == "10.0.0.1:443")
        assert_unwritten(g, "port", "")
    end)

    -- [[ the rule actions that re-enter the decision pipeline ]] --
    --
    -- rule.resolve and rule.loopback dispatch to route_/route6_/resolve_,
    -- which read their tables from _G. withtables installs exactly the given
    -- ones for the duration of the call and restores the previous set
    -- afterwards, so a failing case cannot leak state into its neighbours.
    local DECISION_TABLES = {
        "redirect", "redirect6", "redirect_name",
        "route", "route6", "route_default",
    }

    local function withtables(t, f, ...)
        local saved = {}
        for _, k in ipairs(DECISION_TABLES) do
            saved[k] = _G[k]
            _G[k] = t[k]
        end
        local r = table.pack(pcall(f, ...))
        for _, k in ipairs(DECISION_TABLES) do
            _G[k] = saved[k]
        end
        return table.unpack(r, 1, r.n)
    end

    -- withresolve runs f (always withtables below, which is the one that
    -- protects the call) with await.resolve replaced by a stub answering
    -- `answer`, and additionally returns the hostname the stub was asked for.
    local function withresolve(answer, f, ...)
        local saved, queried = await.resolve, nil
        await.resolve = function(host)
            queried = host
            -- suspend as the real resolver does, so the action is exercised
            -- across an actual yield
            await.sleep(0)
            return answer
        end
        local r = table.pack(f(...))
        await.resolve = saved
        return queried, table.unpack(r, 1, r.n)
    end

    T:atest("rule.resolve resolves the bare host and routes the IPv4 result", function()
        -- Regression: the whole "host:port" was handed to await.resolve, and
        -- the portless IP it answers with was then fed to splithostport,
        -- which raises -- the action never worked on any input.
        local queried, ok, dst = withresolve("192.0.2.1", withtables, {
            redirect = {
                { match.exact("192.0.2.1:80"), rule.redirect("10.0.0.9:8080") },
            },
        }, rule.resolve(), "example.com:80")
        assert(ok, string.format("rule.resolve() raised: %s", tostring(dst)))
        assert(queried == "example.com", string.format(
            "expected the bare hostname to be resolved, got %q", tostring(queried)))
        -- reaching the redirect table proves route_ saw the rejoined address
        assert(dst == "10.0.0.9:8080", string.format(
            "expected '10.0.0.9:8080', got %q", tostring(dst)))
    end)

    T:atest("rule.resolve brackets an IPv6 result before route6", function()
        local queried, ok, dst = withresolve("2001:db8::1", withtables, {
            redirect6 = {
                { match.exact("[2001:db8::1]:80"), rule.redirect("10.0.0.9:8080") },
            },
        }, rule.resolve(), "example.com:80")
        assert(ok, string.format("rule.resolve() raised: %s", tostring(dst)))
        assert(queried == "example.com")
        assert(dst == "10.0.0.9:8080", string.format(
            "expected '10.0.0.9:8080', got %q", tostring(dst)))
    end)

    T:atest("rule.resolve keeps the port and falls through to route_default", function()
        local queried, ok, dst = withresolve("192.0.2.1", withtables, {},
            rule.resolve(), "example.com:8443")
        assert(ok, string.format("rule.resolve() raised: %s", tostring(dst)))
        assert(queried == "example.com")
        assert(dst == "192.0.2.1:8443", string.format(
            "expected '192.0.2.1:8443', got %q", tostring(dst)))
    end)

    T:atest("rule.resolve rejects when resolution fails", function()
        local queried, ok, dst = withresolve(nil, withtables, {},
            rule.resolve(), "example.com:80")
        assert(ok, string.format("rule.resolve() raised: %s", tostring(dst)))
        assert(queried == "example.com")
        assert(dst == nil, string.format(
            "expected nil for an unresolvable host, got %q", tostring(dst)))
    end)

    T:test("rule.loopback re-dispatches an IPv4 rewrite through route_", function()
        local ok, dst = withtables({
            redirect = {
                { match.exact("192.0.2.2:80"), rule.redirect("10.0.0.9:8080") },
            },
        }, rule.loopback("^.+:(%d+)$", "192.0.2.2:%1"), "example.com:80")
        assert(ok, string.format("rule.loopback() raised: %s", tostring(dst)))
        assert(dst == "10.0.0.9:8080", string.format(
            "expected '10.0.0.9:8080', got %q", tostring(dst)))
    end)

    T:test("rule.loopback re-dispatches an IPv6 rewrite through route6_", function()
        local ok, dst = withtables({
            redirect6 = {
                { match.exact("[2001:db8::2]:80"), rule.redirect("10.0.0.9:8080") },
            },
        }, rule.loopback("^.+:(%d+)$", "[2001:db8::2]:%1"), "example.com:80")
        assert(ok, string.format("rule.loopback() raised: %s", tostring(dst)))
        assert(dst == "10.0.0.9:8080", string.format(
            "expected '10.0.0.9:8080', got %q", tostring(dst)))
    end)

    T:test("rule.loopback re-dispatches a name rewrite through resolve_", function()
        local ok, dst = withtables({
            redirect_name = {
                { match.exact("loop.example:80"), rule.redirect("10.0.0.9:8080") },
            },
        }, rule.loopback("^.+:(%d+)$", "loop.example:%1"), "example.com:80")
        assert(ok, string.format("rule.loopback() raised: %s", tostring(dst)))
        assert(dst == "10.0.0.9:8080", string.format(
            "expected '10.0.0.9:8080', got %q", tostring(dst)))
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

    T:test("lb.iwrr leaves the caller's weight table untouched", function()
        -- Regression: normalization divided every weight in place, so the
        -- declared configuration was rewritten (and integers became floats),
        -- rescaling any other instance sharing those entries.
        local a, b = function() end, function() end
        local t = { { 2, a }, { 1, b } }
        lb.iwrr(t, 3)
        assert(t[1][1] == 2 and t[2][1] == 1, string.format(
            "expected the declared weights {2,1}, got {%s,%s}",
            tostring(t[1][1]), tostring(t[2][1])))
        assert(math.type(t[1][1]) == math.type(2), "an integer weight became a float")
        assert(t[1][2] == a and t[2][2] == b, "the actions were replaced")
        -- a second instance over the same entries sees the same ratios
        local calls = { 0, 0 }
        t[1][2] = function() calls[1] = calls[1] + 1 end
        t[2][2] = function() calls[2] = calls[2] + 1 end
        local f = lb.iwrr(t, 3)
        for _ = 1, 3 do f() end
        assert(calls[1] == 2 and calls[2] == 1, string.format(
            "expected {2,1} after a repeated lb.iwrr, got {%d,%d}",
            calls[1], calls[2]))
    end)

    T:test("lb.iwrr with all-zero weights does not hang", function()
        -- Regression: max was computed as 0, dividing every weight into
        -- NaN; the dispatcher's `until r < t[i][1]` then never became
        -- true against NaN, spinning forever on the very first call.
        local f = lb.iwrr({
            { 0, function() return "a" end },
        })
        for _ = 1, 5 do
            assert(f() == nil, "drained-to-zero dispatcher should reject")
        end
    end)

    T:test("lb.iwrr excludes non-positive weights from rotation", function()
        local calls = { 0, 0, 0 }
        local f = lb.iwrr({
            { 1, function() calls[1] = calls[1] + 1 end },
            { 0, function() calls[2] = calls[2] + 1 end },
            { -1, function() calls[3] = calls[3] + 1 end },
        })
        for _ = 1, 20 do f() end
        assert(calls[2] == 0 and calls[3] == 0,
            string.format(
                "non-positive-weight backends must never be called, got {%d,%d}",
                calls[2], calls[3]))
        assert(calls[1] == 20,
            string.format(
                "the sole positive-weight backend should get every call, got %d",
                calls[1]))
    end)

    T:test("lb.iwrr with an empty backend list does not error", function()
        local f = lb.iwrr({})
        assert(f() == nil)
    end)

    -- [[ ruleset callbacks (integration) ]] --

    T:test("ruleset.decide.route passthrough when no tables set", function()
        local saved_redirect      = _G.redirect
        local saved_route         = _G.route
        local saved_route_default = _G.route_default
        _G.redirect      = nil
        _G.route         = nil
        _G.route_default = nil
        local dst = libruleset.decide.route("example.com:80")
        _G.redirect      = saved_redirect
        _G.route         = saved_route
        _G.route_default = saved_route_default
        assert(dst == "example.com:80",
            string.format("expected passthrough, got %q", tostring(dst)))
    end)

    T:test("ruleset.decide.route applies redirect table", function()
        local saved_redirect      = _G.redirect
        local saved_route         = _G.route
        local saved_route_default = _G.route_default
        _G.redirect = {
            { match.exact("example.com:80"), rule.redirect("10.0.0.1:8080") },
        }
        _G.route         = nil
        _G.route_default = nil
        local dst = libruleset.decide.route("example.com:80")
        _G.redirect      = saved_redirect
        _G.route         = saved_route
        _G.route_default = saved_route_default
        assert(dst == "10.0.0.1:8080",
            string.format("expected '10.0.0.1:8080', got %q", tostring(dst)))
    end)

    T:test("ruleset.decide.route6 applies redirect6 table", function()
        local saved_redirect6     = _G.redirect6
        local saved_route6        = _G.route6
        local saved_route_default = _G.route_default
        _G.redirect6 = {
            { match.exact("[::1]:80"), rule.redirect("10.0.0.1:8080") },
        }
        _G.route6        = nil
        _G.route_default = nil
        local dst = libruleset.decide.route6("[::1]:80")
        _G.redirect6     = saved_redirect6
        _G.route6        = saved_route6
        _G.route_default = saved_route_default
        assert(dst == "10.0.0.1:8080",
            string.format("expected '10.0.0.1:8080', got %q", tostring(dst)))
    end)

    T:test("ruleset.decide.resolve performs hosts table lookup", function()
        local saved_hosts         = _G.hosts
        local saved_redirect_name = _G.redirect_name
        local saved_route         = _G.route
        local saved_route_default = _G.route_default
        _G.hosts         = { ["myhost"] = "192.168.1.1" }
        _G.redirect_name = nil
        _G.route         = nil
        _G.route_default = nil
        local dst = libruleset.decide.resolve("myhost:80")
        _G.hosts         = saved_hosts
        _G.redirect_name = saved_redirect_name
        _G.route         = saved_route
        _G.route_default = saved_route_default
        assert(dst == "192.168.1.1:80",
            string.format("expected '192.168.1.1:80', got %q", tostring(dst)))
    end)

    T:test("ruleset.decide.resolve applies redirect_name table", function()
        local saved_redirect_name = _G.redirect_name
        local saved_route_default = _G.route_default
        _G.redirect_name = {
            { match.host("blocked.example"), rule.reject() },
        }
        _G.route_default = nil
        local dst = libruleset.decide.resolve("blocked.example:80")
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

    -- [[ authentication ]] --
    --
    -- libruleset keeps authenticate() file-local and decides the credential
    -- policy from neosocksd.config().auth_required, which the suite boots with
    -- false (tests/boot.lua), so the whole auth branch is unreachable through
    -- the module this suite runs on. These cases load private instances of
    -- libruleset.lua instead, each with a configuration of its own that they
    -- can also change after the instance has loaded -- the way the daemon
    -- applies a `-c' config table only after the chunk that required
    -- libruleset has returned.

    -- Globals a private instance must not share with the running suite: the
    -- routing tables (so a decision is the request address itself), the
    -- credential table and the ruleset hooks, the request counters and the
    -- event rings. They read as absent inside an instance whatever the live _G
    -- holds, and every write an instance makes stays inside the instance.
    local PRIVATE_GLOBALS = {
        ruleset = true, secrets = true, hosts = true,
        redirect_name = true, redirect = true, redirect6 = true,
        route = true, route6 = true, route_default = true,
        num_requests = true, num_authorized = true,
        stat_requests = true, recent_events = true,
    }

    -- newruleset loads a private libruleset instance with the given
    -- auth_required setting and returns the module, its global table, the log
    -- of await.forward() calls (`n` calls, addresses at 1..n), a setter for the
    -- instance's configuration, and the log of print() output (`n` lines at
    -- 1..n). The instance's await.forward only records the decision instead of
    -- dialing, which is what makes the wrapped ruleset callbacks observable
    -- outside a request handler.
    --
    -- setconfig(key, value) changes what the instance's neosocksd.config()
    -- reports from its next call on; it is how a case reproduces a
    -- configuration that only takes effect after the module has loaded.
    -- setconfig(nil, message) instead makes every configuration read raise
    -- `message', standing in for a configuration that cannot be read at all.
    -- Every instance starts below libruleset's debug-logging threshold so that
    -- its captured output is a property of the case, not of the level the suite
    -- happens to run at.
    local function newruleset(auth_required)
        local env, forwarded, printed = {}, { n = 0 }, { n = 0 }
        local overrides = { auth_required = auth_required, loglevel = 4 }
        local config_error
        env._G = env
        env.neosocksd = setmetatable({
            config = function()
                if config_error then error(config_error, 0) end
                local cfg = {}
                for k, v in pairs(neosocksd.config()) do cfg[k] = v end
                for k, v in pairs(overrides) do cfg[k] = v end
                return cfg
            end,
        }, { __index = neosocksd })
        env.await = setmetatable({
            forward = function(addr)
                forwarded.n = forwarded.n + 1
                forwarded[forwarded.n] = addr
                return addr ~= nil
            end,
        }, { __index = await })
        -- libruleset binds print at load time, so the capture has to be in
        -- place before the chunk runs
        env.print = function(line)
            printed.n = printed.n + 1
            printed[printed.n] = line
        end
        setmetatable(env, {
            __index = function(_, k)
                if PRIVATE_GLOBALS[k] then return nil end
                return _G[k]
            end,
        })
        -- loadfile (not require) keeps package.loaded and the live module
        -- untouched; the third argument gives the chunk its own _ENV. An
        -- instance still installs libruleset's string.*/table.get/
        -- package.replace extensions onto the shared standard-library tables,
        -- but with the same definitions the live module already put there.
        local chunk, err = loadfile("libruleset.lua", "t", env)
        assert(chunk, "loadfile libruleset.lua failed: " .. tostring(err))
        local function setconfig(key, value)
            if key == nil then
                config_error = value
                return
            end
            overrides[key] = value
        end
        return chunk("libruleset"), env, forwarded, setconfig, printed
    end

    -- counters formats the per-instance request accounting for a message
    local function counters(env)
        return string.format("requests=%d, authorized=%d",
            env.num_requests, env.num_authorized)
    end

    local AUTH_ADDR = "auth.test:80"

    T:test("with_authenticate skips the credential check when auth is not required", function()
        local mod, env, forwarded = newruleset(false)
        local hooked = false
        env.secrets = { ["alice"] = "s3cr3t" }
        env.ruleset = {
            authenticate = function() hooked = true; return false end,
        }
        assert(mod.resolve(AUTH_ADDR, "mallory", "wrong") == true,
            "an unknown user must be served when auth is not required")
        assert(mod.resolve(AUTH_ADDR) == true,
            "a request without credentials must be served when auth is not required")
        assert(not hooked, "ruleset.authenticate must not run when auth is not required")
        assert(forwarded.n == 2 and forwarded[1] == AUTH_ADDR and forwarded[2] == AUTH_ADDR,
            string.format("expected 2 forwards to %q, got %d", AUTH_ADDR, forwarded.n))
        assert(env.num_requests == 2 and env.num_authorized == 2,
            string.format("every request counts as authorized: %s", counters(env)))
    end)

    T:test("authenticate accepts the configured secret", function()
        local mod, env, forwarded = newruleset(true)
        env.secrets = { ["alice"] = "s3cr3t" }
        assert(mod.resolve(AUTH_ADDR, "alice", "s3cr3t") == true,
            "the configured credentials must be accepted")
        assert(forwarded.n == 1 and forwarded[1] == AUTH_ADDR,
            string.format("expected 1 forward to %q, got %d", AUTH_ADDR, forwarded.n))
        assert(env.num_requests == 1 and env.num_authorized == 1,
            string.format("an accepted request counts as authorized: %s", counters(env)))
    end)

    T:test("authenticate rejects a wrong password", function()
        local mod, env, forwarded = newruleset(true)
        env.secrets = { ["alice"] = "s3cr3t" }
        assert(mod.resolve(AUTH_ADDR, "alice", "s3cr3T") == nil,
            "a wrong password must be rejected")
        assert(forwarded.n == 0,
            "a rejected request must not reach the routing pipeline")
        assert(env.num_requests == 1 and env.num_authorized == 0,
            string.format("a rejected request must not count as authorized: %s",
                counters(env)))
        local last = env.recent_events:get(1)
        assert(last and last.msg == [[authenticate failed: "alice"]],
            string.format("expected the rejection logged, got %q",
                tostring(last and last.msg)))
    end)

    T:test("authenticate rejects an unknown user and absent credentials", function()
        local mod, env, forwarded = newruleset(true)
        env.secrets = { ["alice"] = "s3cr3t" }
        assert(mod.resolve(AUTH_ADDR, "mallory", "s3cr3t") == nil,
            "an unknown username must be rejected")
        -- no credentials at all: SOCKS4 without a user ID, SOCKS5 without the
        -- username/password method, HTTP without Proxy-Authorization
        assert(mod.resolve(AUTH_ADDR) == nil,
            "a request without credentials must be rejected")
        assert(forwarded.n == 0,
            "a rejected request must not reach the routing pipeline")
        assert(env.num_requests == 2 and env.num_authorized == 0,
            string.format("rejected requests must not count as authorized: %s",
                counters(env)))
    end)

    T:test("authenticate treats a `true` secret as a wildcard password", function()
        local mod, env, forwarded = newruleset(true)
        env.secrets = { ["guest"] = true }
        assert(mod.resolve(AUTH_ADDR, "guest", "anything") == true,
            "a wildcard secret must accept any password")
        assert(mod.resolve(AUTH_ADDR, "guest") == true,
            "a wildcard secret must accept a missing password")
        assert(mod.resolve(AUTH_ADDR, "ghost", "anything") == nil,
            "a wildcard secret must not accept a different username")
        assert(forwarded.n == 2,
            string.format("expected 2 forwards, got %d", forwarded.n))
        assert(env.num_requests == 3 and env.num_authorized == 2,
            string.format("expected 3 requests and 2 authorized: %s", counters(env)))
    end)

    T:test("authenticate rejects everything with an empty or absent secrets table", function()
        local mod, env, forwarded = newruleset(true)
        assert(type(env.secrets) == "table" and next(env.secrets) == nil,
            "libruleset must default _G.secrets to an empty table")
        assert(mod.resolve(AUTH_ADDR, "alice", "s3cr3t") == nil,
            "an empty secrets table must reject every request")
        env.secrets = nil
        assert(mod.resolve(AUTH_ADDR, "alice", "s3cr3t") == nil,
            "an absent secrets table must reject every request")
        assert(forwarded.n == 0,
            "a rejected request must not reach the routing pipeline")
        assert(env.num_requests == 2 and env.num_authorized == 0,
            string.format("rejected requests must not count as authorized: %s",
                counters(env)))
    end)

    T:test("authenticate compares credentials byte for byte", function()
        local mod, env, forwarded = newruleset(true)
        local username, password = "us\0er", "p\0ss\255\n"
        env.secrets = { [username] = password }
        assert(mod.resolve(AUTH_ADDR, username, password) == true,
            "an embedded NUL or non-UTF-8 byte must not truncate a secret")
        assert(mod.resolve(AUTH_ADDR, username, "p") == nil,
            "a prefix of the password must not be accepted")
        assert(mod.resolve(AUTH_ADDR, "us", password) == nil,
            "a prefix of the username must not be accepted")
        assert(forwarded.n == 1,
            string.format("expected 1 forward, got %d", forwarded.n))
    end)

    T:test("ruleset.authenticate replaces the secrets table", function()
        local mod, env, forwarded = newruleset(true)
        local seen
        env.secrets = { ["alice"] = "s3cr3t" }
        env.ruleset = {
            authenticate = function(addr, username, password)
                seen = { addr, username, password }
                return username == "bob"
            end,
        }
        assert(mod.resolve(AUTH_ADDR, "alice", "s3cr3t") == nil,
            "the hook decides alone; the secrets table must not be consulted")
        assert(seen[1] == AUTH_ADDR and seen[2] == "alice" and seen[3] == "s3cr3t",
            "the hook must receive the request address and the credentials")
        assert(mod.resolve(AUTH_ADDR, "bob") == true,
            "the hook's acceptance must be honored")
        assert(forwarded.n == 1 and forwarded[1] == AUTH_ADDR,
            string.format("expected 1 forward to %q, got %d", AUTH_ADDR, forwarded.n))
        assert(env.num_requests == 2 and env.num_authorized == 1,
            string.format("expected 2 requests and 1 authorized: %s", counters(env)))
    end)

    T:test("ruleset.route and ruleset.route6 authenticate as well", function()
        local mod, env, forwarded = newruleset(true)
        local addr4, addr6 = "192.0.2.1:80", "[2001:db8::1]:80"
        env.secrets = { ["alice"] = "s3cr3t" }
        assert(mod.route(addr4, "alice", "nope") == nil,
            "ruleset.route must reject a wrong password")
        assert(mod.route6(addr6, "alice", "nope") == nil,
            "ruleset.route6 must reject a wrong password")
        assert(mod.route(addr4, "alice", "s3cr3t") == true,
            "ruleset.route must accept the configured credentials")
        assert(mod.route6(addr6, "alice", "s3cr3t") == true,
            "ruleset.route6 must accept the configured credentials")
        assert(forwarded.n == 2 and forwarded[1] == addr4 and forwarded[2] == addr6,
            string.format("expected the two accepted requests forwarded, got %d",
                forwarded.n))
        assert(env.num_requests == 4 and env.num_authorized == 2,
            string.format("expected 4 requests and 2 authorized: %s", counters(env)))
    end)

    -- [[ configuration applied after the module loads ]] --
    --
    -- A `-c' config chunk returns its configuration table, so nothing in it has
    -- been applied while the chunk itself runs -- including the
    -- `require("libruleset")' that example/config.lua documents. A module that
    -- read the configuration once, at load time, would answer with the
    -- pre-config values for the life of the process.

    T:test("authentication follows an auth_required applied after the load", function()
        local mod, env, forwarded, setconfig = newruleset(false)
        env.secrets = { ["alice"] = "s3cr3t" }
        setconfig("auth_required", true)
        assert(mod.resolve(AUTH_ADDR, "alice", "s3cr3T") == nil,
            "a wrong password must be rejected once the configuration requires authentication")
        assert(mod.route("192.0.2.1:80", "mallory", "s3cr3t") == nil,
            "an unknown user must be rejected once the configuration requires authentication")
        assert(mod.route6("[2001:db8::1]:80") == nil,
            "a request without credentials must be rejected")
        assert(forwarded.n == 0,
            string.format("a rejected request must not reach the routing pipeline, got %d forwards",
                forwarded.n))
        assert(mod.resolve(AUTH_ADDR, "alice", "s3cr3t") == true,
            "the configured credentials must be accepted")
        assert(forwarded.n == 1 and forwarded[1] == AUTH_ADDR,
            string.format("expected the accepted request forwarded to %q, got %d forwards",
                AUTH_ADDR, forwarded.n))
        assert(env.num_requests == 4 and env.num_authorized == 1,
            string.format("expected 4 requests and 1 authorized: %s", counters(env)))
    end)

    T:test("authentication follows an auth_required cleared after the load", function()
        local mod, env, forwarded, setconfig = newruleset(true)
        env.secrets = { ["alice"] = "s3cr3t" }
        assert(mod.resolve(AUTH_ADDR, "mallory", "nope") == nil,
            "an unknown user must be rejected while authentication is required")
        setconfig("auth_required", false)
        assert(mod.resolve(AUTH_ADDR, "mallory", "nope") == true,
            "the credential check must stop once the configuration drops it")
        assert(forwarded.n == 1 and forwarded[1] == AUTH_ADDR,
            string.format("expected 1 forward to %q, got %d", AUTH_ADDR, forwarded.n))
        assert(env.num_requests == 2 and env.num_authorized == 1,
            string.format("expected 2 requests and 1 authorized: %s", counters(env)))
    end)

    T:test("debug logging follows a loglevel applied after the load", function()
        local _, env, _, setconfig, printed = newruleset(false)
        env.logf("below the threshold: %d", 4)
        assert(printed.n == 0,
            string.format("nothing may be logged below level 6, got %q",
                tostring(printed[1])))
        setconfig("loglevel", 6)
        env.logf("above the threshold: %d", 6)
        assert(printed.n == 1 and printed[1]:find("above the threshold: 6", 1, true),
            string.format("expected the message logged at level 6, got %d lines (%q)",
                printed.n, tostring(printed[1])))
    end)

    T:test("a configuration that cannot be read denies the request", function()
        local mod, env, forwarded, setconfig = newruleset(true)
        env.secrets = { ["alice"] = "s3cr3t" }
        setconfig(nil, "config unavailable")
        local ok, err = pcall(mod.resolve, AUTH_ADDR, "alice", "s3cr3t")
        assert(not ok and tostring(err):find("config unavailable", 1, true),
            string.format("an unreadable configuration must raise: ok=%s, err=%q",
                tostring(ok), tostring(err)))
        assert(forwarded.n == 0,
            "an unreadable configuration must not let a request through")
        assert(env.num_authorized == 0,
            string.format("no request may be authorized: %s", counters(env)))
    end)

    T:test("config is a live read-only view of neosocksd.config()", function()
        local _, env, _, setconfig = newruleset(false)
        assert(env.config.auth_required == false,
            "config must report the configuration the instance loaded with")
        setconfig("auth_required", true)
        assert(env.config.auth_required == true,
            "config must read through to the configuration in effect now")
        local fields = 0
        for _, _ in pairs(env.config) do fields = fields + 1 end
        assert(fields > 1,
            string.format("pairs(config) must iterate the configuration fields, got %d",
                fields))
        assert(not pcall(function() env.config.auth_required = false end),
            "config must reject writes instead of shadowing the live value")
        assert(env.config.auth_required == true,
            "a rejected write must leave the live value readable")
    end)

    -- [[ client-supplied addresses ]] --
    --
    -- ruleset.resolve is reached with a SOCKS5 DOMAINNAME (RFC 1928, 5: a
    -- length-prefixed byte string) or an HTTP CONNECT request-target, neither
    -- of which the server validates, with the port appended. A host name holds
    -- letters, digits, hyphens and dots (RFC 1035, 2.3.1; RFC 1123, 2.1) and an
    -- IPv6 literal is only unambiguous in brackets (RFC 3986, 3.2.2), so
    -- anything else forms no "host:port" authority and every site that reads
    -- the address -- a matcher, or resolve_ itself -- raises on it.

    -- Addresses a client can produce that name no reachable host
    local MALFORMED_ADDRS = {
        "a:b:80",               -- a colon in the name
        "2001:db8::7:80",       -- an IPv6 literal sent as a domain name
        "a:b:c:d:e:80",         -- several colons
        "evil.example:9999:80", -- a name carrying a port of its own
        "host::80",             -- a trailing colon
        ":host:80",             -- a leading colon
        ":80",                  -- an empty name
        "[foo]:80",             -- brackets around something not an IPv6 literal
        "[2001:db8::7:80",      -- an unterminated bracket
        "noport",               -- a request-target with no port at all
    }

    T:test("resolve decides a malformed client name instead of raising", function()
        local mod, env, forwarded = newruleset(false)
        local matched, defaulted = 0, 0
        -- a chain that matches nothing, only counts: a malformed address must
        -- not reach a rule, and must not become a match for one either
        env.redirect_name = {
            { function(_) matched = matched + 1 end },
        }
        env.route_default = {
            function(addr) defaulted = defaulted + 1; return addr end,
        }
        for _, addr in ipairs(MALFORMED_ADDRS) do
            local ok, ret = pcall(mod.decide.resolve, addr)
            assert(ok, string.format("decide.resolve(%q) raised: %s",
                addr, tostring(ret)))
            assert(ret == nil, string.format(
                "decide.resolve(%q) must reject, got %q", addr, tostring(ret)))
            -- the whole callback, not just the decision function
            ok, ret = pcall(mod.resolve, addr)
            assert(ok, string.format("resolve(%q) raised: %s",
                addr, tostring(ret)))
            assert(forwarded[forwarded.n] == nil, string.format(
                "resolve(%q) must forward nothing, got %q",
                addr, tostring(forwarded[forwarded.n])))
        end
        assert(matched == 0, string.format(
            "no rule may see a malformed address, got %d", matched))
        assert(defaulted == 0, string.format(
            "a malformed address must not take the default route, got %d",
            defaulted))
    end)

    T:test("resolve routes a well-formed address exactly as before", function()
        local mod, env = newruleset(false)
        env.redirect_name = {
            { match.host("blocked.example"), rule.reject() },
        }
        env.hosts        = { ["mapped.example"] = "192.0.2.9" }
        env.redirect     = {
            { match.exact("192.0.2.9:80"), rule.redirect("127.0.0.1:8080") },
        }
        env.route        = {
            { inet.subnet("192.0.2.0/24"), rule.direct() },
        }
        env.route6       = {
            { inet6.subnet("2001:db8::/32"), rule.reject() },
        }
        env.route_default = { rule.direct() }
        local cases = {
            -- a name no rule claims falls through to the default route
            { "plain.example:80",   "plain.example:80" },
            -- a name a rule rejects is still rejected
            { "blocked.example:80", nil },
            -- _G.hosts maps a name into the address-based tables
            { "mapped.example:80",  "127.0.0.1:8080" },
            -- an IPv4 literal sent as a domain name still reaches _G.route
            { "192.0.2.7:80",       "192.0.2.7:80" },
            -- a bracketed IPv6 literal is a valid authority: _G.route6 decides
            { "[2001:db8::7]:80",   nil },
            -- ... and an address outside it still takes the default route
            { "[2001:db9::7]:80",   "[2001:db9::7]:80" },
        }
        for _, case in ipairs(cases) do
            local addr, expect = case[1], case[2]
            local ok, ret = pcall(mod.decide.resolve, addr)
            assert(ok, string.format("decide.resolve(%q) raised: %s",
                addr, tostring(ret)))
            assert(ret == expect, string.format(
                "decide.resolve(%q): expected %q, got %q",
                addr, tostring(expect), tostring(ret)))
        end
    end)

    T:test("a client-supplied address cannot inject a log line", function()
        local mod, env, _, setconfig, printed = newruleset(false)
        setconfig("loglevel", 6)
        env.redirect_name = {
            { match.any(), rule.direct(), "tagged" },
        }
        -- a newline is as legal in a DOMAINNAME as any other byte, and
        -- string.format("%q") spells it as a backslash and a real newline
        local FORGED = "\nE 1970-01-01T00-00-00+0000 forged.c-1 forged line"
        local tagged = "evil.example" .. FORGED .. ":80"
        assert(mod.decide.resolve(tagged) == tagged,
            "a name that forms an address is still routed")
        assert(printed.n == 1 and not printed[1]:find("\n", 1, true),
            string.format("a tagged rule must log one line, got %d: %q",
                printed.n, tostring(printed[1])))
        env.redirect_name = nil
        local rejected = "a:b" .. FORGED .. ":80"
        assert(mod.decide.resolve(rejected) == nil,
            "a name that forms no address is rejected")
        assert(printed.n == 2 and not printed[2]:find("\n", 1, true),
            string.format("a rejection must log one line, got %d: %q",
                printed.n, tostring(printed[2])))
        -- the rejection is a routine event, recorded like any other decision
        local entry = env.recent_events:get(1)
        assert(entry and entry.msg:find("invalid address", 1, true),
            string.format("expected the rejection recorded, got %q",
                tostring(entry and entry.msg)))
    end)

    -- [[ host-name folding on the decision path ]] --
    --
    -- resolve_() is where a folded name meets _G.hosts and the route tables,
    -- and all of those are private-instance globals, so these cases drive the
    -- real decision function through an instance of its own.

    -- newhosts builds an instance whose _G.hosts maps names to IP literals and
    -- whose route tables redirect those literals to a recognizable address.
    -- Anything the pipeline does not map falls through to route_default, which
    -- an instance never has, so the decision is then the address itself.
    local function newhosts()
        local mod, env = newruleset(false)
        env.hosts = {
            ["mapped.lan"] = "192.0.2.7",
            ["mapped6.lan"] = "2001:db8::7",
        }
        env.route = {
            { inet.subnet("192.0.2.0/24"), rule.redirect("10.0.0.4:8080") },
        }
        env.route6 = {
            { inet6.subnet("2001:db8::/64"), rule.redirect("10.0.0.6:8080") },
        }
        return mod, env
    end

    T:test("resolve_ looks up _G.hosts by the folded name", function()
        -- Regression: the lookup lowercased the name but kept a trailing root
        -- dot, so "mapped.lan." missed its _G.hosts entry and escaped to
        -- route_default instead of the mapped route.
        local mod = newhosts()
        for _, addr in ipairs({
            "mapped.lan:80", "mapped.lan.:80",
            "MAPPED.LAN:80", "MAPPED.LAN.:80",
        }) do
            local dst = mod.decide.resolve(addr)
            assert(dst == "10.0.0.4:8080", string.format(
                "%q must take the mapped route, got %q", addr, tostring(dst)))
        end
        -- an unmapped name still falls through, and keeps the spelling the
        -- client sent: a trailing dot also tells the resolver not to apply
        -- its search list
        for _, addr in ipairs({
            "unmapped.lan:80", "unmapped.lan.:80", "mapped.lan.org:80",
        }) do
            local dst = mod.decide.resolve(addr)
            assert(dst == addr, string.format(
                "%q must fall through unchanged, got %q", addr, tostring(dst)))
        end
    end)

    T:test("resolve_ routes an IP literal spelled with the root dot", function()
        -- Regression: parse_ipv4() rejected "192.0.2.7.", so a rooted literal
        -- skipped _G.route -- where the reject rules live -- and reached
        -- route_default. Folding it makes it parse, and route_ splits the
        -- address again, so it must be handed the folded spelling as well.
        local mod = newhosts()
        for _, addr in ipairs({ "192.0.2.7:80", "192.0.2.7.:80" }) do
            local dst = mod.decide.resolve(addr)
            assert(dst == "10.0.0.4:8080", string.format(
                "%q must take the IPv4 route, got %q", addr, tostring(dst)))
        end
        -- an address that is not a literal at all is still a name
        local dst = mod.decide.resolve("192.0.2.7.9:80")
        assert(dst == "192.0.2.7.9:80", string.format(
            "a non-literal must fall through unchanged, got %q", tostring(dst)))
    end)

    T:test("resolve_ brackets an IPv6 host mapping before route6_", function()
        -- Regression: the mapped address was rejoined as "2001:db8::7:80",
        -- which splithostport rejects as an unbracketed multi-colon host, so
        -- route6_ raised instead of routing.
        local mod = newhosts()
        for _, addr in ipairs({ "mapped6.lan:80", "MAPPED6.LAN.:80" }) do
            local ok, dst = pcall(mod.decide.resolve, addr)
            assert(ok, string.format("%q raised: %s", addr, tostring(dst)))
            assert(dst == "10.0.0.6:8080", string.format(
                "%q must take the IPv6 route, got %q", addr, tostring(dst)))
        end
    end)

    T:test("the fold is ASCII-only, not string.lower's locale fold", function()
        -- RFC 4343 defines name comparison as ASCII-only, but string.lower()
        -- folds through tolower(3), which follows the process locale (init()
        -- calls setlocale(LC_ALL, "")). In a Turkish locale "I" does not fold
        -- to "i" but to the dotless variant, so a matcher built on
        -- string.lower() stops recognizing the very spellings it exists to
        -- catch, and a mapping outside 0-255 truncates to a different byte
        -- instead. No such locale is installed here (only C, C.utf8 and
        -- POSIX, whose tolower is ASCII-only), so it is modelled: a private
        -- instance is handed a string.lower() that folds the Turkish way, and
        -- the matchers must come out unaffected by it.
        local mod, env = newruleset(false)
        env.hosts = { ["host.internal"] = "192.0.2.7" }
        env.route = {
            { inet.subnet("192.0.2.0/24"), rule.redirect("10.0.0.4:8080") },
        }
        env.string = setmetatable({
            lower = function(str)
                return (str:gsub("I", "\xfd"):lower())
            end,
        }, { __index = string })
        local matchers = {
            ["match.exact"] = env.match.exact("host.internal:80"),
            ["match.exact table"] = env.match.exact({ "host.internal:80" }),
            ["match.host"] = env.match.host("host.internal"),
            ["match.host table"] = env.match.host({ "host.internal" }),
            ["match.domain"] = env.match.domain("host.internal"),
            ["match.domain table"] = env.match.domain({ "host.internal" }),
            ["match.domaintree"] = env.match.domaintree(
                { internal = { host = true } }),
        }
        for name, m in pairs(matchers) do
            assert(m("HOST.INTERNAL:80"), string.format(
                "%s must fold 'I' whatever tolower(3) does", name))
            assert(m("Host.Internal.:80"), string.format(
                "%s must fold case and root dot together", name))
            assert(not m("host.external:80"), string.format(
                "%s must not match a different name", name))
        end
        local dst = mod.decide.resolve("HOST.INTERNAL.:80")
        assert(dst == "10.0.0.4:8080", string.format(
            "the _G.hosts lookup must fold ASCII-only, got %q", tostring(dst)))
    end)

    -- [[ rule chain throughput benchmarks ]] --
    -- Deferred by the framework: run only when selected by TESTING_BENCH
    -- (e.g. TESTING_BENCH=. runs every bench).
    -- Each chain is sized so the matching rule sits last, so every decision
    -- walks the whole chain (worst case) and the cost reflects per-rule
    -- traversal of runchain_ rather than an early hit.

    local BENCH_ITERS = 100000
    local CHAIN_LEN   = 16

    -- redirect chain: string-address matchers (each rule calls splithostport)
    T:bench("decide.route redirect chain", BENCH_ITERS, function()
        local saved_redirect      = _G.redirect
        local saved_route         = _G.route
        local saved_route_default = _G.route_default
        local chain = {}
        for i = 1, CHAIN_LEN - 1 do
            chain[i] = { match.host(string.format("noexist%d.example", i)), rule.reject() }
        end
        chain[CHAIN_LEN] = { match.exact("example.com:80"), rule.redirect("10.0.0.1:8080") }
        _G.redirect      = chain
        _G.route         = nil
        _G.route_default = nil
        for _ = 1, BENCH_ITERS do
            libruleset.decide.route("example.com:80")
        end
        _G.redirect      = saved_redirect
        _G.route         = saved_route
        _G.route_default = saved_route_default
    end)

    -- route chain: IPv4 subnet matchers over a parsed address
    T:bench("decide.route subnet chain", BENCH_ITERS, function()
        local saved_redirect      = _G.redirect
        local saved_route         = _G.route
        local saved_route_default = _G.route_default
        local chain = {}
        for i = 1, CHAIN_LEN - 1 do
            chain[i] = { inet.subnet(string.format("10.%d.0.0/16", i)), rule.direct() }
        end
        chain[CHAIN_LEN] = { inet.subnet("192.168.0.0/16"), rule.direct() }
        _G.redirect      = nil
        _G.route         = chain
        _G.route_default = nil
        for _ = 1, BENCH_ITERS do
            libruleset.decide.route("192.168.1.1:80")
        end
        _G.redirect      = saved_redirect
        _G.route         = saved_route
        _G.route_default = saved_route_default
    end)

    -- resolve chain: domain matchers, the common name-based routing path
    T:bench("decide.resolve domain chain", BENCH_ITERS, function()
        local saved_redirect_name = _G.redirect_name
        local saved_route_default = _G.route_default
        local chain = {}
        for i = 1, CHAIN_LEN - 1 do
            chain[i] = { match.domain(string.format("noexist%d.example", i)), rule.reject() }
        end
        chain[CHAIN_LEN] = { match.domain("example.com"), rule.direct() }
        _G.redirect_name = chain
        _G.route_default = nil
        for _ = 1, BENCH_ITERS do
            libruleset.decide.resolve("host.example.com:80")
        end
        _G.redirect_name = saved_redirect_name
        _G.route_default = saved_route_default
    end)

end
