-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ test_api.lua: tests for the built-in neosocksd Lua API ]] --

return function(T)
    -- neosocksd.config --

    T:test("neosocksd.config returns table with expected fields", function()
        local cfg = neosocksd.config()
        assert(type(cfg) == "table",
            string.format("expected table, got %s", type(cfg)))
        assert(type(cfg.loglevel) == "number",
            string.format("loglevel: expected number, got %s", type(cfg.loglevel)))
        assert(type(cfg.timeout) == "number",
            string.format("timeout: expected number, got %s", type(cfg.timeout)))
        assert(type(cfg.auth_required) == "boolean",
            string.format("auth_required: expected boolean, got %s", type(cfg.auth_required)))
        assert(type(cfg.listen) == "string",
            string.format("listen: expected string, got %s", type(cfg.listen)))
        assert(type(cfg.api) == "string",
            string.format("api: expected string, got %s", type(cfg.api)))
    end)

    -- neosocksd.splithostport --

    T:test("neosocksd.splithostport splits host:port", function()
        local h, p = neosocksd.splithostport("example.com:80")
        assert(h == "example.com",
            string.format("expected 'example.com', got %q", tostring(h)))
        assert(p == "80",
            string.format("expected '80', got %q", tostring(p)))
    end)

    T:test("neosocksd.splithostport handles IPv6 bracket notation", function()
        local h, p = neosocksd.splithostport("[::1]:443")
        assert(h == "::1",
            string.format("expected '::1', got %q", tostring(h)))
        assert(p == "443",
            string.format("expected '443', got %q", tostring(p)))
    end)

    T:test("neosocksd.splithostport raises on malformed input", function()
        local ok = pcall(neosocksd.splithostport, "no-colon-here")
        assert(not ok, "expected error on malformed input")
    end)

    -- neosocksd.parse_ipv4 --

    T:test("neosocksd.parse_ipv4 parses valid address", function()
        local ip = neosocksd.parse_ipv4("203.0.113.1")
        assert(type(ip) == "number",
            string.format("expected number, got %s", type(ip)))
        assert(ip == 0xCB007101,
            string.format("expected 0xCB007101, got 0x%X", ip))
    end)

    T:test("neosocksd.parse_ipv4 returns nil for invalid input", function()
        assert(neosocksd.parse_ipv4("not-an-ip") == nil,
            "expected nil for non-IP string")
        assert(neosocksd.parse_ipv4("256.0.0.1") == nil,
            "expected nil for out-of-range octet")
    end)

    T:test("neosocksd.parse_ipv4 subnet mask check", function()
        local subnet = neosocksd.parse_ipv4("169.254.0.0")
        local mask = 0xFFFF0000 -- /16
        local ip_in = neosocksd.parse_ipv4("169.254.1.1")
        assert(ip_in ~= nil, "169.254.1.1 should parse")
        assert((ip_in & mask) == subnet,
            "169.254.1.1 should be in 169.254.0.0/16")
        local ip_out = neosocksd.parse_ipv4("10.0.0.1")
        assert(ip_out ~= nil, "10.0.0.1 should parse")
        assert((ip_out & mask) ~= subnet,
            "10.0.0.1 should not be in 169.254.0.0/16")
    end)

    -- neosocksd.parse_ipv6 --

    T:test("neosocksd.parse_ipv6 parses loopback ::1", function()
        local hi, lo = neosocksd.parse_ipv6("::1")
        assert(type(hi) == "number" and type(lo) == "number",
            "expected two numbers")
        assert(hi == 0 and lo == 1,
            string.format("expected (0, 1), got (%d, %d)", hi, lo))
    end)

    T:test("neosocksd.parse_ipv6 returns nil for invalid input", function()
        local v = neosocksd.parse_ipv6("not-an-ipv6")
        assert(v == nil, "expected nil for invalid IPv6 string")
    end)

    T:test("neosocksd.parse_ipv6 fe80::/10 subnet check", function()
        local subnet1, _ = neosocksd.parse_ipv6("FE80::")
        local mask1 = ~((1 << 54) - 1) -- /10 covers top 10 bits of high qword
        local ip1, _ = neosocksd.parse_ipv6("fe80::1")
        assert(ip1 ~= nil, "expected fe80::1 to parse successfully")
        assert((ip1 & mask1) == (subnet1 & mask1),
            "fe80::1 should be in fe80::/10")
        local ip2, _ = neosocksd.parse_ipv6("2001:db8::1")
        assert(ip2 ~= nil, "expected 2001:db8::1 to parse successfully")
        assert((ip2 & mask1) ~= (subnet1 & mask1),
            "2001:db8::1 should not be in fe80::/10")
    end)

    -- neosocksd.now --

    T:test("neosocksd.now returns a positive number", function()
        local t = neosocksd.now()
        assert(type(t) == "number" and t > 0,
            string.format("expected positive number, got %s", tostring(t)))
    end)

    T:test("neosocksd.now is non-decreasing within the same callback", function()
        local t1 = neosocksd.now()
        local t2 = neosocksd.now()
        assert(t2 >= t1,
            string.format("now() decreased: %.9f -> %.9f", t1, t2))
    end)

    -- neosocksd.stats --

    T:test("neosocksd.stats returns table with numeric fields", function()
        local s = neosocksd.stats()
        assert(type(s) == "table", "expected table")
        local numeric_fields = {
            "num_halfopen", "num_sessions", "num_sessions_peak",
            "num_request", "num_success",
            "num_reject_ruleset", "num_reject_timeout", "num_reject_upstream",
            "byt_up", "byt_down", "uptime",
            "bytes_allocated", "num_object",
            "num_accept", "num_serve",
            "num_dns_query", "num_dns_success",
        }
        for _, k in ipairs(numeric_fields) do
            local v = s[k]
            assert(type(v) == "number",
                string.format("stats.%s: expected number, got %s", k, type(v)))
        end
    end)

    -- neosocksd.traceback --

    T:test("neosocksd.traceback works as xpcall message handler", function()
        local function boom() error("TEST_TRACEBACK") end
        local ok, msg = xpcall(boom, neosocksd.traceback)
        assert(not ok, "expected xpcall to return false")
        assert(type(msg) == "string",
            string.format("expected string message, got %s", type(msg)))
        assert(msg:find("TEST_TRACEBACK"),
            string.format("message missing expected text: %q", msg))
    end)

    -- neosocksd.setinterval --

    T:test("neosocksd.setinterval accepts the valid range", function()
        neosocksd.setinterval(1e-3)  -- minimum
        neosocksd.setinterval(1e+9)  -- maximum
        neosocksd.setinterval(0)     -- stop timer
        neosocksd.setinterval(60.0)  -- restore to test default
    end)

    -- time.* --

    T:test("time.monotonic returns a positive non-decreasing value", function()
        local t1 = time.monotonic()
        local t2 = time.monotonic()
        assert(type(t1) == "number" and t1 > 0,
            string.format("expected positive monotonic time, got %s", tostring(t1)))
        assert(t2 >= t1,
            string.format("monotonic clock decreased: %.9f -> %.9f", t1, t2))
    end)

    T:test("time.process returns a non-negative number", function()
        local t = time.process()
        assert(type(t) == "number" and t >= 0,
            string.format("expected non-negative number, got %s", tostring(t)))
    end)

    T:test("time.thread returns a non-negative number", function()
        local t = time.thread()
        assert(type(t) == "number" and t >= 0,
            string.format("expected non-negative number, got %s", tostring(t)))
    end)

    T:test("time.unix is close to os.time()", function()
        local tu = time.unix()
        local to = os.time()
        assert(type(tu) == "number",
            string.format("expected number, got %s", type(tu)))
        assert(math.abs(tu - to) < 5,
            string.format("time.unix (%.3f) far from os.time (%d)", tu, to))
    end)

    T:test("time.measure returns elapsed time and pass-through results", function()
        local elapsed, r1, r2 = time.measure(function() return "hello", 99 end)
        -- Allow a small negative epsilon for clock resolution artefacts
        assert(type(elapsed) == "number" and elapsed > -1e-6,
            string.format("expected non-negative elapsed, got %s", tostring(elapsed)))
        assert(r1 == "hello",
            string.format("expected 'hello', got %q", tostring(r1)))
        assert(r2 == 99,
            string.format("expected 99, got %s", tostring(r2)))
    end)

    T:test("time.measure elapsed is consistent with time.monotonic", function()
        -- time.measure of a no-op must cost less than 1 second
        local elapsed = time.measure(function() end)
        assert(elapsed < 1.0,
            string.format("time.measure overhead unexpectedly large: %.3fs", elapsed))
    end)

    -- await.resolve --

    T:atest("await.resolve accepts an IP literal", function()
        local addr = await.resolve("127.0.0.1")
        assert(addr ~= nil,
            "expected non-nil result for IP literal '127.0.0.1'")
        assert(type(addr) == "string",
            string.format("expected string, got %s", type(addr)))
    end)

    T:atest("await.resolve returns nil or string for a hostname", function()
        local addr = await.resolve("localhost")
        assert(addr == nil or type(addr) == "string",
            string.format("expected nil or string, got %s (%s)",
                type(addr), tostring(addr)))
    end)
end
