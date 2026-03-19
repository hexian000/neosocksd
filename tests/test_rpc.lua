-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ test_rpc.lua: RPC round-trip tests and throughput benchmarks ]] --
--
-- RPC handlers are registered as a side effect of requiring this module
-- so they are available before the event loop starts processing connections.
-- The module returns a test runner function that accepts (T, api_target).

local rpc_target  -- set by the test runner before any RPC test runs

function rpc.test_relay(...)
    local ok, r1, r2 = await.rpcall(rpc_target, "echo", ...)
    if not ok then
        error("relay rpcall failed: " .. tostring(r1))
    end
    return r1, r2
end

function rpc.test_error()
    error("TEST")
end

function rpc.test_timeout()
    await.sleep(61)
end

return function(T, api_target)
    rpc_target = api_target

    T:atest("rpc echo round-trip", function()
        local ok, ret = await.rpcall(rpc_target, "echo", "ping")
        assert(ok, "rpcall failed: " .. tostring(ret))
        assert(ret == "ping",
            string.format("expected %q, got %q", "ping", tostring(ret)))
    end)

    T:atest("rpc echo preserves multiple return values", function()
        local obj     = { pi = math.pi, list = { 1, 2, 3 } }
        local payload = string.rep(" ", 32)
        local ok, r1, r2 = await.rpcall(rpc_target, "echo", obj, payload)
        assert(ok, "rpcall failed: " .. tostring(r1))
        assert(marshal(r1) == marshal(obj),
            string.format("obj mismatch: %s vs %s", marshal(obj), marshal(r1)))
        assert(r2 == payload, "payload mismatch")
    end)

    T:atest("rpc.test_relay relays through loopback", function()
        local obj     = { ts = 1725292854, svc = { "a:22", "b:80" } }
        local payload = string.rep(" ", 32)
        local ok, r1, r2 = await.rpcall(rpc_target, "test_relay", obj, payload)
        assert(ok, "test_relay failed: " .. tostring(r1))
        assert(marshal(r1) == marshal(obj),
            string.format("obj mismatch: %s vs %s", marshal(obj), marshal(r1)))
        assert(r2 == payload, "payload mismatch")
    end)

    T:atest("rpc.test_error propagates error to caller", function()
        local ok, err = await.rpcall(rpc_target, "test_error")
        assert(not ok, "expected rpcall to fail")
        assert(err and #err > 0,
            string.format("expected non-empty error, got %q", tostring(err)))
    end)

    T:atest("neosocksd.resolve returns address for localhost", function()
        local addr = neosocksd.resolve("localhost")
        assert(type(addr) == "string" and #addr > 0,
            string.format("expected address string, got %q", tostring(addr)))
    end)

    -- Throughput benchmarks: results are printed but do not affect pass/fail.

    T:bench("neosocksd.sendmsg", 200 * 100, function()
        local m, n    = 200, 100
        local msgcount = 0
        function msgh.count()
            msgcount = msgcount + 1
        end
        for _ = 1, m do
            for _ = 1, n do
                neosocksd.sendmsg(rpc_target, "count", "data")
            end
            await.sleep(0)
        end
        assert(msgcount == m * n, string.format(
            "expected %d messages, got %d", m * n, msgcount))
    end)

    T:bench("await.rpcall", 200 * 100, function()
        local m, n    = 200, 100
        local msgcount = 0
        function rpc.count(data)
            msgcount = msgcount + 1
            return data
        end
        local futures = {}
        for i = 1, m do
            futures[i] = async(function()
                for _ = 1, n do
                    local ok, ret = await.rpcall(rpc_target, "count", "data")
                    if not ok then
                        error("rpcall failed: " .. tostring(ret))
                    end
                    assert(ret == "data")
                end
            end)
        end
        for _, f in ipairs(futures) do
            local ok, err = f:get()
            assert(ok, tostring(err))
        end
        assert(msgcount == m * n, string.format(
            "expected %d calls, got %d", m * n, msgcount))
    end)
end
