-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ tests/ruleset.lua: main test entry point ]] --
--
-- Usage:
--   neosocksd -c tests/main.lua
--
-- package.path is "?.lua" relative to the working directory (project root).

_G.libruleset = require("libruleset")

local testlib = require("tests.testlib")

pcall(collectgarbage, "generational")

local ruleset      = {}
local API_ENDPOINT = "api.neosocksd.internal:80"
local API_TARGET   = { neosocksd.config().restapi }

-- Require test_rpc early so RPC handlers are registered before the
-- event loop starts processing incoming connections.
local run_rpc_tests = require("tests.test_rpc")

local function run_all(T)
    require("tests.test_libruleset")(T:sub("libruleset"))
    require("tests.test_regex")(T)
    require("tests.test_codec")(T)
    require("tests.test_async")(T)
    require("tests.test_api")(T)
    run_rpc_tests(T, API_TARGET)
    require("tests.test_forward")(T:sub("forward"), API_ENDPOINT)
    require("tests.test_agent")(T:sub("agent"))
end

async(function()
    -- Allow the event loop to start and the API listener to bind before
    -- issuing any RPC calls.
    await.sleep(0.1)

    local T = testlib.new("neosocksd")
    -- Run the suite as a child task and observe its future. An uncaught
    -- error (e.g. a syntax error while loading a test module) is captured
    -- here and reported, instead of silently aborting this fire-and-forget
    -- driver and leaving the event loop running forever (a silent hang).
    local ok, err = async(run_all, T):get()
    if not ok then
        printf("[FATAL] test driver aborted: %s", tostring(err))
    end
    local passed = T:report()
    if ok and passed then
        print("all tests passed")
        os.exit(0)
    end
    print("some tests failed")
    os.exit(1)
end)

-- Ruleset boilerplate required by neosocksd --

_G.redirect_name = {
    { match.exact(API_ENDPOINT), rule.redirect(neosocksd.config().restapi) },
}
_G.route_default = { lb.roundrobin({
    rule.redirect("127.0.0.1:30001"),
    rule.redirect("127.0.0.1:30002"),
}) }

-- failover demo for tests/test_forward.lua: try an unreachable proxy, then
-- fall back to a direct connection to the API endpoint
local FAILOVER_NAME = "failover.test:80"
-- a failed forward followed by a policy rejection (return nil): the rejection
-- must be reported as a ruleset reject, not an upstream failure.
local POLICYREJECT_NAME = "policyreject.test:80"
function ruleset.resolve(addr, username, password)
    if addr == FAILOVER_NAME then
        return libruleset.failover(neosocksd.config().restapi, {
            { "socks5://127.0.0.1:1" }, -- connection refused: this fails
            {},                         -- direct to the API: this succeeds
        })
    end
    if addr == POLICYREJECT_NAME then
        await.forward("127.0.0.1:1") -- refused; sets the forward error
        return nil                   -- policy reject; the error is cleared
    end
    return libruleset.resolve(addr, username, password)
end

local function main(...)
    neosocksd.setinterval(0.0)
    return setmetatable(ruleset, {
        __index = function(_, k)
            return _G.libruleset[k]
        end,
    })
end

logf("ruleset loaded, interpreter: %s", _VERSION)
return main(...)
