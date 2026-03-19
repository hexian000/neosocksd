-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ tests/main.lua: main test entry point ]] --
--
-- Usage:
--   neosocksd -l 127.0.1.1:31080 --api 127.0.1.1:39080 -r tests/main.lua --traceback
--
-- package.path is "?.lua" relative to the working directory (project root).

_G.libruleset = require("libruleset")

local testlib = require("tests.testlib")

pcall(collectgarbage, "generational")

local ruleset      = {}
local API_ENDPOINT = "api.neosocksd.internal:80"
local API_TARGET   = { neosocksd.config().api }

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
end

async(function()
    -- Allow the event loop to start and the API listener to bind before
    -- issuing any RPC calls.
    await.sleep(0.1)

    local T = testlib.new("neosocksd")
    run_all(T)
    local ok = T:report()
    if ok then
        print("all tests passed")
    else
        print("some tests failed")
    end
    os.exit(ok and 0 or 1)
end)

-- Ruleset boilerplate required by neosocksd --

_G.redirect_name = {
    { match.exact(API_ENDPOINT), rule.redirect(neosocksd.config().api) },
}
_G.route_default = { lb.roundrobin({
    rule.redirect("127.0.0.1:30001"),
    rule.redirect("127.0.0.1:30002"),
}) }

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
