local ruleset = require("simple_ruleset")

-- [[ configurations ]] --
-- global schedule
function _G.is_enabled()
    return true
end

-- unordered hosts map
_G.hosts = {
    ["neosocksd.lan"] = "127.0.1.1",
    ["gateway.region1.lan"] = "192.168.32.1",
    ["host123.region1.lan"] = "192.168.32.123",
    ["gateway.region2.lan"] = "192.168.33.1",
    ["host123.region2.lan"] = "192.168.33.123"
}

-- ordered redirect rules
_G.redirect = {
    -- redirect API domain
    [1] = {"^127%.0%.1%.1:80$", {"127.0.1.1:9080"}},
    [2] = {"^127%.0%.1%.1:", {nil}},
    -- reject loopback or link-local
    [3] = {"^127%.", {nil}},
    [4] = {"^169%.254%.", {nil}}
}

-- ordered routes
_G.route = {
    -- region1 gateway
    [1] = {"^192%.168%.32%.", {"192.168.32.1:1080"}},
    -- jump to region2 via region1 gateway
    [2] = {"^192%.168%.33%.", {"192.168.33.1:1080", "192.168.32.1:1080"}},
    -- access other lan addresses directly
    [3] = {"^192%.168%.", {}}
}
-- default gateway
_G.route_default = {"192.168.1.1:1080"}

printf("ruleset loaded, interpreter: %s", _VERSION)
return ruleset
