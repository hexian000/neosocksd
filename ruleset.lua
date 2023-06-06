local ruleset = require("libruleset")

-- [[ configurations ]] --
function _G.is_enabled()
    -- if false, new connections are rejected
    return true
end

-- unordered hosts map
_G.hosts = {
    ["gateway.region1.lan"] = "192.168.32.1",
    ["host123.region1.lan"] = "192.168.32.123",
    ["gateway.region2.lan"] = "192.168.33.1",
    ["host123.region2.lan"] = "192.168.33.123",
    -- self-assignment
    ["neosocksd.lan"] = "127.0.1.1" -- see _G.redirect
}

-- ordered redirect rules
-- in {matcher, action, optional log tag}
_G.redirect_name = {
    -- resolve mDNS names locally
    [1] = {match.domain(".local"), rule.direct(), "local"},
    -- no default action
    [0] = nil
}

_G.redirect = {
    -- redirect API domain
    [1] = {match.exact("127.0.1.1:80"), rule.redirect("127.0.1.1:9080")},
    -- no default action, go to _G.route
    [0] = nil
}

-- _G.redirect6 is not set

-- ordered routes
_G.route = {
    -- reject loopback or link-local
    [1] = {inet.subnet("127.0.0.0/8"), rule.reject()},
    [2] = {inet.subnet("169.254.0.0/16"), rule.reject()},
    -- region1 proxy
    [3] = {inet.subnet("192.168.32.0/24"), rule.proxy("192.168.32.1:1080"), "region1"},
    -- jump to region2 through region1 proxy
    [4] = {inet.subnet("192.168.33.0/24"), rule.proxy("192.168.32.1:1080", "192.168.33.1:1080"), "region2"},
    -- access other lan addresses directly
    [5] = {inet.subnet("192.168.0.0/16"), rule.direct(), "lan"},
    -- no default action, go to _G.route_default
    [0] = nil
}

_G.route6 = {
    -- reject loopback or link-local
    [1] = {inet6.subnet("::1/128"), rule.reject()},
    [2] = {inet6.subnet("fe80::/10"), rule.reject()},
    [3] = {inet6.subnet("::ffff:127.0.0.0/104"), rule.reject()},
    [4] = {inet6.subnet("::ffff:169.254.0.0/112"), rule.reject()},
    -- default action
    [0] = rule.direct()
}

-- this global default applies to any unmatched requests
_G.route_default = rule.proxy("192.168.1.1:1080")

printf("ruleset loaded, interpreter: %s", _VERSION)
return ruleset
