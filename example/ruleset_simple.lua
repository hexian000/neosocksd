-- [[ ruleset_simple.lua: simple rule table example ]] --
_G.libruleset    = require("libruleset")

-- [[ configurations ]] --

-- 1. _G.redirect*: match the full request "host:port"
-- in {matcher, action, optional log tag}
-- matching stops after a match is found

-- _G.redirect_name: for requests with name string
_G.redirect_name = {
    -- access mDNS sites directly
    { match.domain(".local"),        rule.direct() },
    -- loopback
    { match.exact("server.lan:22"),  rule.redirect("127.0.0.1:22"), "ssh" },
    { match.exact("server.lan:80"),  rule.redirect("127.0.0.1:80"), "web" },
    { match.exact("server.lan:443"), rule.reject(),                 "web" },
    -- self assignment
    { match.host("server.lan"),      rule.redirect("127.0.0.1:"),   "localhost" },
    -- if in _G.hosts, go to _G.route/_G.route6
    -- otherwise, go to _G.route_default
}

-- _G.redirect: for requests with IPv4 address
_G.redirect      = {
    -- redirect TCP DNS to local cache
    { match.exact("1.1.1.1:53"), rule.redirect("127.0.0.53:53") },
    { match.exact("1.0.0.1:53"), rule.redirect("127.0.0.53:53") },
    -- go to _G.route
}

-- _G.redirect6: for requests with IPv6 address
_G.redirect6     = {
    -- go to _G.route6
}

-- 2. _G.hosts: map unmatched hosts
_G.hosts         = {
    ["site1.lan"] = "192.168.1.100",
}

-- 3. _G.route*: match the IP address
_G.route         = {
    -- reject loopback or link-local
    { inet.subnet("127.0.0.0/8"),    rule.reject() },
    { inet.subnet("169.254.0.0/16"), rule.reject() },
    -- access lan addresses directly
    { inet.subnet("192.168.0.0/16"), rule.direct(), "lan" },
    -- go to _G.route_default
}

_G.route6        = {
    -- reject loopback or link-local
    { inet6.subnet("::1/128"),                rule.reject() },
    { inet6.subnet("fe80::/10"),              rule.reject() },
    { inet6.subnet("::ffff:127.0.0.0/104"),   rule.reject() },
    { inet6.subnet("::ffff:169.254.0.0/112"), rule.reject() },
    -- go to _G.route_default
}

-- 4. the global default applies to any unmatched requests
-- in {action, optional log tag}
_G.route_default = { rule.proxy("socks5://user:pass@internet-gateway.lan:1080"), "internet" }

local function main(...)
    pcall(collectgarbage, "generational")
    neosocksd.setinterval(60.0)
    return _G.libruleset
end

evlogf("ruleset loaded, interpreter: %s", _VERSION)
return main(...)