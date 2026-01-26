-- [[ ruleset_simple.lua: simple runnable ruleset example ]] --
_G.libruleset     = require("libruleset")

local front_proxy = rule.proxy("socks4a://front-proxy.lan:1080")

-- 1. Domain-based rules (host:port)
_G.redirect_name  = {
    { match.domain(".local"),              rule.direct() },
    { match.exact("server.lan:22"),        rule.redirect("127.0.0.1:22"), "ssh" },
    { match.exact("server.lan:80"),        rule.redirect("127.0.0.1:80") },
    { match.exact("server.lan:443"),       rule.reject() },
    { match.host("server.lan"),            rule.redirect("127.0.0.1:"),   "localhost" },
    { composite.maybe(_G, "biglist_name"), front_proxy,                   "biglist" },
    -- go to _G.hosts
}

-- 2. Map unmatched hosts
_G.hosts          = {
    ["site1.lan"] = "192.168.1.100",
    -- when matched, go to _G.redirect / _G.redirect6
    -- otherwise, go to _G.route_default
}

-- 3. IP-based rules (ip:port)
_G.redirect       = {
    { match.exact("1.1.1.1:53"), rule.redirect("127.0.0.53:53") },
    { match.exact("1.0.0.1:53"), rule.redirect("127.0.0.53:53") },
    -- go to _G.route
}

_G.redirect6      = {
    { match.port(53), rule.redirect("127.0.0.53:53") },
    -- go to _G.route6
}

-- 4. IP-based routes (for subnet matching)
_G.route          = {
    { inet.subnet("127.0.0.0/8"),     rule.reject() },
    { inet.subnet("169.254.0.0/16"),  rule.reject() },
    { inet.subnet("192.168.0.0/16"),  rule.direct(), "lan" },
    { composite.maybe(_G, "biglist"), front_proxy,   "biglist" },
    -- go to _G.route_default
}

_G.route6         = {
    { inet6.subnet("::1/128"),         rule.reject() },
    { inet6.subnet("fe80::/10"),       rule.reject() },
    { composite.maybe(_G, "biglist6"), front_proxy,  "biglist" },
    -- go to _G.route_default
}

-- 4. Default for unmatched requests
_G.route_default  = { rule.proxy("socks5://user:pass@gateway.lan:1080"), "gateway" }

local function main(...)
    neosocksd.setinterval(60.0)
    return _G.libruleset
end

evlogf("ruleset loaded, interpreter: %s", _VERSION)
return main(...)
