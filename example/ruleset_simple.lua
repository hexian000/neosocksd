-- [[ ruleset_simple.lua: simple rule table example ]] --
_G.libruleset    = require("libruleset")

-- [[ configurations ]] --

-- 1. _G.redirect*: handle requests as a string
-- in {matcher, action, optional log tag}
-- matching stops after a match is found

-- _G.redirect_name: handle domain name requests in "host:port"
_G.redirect_name = {
    -- access mDNS sites directly
    { match.domain(".local"),              rule.direct() },
    -- loopback
    { match.exact("server.lan:22"),        rule.redirect("127.0.0.1:22"),          "ssh" },
    { match.exact("server.lan:80"),        rule.redirect("127.0.0.1:80"),          "web" },
    { match.exact("server.lan:443"),       rule.reject(),                          "web" },
    -- self assignment
    { match.host("server.lan"),            rule.redirect("127.0.0.1:"),            "localhost" },
    -- dynamically loaded big domains list
    { composite.maybe(_G, "biglist_name"), rule.proxy("socks4a://proxy.lan:1080"), "biglist" },
    -- if in _G.hosts, go to _G.route/_G.route6
    -- otherwise, go to _G.route_default
}

-- _G.redirect: handle IPv4 requests in "ip:port"
_G.redirect      = {
    -- redirect TCP DNS to local cache
    { match.exact("1.1.1.1:53"), rule.redirect("127.0.0.53:53") },
    { match.exact("1.0.0.1:53"), rule.redirect("127.0.0.53:53") },
    -- go to _G.route
}

-- _G.redirect6: handle IPv6 requests in "[ipv6]:port"
_G.redirect6     = {
    -- redirect TCP DNS to local cache
    { match.exact("[2606:4700:4700::1111]:53"), rule.redirect("127.0.0.53:53") },
    { match.exact("[2606:4700:4700::1001]:53"), rule.redirect("127.0.0.53:53") },
    -- go to _G.route6
}

-- 2. _G.hosts: map unmatched hosts
_G.hosts         = {
    ["site1.lan"] = "192.168.1.100",
}

-- 3. _G.route*: handle requests by IP address (faster subnet matching)
_G.route         = {
    -- reject loopback or link-local
    { inet.subnet("127.0.0.0/8"),     rule.reject() },
    { inet.subnet("169.254.0.0/16"),  rule.reject() },
    -- access lan addresses directly
    { inet.subnet("192.168.0.0/16"),  rule.direct(), "lan" },
    -- dynamically loaded big IP ranges list
    { composite.maybe(_G, "biglist"), rule.direct(), "biglist" },
    -- go to _G.route_default
}

_G.route6        = {
    -- reject loopback or link-local
    { inet6.subnet("::1/128"),                rule.reject() },
    { inet6.subnet("fe80::/10"),              rule.reject() },
    { inet6.subnet("::ffff:127.0.0.0/104"),   rule.reject() },
    { inet6.subnet("::ffff:169.254.0.0/112"), rule.reject() },
    -- dynamically loaded big IP ranges list
    { composite.maybe(_G, "biglist6"),        rule.direct(), "biglist" },
    -- go to _G.route_default
}

-- 4. the global default applies to all unmatched requests
-- in {action, optional log tag}
_G.route_default = { rule.proxy("socks5://user:pass@gateway.lan:1080"), "wan" }

local function main(...)
    pcall(collectgarbage, "generational")
    neosocksd.setinterval(60.0)
    return _G.libruleset
end

evlogf("ruleset loaded, interpreter: %s", _VERSION)
return main(...)
