_G.libruleset    = require("libruleset")

-- [[ configurations ]] --

-- 1. ordered redirect rules (matched as string)
-- in {matcher, action, optional log tag}
-- matching stops after a match is found

-- redirect_name: for requests with name string
_G.redirect_name = {
    -- access mDNS sites directly
    { match.domain(".local"),              rule.direct() },
    -- self-assignment
    { match.exact("api.neosocksd.lan:80"), rule.redirect("127.0.1.1:9080") },
    -- admin routes
    { match.host("server.lan"),            rule.redirect("127.0.0.1:"),    "localhost" },
    -- if in _G.hosts, go to _G.route/_G.route6
    -- otherwise, go to _G.route_default
}

-- redirect: for requests with IPv4 address
_G.redirect      = {
    -- redirect TCP DNS to local cache
    { match.exact("1.1.1.1:53"), rule.redirect("127.0.0.53:53") },
    { match.exact("1.0.0.1:53"), rule.redirect("127.0.0.53:53") },
    -- go to _G.route
}

-- redirect6: for requests with IPv6 address
_G.redirect6     = {
    -- go to _G.route6
}

-- 2. unordered hosts map
_G.hosts         = {
    ["server.lan"] = "127.0.0.1",
}

-- 3. ordered routes (matched as address)
_G.route         = {
    { inet.subnet("127.0.0.1/32"),   rule.direct() },
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
_G.route_default = { rule.direct(), "default" }

neosocksd.setinterval(60.0)

logf("ruleset loaded, interpreter: %s", _VERSION)
-- inherit undefined fields from libruleset
return setmetatable({}, {
    __index = function(t, k)
        return _G.libruleset[k]
    end
})
