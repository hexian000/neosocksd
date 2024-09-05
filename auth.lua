_G.libruleset = require("libruleset")

_G.secrets = {
    ["lamer"] = "secret",
}

local RESERVED_DOMAIN = ".neosocksd.internal"

_G.redirect_name = {
    { match.host("localhost"),       rule.reject() },
    { match.domain("localdomain"),   rule.reject() },
    { match.domain(RESERVED_DOMAIN), rule.reject() },
}

_G.route = {
    { inet.subnet("127.0.0.0/8"),    rule.reject() },
    { inet.subnet("169.254.0.0/16"), rule.reject() },
}

_G.route6 = {
    { inet6.subnet("::1/128"),                rule.reject() },
    { inet6.subnet("fe80::/10"),              rule.reject() },
    { inet6.subnet("::ffff:127.0.0.0/104"),   rule.reject() },
    { inet6.subnet("::ffff:169.254.0.0/112"), rule.reject() },
}

_G.route_default = { rule.proxy("socks4a://127.0.1.1:1081") }

local function main(...)
    pcall(collectgarbage, "generational")
    neosocksd.setinterval(60.0)
    return _G.libruleset
end

logf("ruleset loaded, interpreter: %s", _VERSION)
return main(...)
