_G.libruleset = require("libruleset")
_G.agent = require("agent")

agent.peername = "peer0"

agent.conns = {
    { "socks4a://127.0.32.1:1080" },
    { "socks4a://127.0.32.1:1080", "socks4a://127.0.32.2:1080" },
    { "socks4a://127.0.33.1:1080" },
}

agent.services = {
    ["serv.internal:80"] = "192.168.1.1:8080",
}

-- [[ configurations ]] --
local ruleset = {}

ruleset.enable_until = nil
local function is_disabled()
    local now = os.time()
    if ruleset.enable_until and now < ruleset.enable_until then
        return false
    end
    local date = os.date("*t", now)
    if not (2 <= date.wday and date.wday <= 6) then
        return true
    end
    return not (9 <= date.hour and date.hour < 18)
end

ruleset.API_ENDPOINT = "api.neosocksd.internal:80"

-- 1. _G.redirect*: match the raw request "host:port"
-- in {matcher, action, optional log tag}
-- matching stops after a match is found

-- _G.redirect_name: for requests with name string
_G.redirect_name = {
    -- admin routes
    { match.exact("localhost:22"),               rule.redirect("127.0.0.1:22"),                               "ssh" },
    { match.exact("region1.lan:22"),             rule.redirect("localhost:22", "socks5://192.168.32.1:1080"), "region1" },
    { match.exact("region2.lan:22"),             rule.redirect("localhost:22", "socks5://192.168.33.1:1080"), "region2" },
    -- access mDNS sites directly
    { match.domain(".local"),                    rule.direct() },
    -- internal assignment
    { match.exact(ruleset.API_ENDPOINT),         rule.redirect("127.0.1.1:9080") },
    { match.agent(),                             rule.agent() },
    -- global condition
    { is_disabled,                               rule.reject(),                                               "off" },
    -- proxy routes
    { match.exact("region1.neosocksd.lan:1080"), rule.redirect("socks4a://192.168.32.1:1080") },
    { match.exact("region2.neosocksd.lan:1080"), rule.redirect("socks4a://192.168.33.1:1080") },
    -- dynamically loaded big domains list
    { composite.maybe(_G, "domains"),            rule.proxy("socks4a://proxy.lan:1080"),                      "biglist" },
    -- if in _G.hosts, go to _G.route/_G.route6
    -- otherwise, go to _G.route_default
}

-- _G.redirect: for requests with IPv4 address
_G.redirect = {
    -- redirect TCP DNS to local cache
    { match.exact("1.1.1.1:53"), rule.redirect("127.0.0.53:53") },
    { match.exact("1.0.0.1:53"), rule.redirect("127.0.0.53:53") },
    -- global condition
    { is_disabled,               rule.reject(),                 "off" },
    -- go to _G.route
}

-- _G.redirect6: for requests with IPv6 address
_G.redirect6 = {
    -- global condition
    { is_disabled, rule.reject(), "off" },
    -- go to _G.route6
}

-- 2. _G.hosts: map unmatched hosts
_G.hosts = {
    ["gateway.region1.lan"] = "192.168.32.1",
    ["host123.region1.lan"] = "192.168.32.123",
    ["gateway.region2.lan"] = "192.168.33.1",
    ["host123.region2.lan"] = "192.168.33.123"
}

-- 3. _G.route*: match the IP address
_G.route = {
    -- reject loopback or link-local
    { inet.subnet("127.0.0.0/8"),       rule.reject() },
    { inet.subnet("169.254.0.0/16"),    rule.reject() },
    -- region1 proxy
    { inet.subnet("192.168.32.0/24"),   rule.proxy("socks4a://192.168.32.1:1080"),                                "region1" },
    -- jump to region2 through region1 proxy (for a fancy demo)
    { inet.subnet("192.168.33.0/24"),   rule.proxy("socks4a://192.168.32.1:1080", "socks4a://192.168.33.1:1080"), "region2" },
    -- access other lan addresses directly
    { inet.subnet("192.168.0.0/16"),    rule.direct(),                                                            "lan" },
    -- dynamically loaded big IP ranges list
    { composite.maybe(_G, "countryip"), rule.proxy("socks4a://proxy.lan:1080"),                                   "biglist" },
    -- go to _G.route_default
}

_G.route6 = {
    -- reject loopback or link-local
    { inet6.subnet("::1/128"),                rule.reject() },
    { inet6.subnet("fe80::/10"),              rule.reject() },
    { inet6.subnet("::ffff:127.0.0.0/104"),   rule.reject() },
    { inet6.subnet("::ffff:169.254.0.0/112"), rule.reject() },
    -- dynamically loaded big IP ranges list
    { composite.maybe(_G, "countryip6"),      rule.proxy("socks4a://proxy.lan:1080"), "biglist" },
    -- go to _G.route_default
}

-- 4. the global default applies to any unmatched requests
-- in {action, optional log tag}
_G.route_default = { rule.proxy("socks4a://gateway.lan"), "default" }

function ruleset.stats(dt)
    local w = list:new()
    if is_disabled and is_disabled() then
        w:insertf("%-20s: %s", "Status", "(service disabled)")
    else
        w:insertf("%-20s: %s", "Status", "running")
    end
    w:insert(libruleset.stats(dt))
    w:insert(agent.stats(dt))
    w:insert("")
    return w:concat("\n")
end

local function main(...)
    pcall(collectgarbage, "generational")
    neosocksd.setinterval(60.0)
    -- inherit undefined fields from libruleset
    return setmetatable(ruleset, {
        __index = function(_, k)
            return _G.libruleset[k]
        end
    })
end

logf("ruleset loaded, interpreter: %s", _VERSION)
return main(...)
