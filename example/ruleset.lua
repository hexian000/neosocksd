-- [[ ruleset.lua: code with rule table example ]] --
_G.libruleset = require("libruleset")
_G.agent = require("agent")

agent.api_endpoint = "127.0.1.1:9080"
agent.peername = "peer0"
agent.conns = {
    -- "api.neosocksd.internal:80" should be available over { proxy1, proxy2, ... }
    { "socks4a://127.0.32.1:1080" },
    { "socks4a://127.0.32.1:1080", "socks4a://127.0.32.2:1080" },
    { "socks4a://127.0.33.1:1080" },
}
-- route "peer0.internal" to current peer
agent.hosts = { "peer0" }

-- [[ basic authentication, pass --auth-required to enforce ]] --
_G.secrets = {
    ["lamer"] = "secret",
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

-- 1. _G.redirect*: handle requests as a string
-- in {matcher, action, optional log tag}
-- matching stops after a match is found

-- _G.redirect_name: handle domain name requests in "host:port"
_G.redirect_name = {
    -- rule.redirect(addr, proxy1, proxy2, ...)
    { match.exact("peer0.lan:22"),         rule.redirect("host-gateway:22"),       "ssh" },
    { match.exact("peer0.lan:80"),         rule.redirect("nginx:80"),              "web" },
    { match.exact("peer0.lan:443"),        rule.redirect("nginx:443"),             "web" },
    -- access local sites directly
    { match.domain({ ".lan", ".local" }),  rule.direct(),                          "lan" },
    -- ".internal" assignment
    { match.exact("peer0.internal:22"),    rule.redirect("host-gateway:22"),       "ssh" },
    { composite.subchain(agent, "chain") },
    -- global condition
    { is_disabled,                         rule.reject(),                          "off" },
    -- dynamically loaded big domains list, rule.proxy(proxy1, proxy2, ...)
    { composite.maybe(_G, "biglist_name"), rule.proxy("socks4a://proxy.lan:1080"), "biglist" },
    -- if in _G.hosts, go to _G.route/_G.route6
    -- otherwise, go to _G.route_default
}

-- _G.redirect: handle IPv4 requests in "ip:port"
_G.redirect = {
    -- redirect TCP DNS to local cache
    { match.exact("1.1.1.1:53"), rule.redirect("127.0.0.53:53") },
    { match.exact("1.0.0.1:53"), rule.redirect("127.0.0.53:53") },
    -- global condition
    { is_disabled,               rule.reject(),                 "off" },
    -- go to _G.route
}

-- _G.redirect6: handle IPv6 requests in "[ipv6]:port"
_G.redirect6 = {
    -- redirect TCP DNS to local cache
    { match.port(53), rule.redirect("127.0.0.53:53") },
    -- global condition
    { is_disabled,    rule.reject(),                 "off" },
    -- go to _G.route6
}

-- 2. _G.hosts: map unmatched hosts
_G.hosts = {
    ["gateway.region1.lan"] = "192.168.32.1",
    ["host123.region1.lan"] = "192.168.32.123",
    ["gateway.region2.lan"] = "192.168.33.1",
    ["host123.region2.lan"] = "192.168.33.123"
}

-- jump to region2 through region1 proxy
local proxy_region2 = rule.proxy("socks4a://192.168.32.1:1080", "socks4a://192.168.33.1:1080")

-- 3. _G.route*: Handle requests by IP address (to match subnet efficiently)
_G.route = {
    -- reject loopback or link-local
    { inet.subnet("127.0.0.0/8"),     rule.reject() },
    { inet.subnet("169.254.0.0/16"),  rule.reject() },
    -- region1 proxy
    { inet.subnet("192.168.32.0/24"), rule.proxy("socks4a://192.168.32.1:1080"), "region1" },
    -- region2 proxy
    { inet.subnet("192.168.33.0/24"), proxy_region2,                             "region2" },
    -- access other lan addresses directly
    { inet.subnet("192.168.0.0/16"),  rule.direct(),                             "lan" },
    -- dynamically loaded big IP ranges list
    { composite.maybe(_G, "biglist"), rule.direct(),                             "biglist" },
    -- go to _G.route_default
}

_G.route6 = {
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

function ruleset.stats(dt, q)
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

function rpc.update(timestamp)
    if timestamp and timestamp == table.get(_G, "ruleset_data", "timestamp") then
        return nil
    end
    return ruleset_data
end

function ruleset.update()
    -- fetch updated ruleset from central server
    local ok, data = agent.rpcall("socks4a://central.internal:1080", "update", ruleset.last_updated)
    if not ok then
        evlogf("ruleset update: %s", data)
        return
    end
    if not data then return end
    ruleset.last_updated = data.timestamp
    if data.biglist_raw then
        _G.biglist = inet.subnet(data.biglist_raw.cidr)
        _G.biglist6 = inet6.subnet(data.biglist_raw.cidr6)
        _G.biglist_name = composite.anyof({
            match.domain(data.biglist_raw.domain),
            match.host(data.biglist_raw.host),
            match.regex(data.biglist_raw.regex) })
    end
    _G.ruleset_data = data
    evlog("ruleset update: success")
end

local function main(...)
    neosocksd.setinterval(60)
    -- inherit undefined fields from libruleset
    return setmetatable(ruleset, {
        __index = function(_, k)
            return _G.libruleset[k]
        end
    })
end

evlogf("ruleset loaded, interpreter: %s", _VERSION)
return main(...)
