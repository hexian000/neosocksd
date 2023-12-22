_G.libruleset = require("libruleset")

-- [[ configurations ]] --
-- 1. ordered redirect rules (matched as string)
-- in {matcher, action, optional log tag}
-- matching stops after a match is found

local function is_disabled()
    local now = os.date("*t")
    if not (2 <= now.wday and now.wday <= 6) then
        return true
    end
    return not (9 <= now.hour and now.hour < 18)
end

-- redirect_name: for requests with name string
_G.redirect_name = {
    -- access mDNS sites directly
    { match.domain(".local"),                    rule.direct() },
    -- self-assignment
    { match.exact("api.neosocksd.lan:80"),       rule.redirect("127.0.1.1:9080") },
    -- admin routes
    { match.exact("localhost:22"),               rule.redirect("127.0.0.1:22"),                               "ssh" },
    { match.exact("region1.lan:22"),             rule.redirect("localhost:22", "socks5://192.168.32.1:1080"), "region1" },
    { match.exact("region2.lan:22"),             rule.redirect("localhost:22", "socks5://192.168.33.1:1080"), "region2" },
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

-- redirect: for requests with IPv4 address
_G.redirect = {
    -- redirect TCP DNS to local cache
    { match.exact("1.1.1.1:53"), rule.redirect("127.0.0.53:53") },
    { match.exact("1.0.0.1:53"), rule.redirect("127.0.0.53:53") },
    -- global condition
    { is_disabled,               rule.reject(),                 "off" },
    -- go to _G.route
}

-- redirect6: for requests with IPv6 address
_G.redirect6 = {
    -- global condition
    { is_disabled, rule.reject(), "off" },
    -- go to _G.route6
}

-- 2. unordered hosts map
_G.hosts = {
    ["gateway.region1.lan"] = "192.168.32.1",
    ["host123.region1.lan"] = "192.168.32.123",
    ["gateway.region2.lan"] = "192.168.33.1",
    ["host123.region2.lan"] = "192.168.33.123"
}

-- 3. ordered routes (matched as address)
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
_G.route_index = 1
_G.route_list = {
    [1] = { rule.proxy("socks4a://127.0.0.1:1081"), "default1" },
    [2] = { rule.proxy("socks4a://127.0.0.2:1081"), "default2" }
}
_G.route_default = route_index[1]

function _G.set_route(i, ...)
    _G.route_index = i
    if select("#", ...) > 0 then
        _G.route_list[route_index] = { rule.proxy(...) }
    end
    _G.route_default = route_list[route_index]
end

local ruleset = setmetatable({}, {
    __index = function(t, k)
        return _G.libruleset[k]
    end
})
neosocksd.setinterval(60.0)

_G.server_rtt = {}
local function ping(target)
    local lasterr
    local rtt = {}
    for i = 1, 4 do
        local begin = neosocksd.now()
        local ok, result = await.rpcall(target, "echo", string.rep(" ", 32))
        if ok then
            table.insert(rtt, neosocksd.now() - begin)
        else
            lasterr = result
        end
    end
    if rtt[1] then
        rtt = math.min(table.unpack(rtt))
        return true, string.format("%dms", math.ceil(rtt * 1e+3))
    end
    return false, lasterr
end

local function keepalive(target, tag)
    while true do
        local ok, result = ping(target)
        logf("ping %q: %s", tag, result)
        server_rtt[tag] = result
        await.sleep(ok and 3600 or 60)
    end
end

async(function()
    await.sleep(10)
    for k, v in pairs(route_list) do
        local route, tag = v[1], v[2]
        local target = table.pack(route("api.neosocksd.lan:80"))
        async(keepalive, target, tag)
    end
end)

local function format_rtt()
    local w = list:new()
    for tag, result in pairs(server_rtt) do
        w:insertf("[%s] %s", tag, result)
    end
    w:sort()
    return w:concat(", ")
end

function ruleset.stats(dt)
    local w = list:new()
    w:insertf("%-20s: %d", "Default Route", route_index)
    w:insertf("%-20s: %s", "Server RTT", format_rtt())
    w:insert(libruleset.stats(dt))
    return w:concat("\n")
end

logf("ruleset loaded, interpreter: %s", _VERSION)
return ruleset
