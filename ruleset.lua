function _G.printf(s, ...)
    if _G.NDEBUG then
        return
    end
    local timestamp = os.date("%Y-%m-%dT%T%z")
    local info = debug.getinfo(2, "Sl")
    local source = "<ruleset>"
    if info.source and string.sub(info.source, 1, 1) == "@" then
        source = string.sub(info.source, 2)
    end
    local line = info.currentline
    local msg = string.format(s, ...)
    print(string.format("- %s %s:%d %s", timestamp, source, line, msg))
end

function string:startswith(sub)
    local n = string.len(sub)
    return string.sub(self, 1, n) == sub
end

function string:endswith(sub)
    local n = string.len(sub)
    return string.sub(self, -n) == sub
end

local function splithostport(s)
    local i = string.find(s, ":[^:]*$")
    return string.sub(s, 1, i - 1), string.sub(s, i + 1)
end

--[[ global configs ]]
_G.NDEBUG = _G.NDEBUG or true

function _G.is_enabled()
    return true
end

_G.hosts = {
    ["gateway.region1.lan"] = "192.168.32.1",
    ["host123.region1.lan"] = "192.168.32.123",
    ["gateway.region2.lan"] = "192.168.33.1",
    ["host123.region2.lan"] = "192.168.33.123"
}

_G.redirect = {
    -- reject loopback or link-local
    [1] = {"^127%.", {nil}},
    [2] = {"^169%.254%.", {nil}}
}

_G.route = {
    -- region1 gateway
    [1] = {"^192%.168%.32%.", {"192.168.32.1:1080"}},
    -- jump to region2 via region1 gateway
    [2] = {"^192%.168%.33%.", {"192.168.33.1:1080", "192.168.32.1:1080"}},
    -- other lan address
    [3] = {"^192%.168%.", {"192.168.1.1:1080"}}
}
_G.route_default = {"192.168.1.1:1080"}

--[[ ruleset functions ]]
local ruleset = {}

--[[
    ruleset.resolve(domain) process a host name request
        i.e. HTTP CONNECT / SOCKS5 with host name ("socks5h" in cURL) / SOCKS4A
    <domain>: full qualified domain name and port, like "www.example.org:80"
    return <addr>: replace the request
    return <addr>, <proxy>: forward the request through another neosocksd
    return <addr>, <proxyN>, ..., <proxy1>: forward the request through proxy chain
    return nil: reject the request
]]
function ruleset.resolve(domain)
    if not _G.is_enabled() then
        printf("ruleset.resolve: ruleset disabled, reject %q", domain)
        return nil
    end
    printf("ruleset.resolve: %q", domain)
    local host, port = splithostport(domain)
    host = string.lower(host)
    -- redirect API domain
    if host == "neosocksd.lan:80" then
        return "127.0.0.1:9080"
    end
    -- lookup in hosts table
    local entry = hosts[host]
    if entry then
        return ruleset.route(string.format("%s:%s", entry, port))
    end
    -- resolve lan address locally
    if host:endswith(".lan") or host:endswith(".local") then
        local addr = neosocksd.resolve(host)
        return ruleset.route(string.format("%s:%s", addr, port))
    end
    -- accept
    return domain, table.unpack(route_default)
end

--[[
    ruleset.route(addr) process an IPv4 request
        i.e. SOCKS5 with IPv4 / SOCKS4
    <addr>: address and port, like "8.8.8.8:53"
    returns: same as ruleset.resolve(addr)
]]
function ruleset.route(addr)
    if not _G.is_enabled() then
        printf("ruleset.route: ruleset disabled, reject %q", addr)
        return nil
    end
    printf("ruleset.route: %q", addr)
    -- redirect
    for _, rule in ipairs(redirect) do
        local pattern, target = table.unpack(rule)
        if addr:find(pattern) then
            return table.unpack(target)
        end
    end
    local host, port = splithostport(addr)
    -- check route table
    for _, rule in ipairs(route) do
        local pattern, route = table.unpack(rule)
        if host:find(pattern) then
            return addr, table.unpack(route)
        end
    end
    -- accept
    return addr, table.unpack(route_default)
end

--[[
    ruleset.route6(addr) process an IPv6 request
        i.e. SOCKS5 with IPv6
    <addr>: address and port, like "[::1]:80"
    returns: same as ruleset.resolve(addr)
]]
function ruleset.route6(addr)
    if not _G.is_enabled() then
        printf("ruleset.route6: ruleset disabled, reject %q", addr)
        return nil
    end
    printf("ruleset.route6: %q", addr)
    return addr, table.unpack(route_default)
end

--[[
    ruleset.tick(now)
    <now>: current timestamp in seconds
    returns: ignored
]]
function ruleset.tick(now)
    printf("ruleset.tick: %.03f", now)
end
-- neosocksd.setinterval(1.0)

printf("ruleset loaded, interpreter: %s", _VERSION)
return ruleset
