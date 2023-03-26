local ruleset = {}

-- global options
_G.toggle = _G.toggle or true
_G.NDEBUG = _G.NDEBUG or false

local function printf(s, ...)
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

local function startswith(s, sub)
    local n = string.len(sub)
    return string.sub(s, 1, n) == sub
end

local function endswith(s, sub)
    local n = string.len(sub)
    return string.sub(s, -n) == sub
end

local function splithostport(s)
    local i = string.find(s, ":[^:]*$")
    return string.sub(s, 1, i - 1), string.sub(s, i + 1)
end

local hosts = {
    ["gateway.region1.lan"] = "192.168.32.1",
    ["host123.region1.lan"] = "192.168.32.123",
    ["gateway.region2.lan"] = "192.168.33.1",
    ["host123.region2.lan"] = "192.168.33.123"
}

local routes = {
    ["192.168.32."] = {"192.168.32.1:1080"},
    -- reach region2 via region1 gateway
    ["192.168.33."] = {"192.168.33.1:1080", "192.168.32.1:1080"}
}

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
    printf("ruleset.resolve: %q", domain)
    if not _G.toggle then
        return nil
    end
    local host, port = splithostport(domain)
    host = string.lower(host)
    -- redirect API domain
    if host == "neosocksd.lan" then
        -- test proxy jump
        return "127.0.0.1:9080"
    end
    -- lookup in hosts table
    local entry = hosts[host]
    if entry then
        return ruleset.route(string.format("%s:%s", entry, port))
    end
    -- reject other localnet
    if endswith(host, ".lan") or endswith(host, ".local") then
        return nil
    end
    -- accept
    return domain
end

--[[
    ruleset.route(addr) process an IPv4 request
        i.e. SOCKS5 with IPv4 / SOCKS4
    <addr>: address and port, like "8.8.8.8:53"
    returns: same as ruleset.resolve(addr)
]]
function ruleset.route(addr)
    printf("ruleset.route: %q", addr)
    if not _G.toggle then
        return nil
    end
    local host, port = splithostport(addr)
    -- reject loopback or link-local
    if startswith(host, "127.") or startswith(host, "169.254.") then
        return nil
    end
    -- lookup in route table
    for prefix, route in pairs(routes) do
        if startswith(host, prefix) then
            return addr, table.unpack(route)
        end
    end
    -- direct lan access
    if startswith(host, "192.168.") then
        return addr
    end
    -- default gateway
    return addr, "192.168.1.1:1080"
end

--[[
    ruleset.route6(addr) process an IPv6 request
        i.e. SOCKS5 with IPv6
    <addr>: address and port, like "[::1]:80"
    returns: same as ruleset.resolve(addr)
]]
function ruleset.route6(addr)
    printf("ruleset.route6: %q", addr)
    if not _G.toggle then
        return nil
    end
    -- reject any ipv6
    return nil
end

printf("ruleset loaded, interpreter: %s", _VERSION)
return ruleset
