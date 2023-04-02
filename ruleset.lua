local ruleset = {}

-- global options
_G.NDEBUG = _G.NDEBUG or false

function _G.is_enabled()
    return true
end

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

local hosts = {
    ["gateway.region1.lan"] = "192.168.32.1",
    ["host123.region1.lan"] = "192.168.32.123",
    ["gateway.region2.lan"] = "192.168.33.1",
    ["host123.region2.lan"] = "192.168.33.123"
}

local static_route = {
    -- bypass default gateway
    ["203.0.113.1"] = {}
}

local function route_default(addr)
    -- default gateway
    return addr, "192.168.1.1:1080"
end

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
        return nil
    end
    printf("ruleset.resolve: %q", domain)
    local host, port = splithostport(domain)
    host = string.lower(host)
    -- redirect API domain
    if host == "neosocksd.lan" then
        return "127.0.0.1:9080"
    end
    -- lookup in hosts table
    local entry = hosts[host]
    if entry then
        return ruleset.route(string.format("%s:%s", entry, port))
    end
    -- direct lan access
    if host:endswith(".lan") or host:endswith(".local") then
        return domain
    end
    -- accept
    return route_default(domain)
end

--[[
    ruleset.route(addr) process an IPv4 request
        i.e. SOCKS5 with IPv4 / SOCKS4
    <addr>: address and port, like "8.8.8.8:53"
    returns: same as ruleset.resolve(addr)
]]
function ruleset.route(addr)
    if not _G.is_enabled() then
        return nil
    end
    printf("ruleset.route: %q", addr)
    local host, port = splithostport(addr)
    -- static rule
    local exact_match = static_route[host]
    if exact_match then
        return addr, table.unpack(exact_match)
    end
    -- reject loopback or link-local
    if host:startswith("127.") or host:startswith("169.254.") then
        return nil
    end
    -- region1 gateway
    if addr:startswith("192.168.32.") then
        return addr, "192.168.32.1:1080"
    end
    -- jump to region2 via region1 gateway
    if addr:startswith("192.168.33.") then
        return addr, "192.168.33.1:1080", "192.168.32.1:1080"
    end
    -- direct lan access
    if host:startswith("192.168.") then
        return addr
    end
    -- accept
    return route_default(addr)
end

--[[
    ruleset.route6(addr) process an IPv6 request
        i.e. SOCKS5 with IPv6
    <addr>: address and port, like "[::1]:80"
    returns: same as ruleset.resolve(addr)
]]
function ruleset.route6(addr)
    if not _G.is_enabled() then
        return nil
    end
    printf("ruleset.route6: %q", addr)
    -- access any ipv6 directly
    return addr
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
