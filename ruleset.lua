-- [[ useful library routines ]] --
function string:startswith(sub)
    local n = string.len(sub)
    return string.sub(self, 1, n) == sub
end

function string:endswith(sub)
    local n = string.len(sub)
    return string.sub(self, -n) == sub
end

function _G.printf(s, ...)
    if _G.NDEBUG then
        return
    end
    local timestamp = os.date("%Y-%m-%dT%T%z")
    local info = debug.getinfo(2, "Sl")
    local source = info.source
    if source:startswith("@") then
        source = string.sub(source, 2)
    elseif source:startswith("=") then
        source = "<" .. string.sub(source, 2) .. ">"
    else
        source = info.short_src
    end
    local line = info.currentline
    print(string.format("D %s %s:%d " .. s, timestamp, source, line, ...))
end

function _G.ipv4_subnet(mask)
    local i = string.find(s, "/%d+$")
    local s = string.sub(s, 1, i - 1)
    local shift = tonumber(string.sub(s, i + 1))
    if shift < 0 or shift > 32 then
        error("invalid subnet")
    end
    local mask = ~((1 << (32 - shift)) - 1)
    local subnet = neosocksd.parse_ipv4(s) & mask
    return function(addr)
        local ip = neosocksd.parse_ipv4(addr)
        return (ip & mask) == subnet
    end
end

function _G.ipv6_subnet(mask)
    local i = string.find(s, "/%d+$")
    local s = string.sub(s, 1, i - 1)
    local shift = tonumber(string.sub(s, i + 1))
    if shift < 0 or shift > 64 then
        error("invalid subnet")
    end
    local subnet1, subnet2 = neosocksd.parse_ipv6(s)
    if shift > 64 then
        local mask = ~((1 << (128 - shift)) - 1)
        subnet2 = subnet2 & mask
        return function(ip)
            local ip1, ip2 = neosocksd.parse_ipv6(addr)
            return ip1 == subnet1 and (ip2 & mask) == subnet2
        end
    end
    local mask = ~((1 << (64 - shift)) - 1)
    subnet1 = subnet1 & mask
    return function(ip)
        local ip1, ip2 = neosocksd.parse_ipv6(addr)
        return (ip1 & mask) == subnet1
    end
end

function _G.splithostport(s)
    local i = string.find(s, ":[^:]*$")
    return string.sub(s, 1, i - 1), string.sub(s, i + 1)
end

-- [[ configurations ]] --
-- global schedule
function _G.is_enabled()
    return true
end

-- unordered hosts map
_G.hosts = {
    ["neosocksd.lan"] = "127.0.1.1",
    ["gateway.region1.lan"] = "192.168.32.1",
    ["host123.region1.lan"] = "192.168.32.123",
    ["gateway.region2.lan"] = "192.168.33.1",
    ["host123.region2.lan"] = "192.168.33.123"
}

-- ordered redirect rules
_G.redirect = {
    -- redirect API domain
    [1] = {"^127%.0%.1%.1:80$", {"127.0.1.1:9080"}},
    [2] = {"^127%.0%.1%.1:", {nil}},
    -- reject loopback or link-local
    [3] = {"^127%.", {nil}},
    [4] = {"^169%.254%.", {nil}}
}

-- ordered routes
_G.route = {
    -- region1 gateway
    [1] = {"^192%.168%.32%.", {"192.168.32.1:1080"}},
    -- jump to region2 via region1 gateway
    [2] = {"^192%.168%.33%.", {"192.168.33.1:1080", "192.168.32.1:1080"}},
    -- access other lan addresses directly
    [3] = {"^192%.168%.", {}}
}
-- default gateway
_G.route_default = {"192.168.1.1:1080"}

-- [[ simple route functions ]] --
local function simple_route(addr)
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
    -- default route
    return addr, table.unpack(route_default)
end

local function simple_route6(addr)
    -- default route
    return addr, table.unpack(route_default)
end

local function simple_resolve(addr)
    local host, port = splithostport(addr)
    host = string.lower(host)
    -- lookup in hosts table
    local entry = hosts[host]
    if entry then
        return simple_route(string.format("%s:%s", entry, port))
    end
    -- resolve lan address locally
    if host:endswith(".lan") or host:endswith(".local") then
        local addr = neosocksd.resolve(host)
        return simple_route(string.format("%s:%s", addr, port))
    end
    -- default route
    return addr, table.unpack(route_default)
end

-- [[ ruleset callbacks, see API.md for details ]] --
local ruleset = {}

_G.num_request = _G.num_request or 0

function ruleset.resolve(addr)
    if not _G.is_enabled() then
        printf("ruleset.resolve: service not enabled, reject %q", addr)
        return nil
    end
    printf("ruleset.resolve: %q", addr)
    num_request = num_request + 1
    return simple_resolve(addr)
end

function ruleset.route(addr)
    if not _G.is_enabled() then
        printf("ruleset.route: service not enabled, reject %q", addr)
        return nil
    end
    printf("ruleset.route: %q", addr)
    num_request = num_request + 1
    return simple_route(addr)
end

function ruleset.route6(addr)
    if not _G.is_enabled() then
        printf("ruleset.route6: service not enabled, reject %q", addr)
        return nil
    end
    printf("ruleset.route6: %q", addr)
    num_request = num_request + 1
    return simple_route6(addr)
end

function ruleset.tick(now)
    printf("ruleset.tick: %.03f", now)
    neosocksd.invoke([[printf("test rpc")]], "neosocksd.lan:80", "127.0.0.1:1080")
end
-- neosocksd.setinterval(1.0)

function ruleset.stats(dt)
    local w = {}
    local appendf = function(s, ...)
        table.insert(w, string.format(s, ...))
    end
    appendf("%16s: %d", "Num Requests", num_request)
    return table.concat(w, "\n")
end

printf("ruleset loaded, interpreter: %s", _VERSION)
return ruleset
