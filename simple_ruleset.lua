-- [[ useful library routines ]] --
function string:startswith(sub)
    local n = string.len(sub)
    return string.sub(self, 1, n) == sub
end

function string:endswith(sub)
    local n = string.len(sub)
    return string.sub(self, -n) == sub
end

_G.MAX_RECENT_EVENTS = 10

local function event_add(tstamp, msg)
    local p = _G.recent_events
    if p and p.msg == msg then
        p.count = p.count + 1
        p.tstamp = tstamp
        return
    end
    p = {
        msg = msg,
        count = 1,
        tstamp = tstamp,
        next = p
    }
    _G.recent_events = p
    for i = 1, MAX_RECENT_EVENTS do
        if not p then
            return
        end
        p = p.next
    end
    if p then
        p.next = nil
    end
end

function _G.printf(s, ...)
    local now = os.time()
    local msg = string.format(s, ...)
    event_add(now, msg)
    if _G.NDEBUG then
        return
    end
    local timestamp = os.date("%Y-%m-%dT%T%z", now)
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
    print(string.format("D %s %s:%d ", timestamp, source, line) .. msg)
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

-- [[ simple route functions ]] --
local function simple_route(addr)
    -- check redirect table
    local redirtab = _G.redirect or {}
    for _, rule in ipairs(redirtab) do
        local pattern, target = table.unpack(rule)
        if addr:find(pattern) then
            return table.unpack(target)
        end
    end
    local host, port = splithostport(addr)
    -- check route table
    local routetab = _G.route or {}
    for _, rule in ipairs(routetab) do
        local pattern, dest = table.unpack(rule)
        if host:find(pattern) then
            return addr, table.unpack(dest)
        end
    end
    -- default route
    local default = route_default or {}
    return addr, table.unpack(default)
end

local function simple_route6(addr)
    -- check redirect table
    local redirtab = _G.redirect6 or {}
    for _, rule in ipairs(redirtab) do
        local pattern, target = table.unpack(rule)
        if addr:find(pattern) then
            return table.unpack(target)
        end
    end
    local host, port = splithostport(addr)
    -- check route table
    local routetab = _G.route6 or {}
    for _, rule in ipairs(routetab) do
        local pattern, dest = table.unpack(rule)
        if host:find(pattern) then
            return addr, table.unpack(dest)
        end
    end
    -- default route
    local default = route6_default or route_default or {}
    return addr, table.unpack(default)
end

local function simple_resolve(addr)
    local host, port = splithostport(addr)
    host = string.lower(host)
    -- lookup in hosts table
    local hosts = _G.hosts or {}
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

_G.num_requests = _G.num_requests or 0
_G.stat_requests = _G.stat_requests or {}
_G.MAX_STAT_REQUESTS = 60

function ruleset.resolve(addr)
    num_requests = num_requests + 1
    if not _G.is_enabled() then
        printf("ruleset.resolve: service not enabled, reject %q", addr)
        return nil
    end
    printf("ruleset.resolve: %q", addr)
    return simple_resolve(addr)
end

function ruleset.route(addr)
    num_requests = num_requests + 1
    if not _G.is_enabled() then
        printf("ruleset.route: service not enabled, reject %q", addr)
        return nil
    end
    printf("ruleset.route: %q", addr)
    return simple_route(addr)
end

function ruleset.route6(addr)
    num_requests = num_requests + 1
    if not _G.is_enabled() then
        printf("ruleset.route6: service not enabled, reject %q", addr)
        return nil
    end
    printf("ruleset.route6: %q", addr)
    return simple_route6(addr)
end

function ruleset.tick(now)
    printf("ruleset.tick: %.03f", now)
    table.insert(stat_requests, num_requests)
    if stat_requests[MAX_STAT_REQUESTS + 1] then
        table.remove(stat_requests, 1)
    end
end
neosocksd.setinterval(60.0)

local function render_stats()
    local w = {}
    local requests = {}
    for i, n in ipairs(stat_requests) do
        if i > 1 then
            table.insert(requests, n - stat_requests[i - 1])
        end
    end
    local last_requests = stat_requests[#stat_requests] or 0
    table.insert(requests, num_requests - last_requests)
    local max = math.max(table.unpack(requests))
    if max < 1 then
        return "(graph not available)"
    end
    for i, n in ipairs(requests) do
        requests[i] = math.floor(requests[i] / max * 5.0 + 0.5)
    end
    for y = 4, 0, -1 do
        local line = {}
        for x = 1, MAX_STAT_REQUESTS do
            if requests[x] and requests[x] > y then
                table.insert(line, "|")
            else
                table.insert(line, " ")
            end
        end
        table.insert(w, table.concat(line))
    end
    local card = #requests
    local line = {}
    for x = 1, MAX_STAT_REQUESTS do
        if x < card then
            table.insert(line, "-")
        elseif x == card then
            table.insert(line, "*")
        else -- x > card
            break
        end
    end
    table.insert(line, string.format(" (max=%d)", max))
    table.insert(w, table.concat(line))
    return table.concat(w, "\n")
end

function ruleset.stats(dt)
    local w = {}
    local appendf = function(s, ...)
        table.insert(w, string.format(s, ...))
    end
    local p = recent_events
    for i = 1, MAX_RECENT_EVENTS do
        if not p then
            break
        end
        if p.count == 1 then
            appendf("%s %s", os.date("%Y-%m-%dT%T%z", p.tstamp), p.msg)
        else
            appendf("%s %s (x%d)", os.date("%Y-%m-%dT%T%z", p.tstamp), p.msg, p.count)
        end
        p = p.next
    end
    table.insert(w, render_stats())
    return table.concat(w, "\n")
end

return ruleset
