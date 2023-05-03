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
local function addevent_(tstamp, msg)
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
    addevent_(now, msg)
    if _G.NDEBUG then
        return
    end
    local timestamp = os.date("%Y-%m-%dT%T%z", now)
    local info = debug.getinfo(2, "Sl")
    local source = info.source
    if source:startswith("@") then
        source = string.sub(source, 2)
        local i = string.find(source, "/.+$")
        if i then
            source = string.sub(source, i + 1)
        end
    elseif source:startswith("=") then
        source = "<" .. string.sub(source, 2) .. ">"
    else
        source = info.short_src
    end
    local line = info.currentline
    print(string.format("D %s %s:%d ", timestamp, source, line) .. msg)
end

function _G.errorf(s, ...)
    error(string.format(s, ...), 2)
end

function _G.splithostport(s)
    local i = string.find(s, ":[^:]*$")
    if not i then
        return nil
    end
    return string.sub(s, 1, i - 1), string.sub(s, i + 1)
end

-- [[ route table matchers ]] --
_G.inet = {}
function inet.subnet(s)
    local i = string.find(s, "/%d+$")
    local host = string.sub(s, 1, i - 1)
    local shift = tonumber(string.sub(s, i + 1))
    if shift < 0 or shift > 32 then
        error("invalid subnet")
    end
    local mask = ~((1 << (32 - shift)) - 1)
    local subnet = neosocksd.parse_ipv4(host) & mask
    return function(addr)
        local ip = neosocksd.parse_ipv4(addr)
        if not ip then
            return false
        end
        return (ip & mask) == subnet
    end
end

_G.inet6 = {}
function inet6.subnet(s)
    local i = string.find(s, "/%d+$")
    local host = string.sub(s, 1, i - 1)
    local shift = tonumber(string.sub(s, i + 1))
    if shift < 0 or shift > 128 then
        error("invalid subnet")
    end
    local subnet1, subnet2 = neosocksd.parse_ipv6(host)
    if shift > 64 then
        local mask = ~((1 << (128 - shift)) - 1)
        subnet2 = subnet2 & mask
        return function(addr)
            local ip1, ip2 = neosocksd.parse_ipv6(addr)
            if not ip1 then
                return false
            end
            return ip1 == subnet1 and (ip2 & mask) == subnet2
        end
    end
    local mask = ~((1 << (64 - shift)) - 1)
    subnet1 = subnet1 & mask
    return function(addr)
        local ip1, ip2 = neosocksd.parse_ipv6(addr)
        if not ip1 then
            return false
        end
        return (ip1 & mask) == subnet1
    end
end

-- [[ redirect table matchers ]] --
_G.match = {}
function match.exact(address)
    return function(addr)
        return addr == address
    end
end

function match.startswith(pattern)
    return function(addr)
        return string.startswith(addr, pattern)
    end
end

function match.endswith(pattern)
    return function(addr)
        return string.endswith(addr, pattern)
    end
end

function match.pattern(pattern)
    return function(addr)
        return not not string.find(addr, pattern)
    end
end

function match.port(from, to)
    if not to then
        to = from
    end
    return function(addr)
        local host, port = splithostport(addr)
        if not host then
            return false
        end
        return from <= port and port <= to
    end
end

-- [[ rule actions ]] --
_G.rule = {}
function rule.direct()
    return function(addr)
        return addr
    end
end

function rule.redirect(...)
    local chain = table.pack(...)
    return function(addr)
        return table.unpack(chain)
    end
end

function rule.proxy(...)
    local chain = table.pack(...)
    return function(addr)
        return addr, table.unpack(chain)
    end
end

function rule.reject()
    return function(addr)
        printf("reject: %q", addr)
        return nil
    end
end

function rule.resolve()
    return function(s)
        local host, port = splithostport(s)
        local addr = neosocksd.resolve(host)
        if not addr then
            errorf("unable to resolve host name: %q", host)
        end
        return string.format("%s:%s", addr, port)
    end
end

-- [[ internal route functions ]] --
_G.num_requests = _G.num_requests or 0
_G.stat_requests = _G.stat_requests or {}
_G.last_clock = _G.last_clock or 0.0
_G.MAX_STAT_REQUESTS = 60

local function run_match_(t, request)
    for i, rule in ipairs(t) do
        local match, action = table.unpack(rule)
        if match(request) then
            return action
        end
    end
    return t[0]
end

local function route_(addr)
    -- check redirect table
    local redirtab = _G.redirect
    if redirtab then
        local action = run_match_(redirtab, addr)
        if action then
            return action(addr)
        end
    end
    -- check route table
    local host, port = splithostport(addr)
    if not host then
        errorf("invalid address: %q", addr)
    end
    local routetab = _G.route
    if routetab then
        local action = run_match_(routetab, host)
        if action then
            return action(addr)
        end
    end
    -- global default
    local action = _G.route_default
    if action then
        return action(addr)
    end
    return addr
end

local function route6_(addr)
    -- check redirect table
    local redirtab = _G.redirect6
    if redirtab then
        local action = run_match_(redirtab, addr)
        if action then
            return action(addr)
        end
    end
    -- check route table
    local host, port = splithostport(addr)
    if not host then
        errorf("invalid address: %q", addr)
    end
    local routetab = _G.route6
    if routetab then
        local action = run_match_(routetab, host)
        if action then
            return action(addr)
        end
    end
    -- global default
    local action = _G.route_default
    if action then
        return action(addr)
    end
    return addr
end

local function resolve_(addr)
    -- check redirect table
    local redirtab = _G.redirect_name
    if redirtab then
        local action = run_match_(redirtab, addr)
        if action then
            return action(addr)
        end
    end
    -- lookup in hosts table
    local host, port = splithostport(addr)
    host = string.lower(host)
    local hosts = _G.hosts or {}
    local entry = hosts[host]
    if entry then
        host = entry
        addr = string.format("%s:%s", host, port)
    end
    -- check if addr is a raw address
    if neosocksd.parse_ipv4(host) then
        return route_(addr)
    elseif neosocksd.parse_ipv6(host) then
        return route6_(addr)
    end
    -- global default
    local action = _G.route_default
    if action then
        return action(addr)
    end
    return addr
end

local function render_(w)
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
        table.insert(w, "(graph not available)")
        return
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
end

local function stats_(dt)
    local w = {}
    local appendf = function(w, s, ...)
        table.insert(w, string.format(s, ...))
    end
    local clock = os.clock()
    if clock > 0.0 then
        appendf(w, "%-16s: %.03f %%", "Server Load", (clock - last_clock) / dt * 100.0)
        last_clock = clock
    end
    table.insert(w, "> Recent Events")
    local p = recent_events
    for i = 1, MAX_RECENT_EVENTS do
        if not p then
            break
        end
        if p.count == 1 then
            appendf(w, "%s %s", os.date("%Y-%m-%dT%T%z", p.tstamp), p.msg)
        else
            appendf(w, "%s %s (x%d)", os.date("%Y-%m-%dT%T%z", p.tstamp), p.msg, p.count)
        end
        p = p.next
    end
    table.insert(w, "> Request Stats")
    render_(w)
    return table.concat(w, "\n")
end

-- [[ ruleset callbacks, see API.md for details ]] --
local ruleset = {}

function ruleset.resolve(addr)
    num_requests = num_requests + 1
    if not _G.is_enabled() then
        printf("ruleset.resolve: service not enabled, reject %q", addr)
        return nil
    end
    printf("ruleset.resolve: %q", addr)
    return resolve_(addr)
end

function ruleset.route(addr)
    num_requests = num_requests + 1
    if not _G.is_enabled() then
        printf("ruleset.route: service not enabled, reject %q", addr)
        return nil
    end
    printf("ruleset.route: %q", addr)
    return route_(addr)
end

function ruleset.route6(addr)
    num_requests = num_requests + 1
    if not _G.is_enabled() then
        printf("ruleset.route6: service not enabled, reject %q", addr)
        return nil
    end
    printf("ruleset.route6: %q", addr)
    return route6_(addr)
end

function ruleset.tick(now)
    printf("ruleset.tick: %.03f", now)
    table.insert(stat_requests, num_requests)
    if stat_requests[MAX_STAT_REQUESTS + 1] then
        table.remove(stat_requests, 1)
    end
end
neosocksd.setinterval(60.0)

function ruleset.stats(dt)
    local ok, ret = pcall(stats_, dt)
    if not ok then
        return tostring(ret)
    end
    return ret
end

return ruleset
