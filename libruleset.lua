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
    assert(i, "invalid address format (configuration error?)")
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
    return function(ip)
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
        return function(ip1, ip2)
            return ip1 == subnet1 and (ip2 & mask) == subnet2
        end
    end
    local mask = ~((1 << (64 - shift)) - 1)
    subnet1 = subnet1 & mask
    return function(ip1, ip2)
        return (ip1 & mask) == subnet1
    end
end

-- [[ redirect table matchers ]] --
_G.match = {}
function match.exact(s)
    local host, port = splithostport(s)
    if not host then
        errorf("exact matcher should contains host and port: %q", s)
    end
    return function(addr)
        return addr == s
    end
end

function match.host(s)
    return function(addr)
        local host, port = splithostport(addr)
        if not host then
            return false
        end
        return host == s
    end
end

function match.port(from, to)
    if not to then
        to = from
    end
    return function(addr)
        local host, port = splithostport(addr)
        if not port then
            return false
        end
        port = tonumber(port)
        return from <= port and port <= to
    end
end

function match.domain(s)
    if not s:startswith(".") then
        errorf("domain matcher should starts with \".\": %q", s)
    end
    return function(addr)
        local host, port = splithostport(addr)
        if not host then
            return false
        end
        return host:endswith(s)
    end
end

function match.pattern(s)
    return function(addr)
        return not not addr:find(s)
    end
end

-- [[ composite matchers ]] --
_G.composite = {}
function composite.anyof(t)
    return function(q)
        for i, match in ipairs(t) do
            if match(q) then
                return true
            end
        end
        return false
    end
end

-- [[ rule actions ]] --
_G.rule = {}
function rule.direct()
    return function(addr)
        return addr
    end
end

function rule.reject()
    return function(addr)
        return nil
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
_G.last_clock = _G.last_clock or nil
_G.MAX_STAT_REQUESTS = 60

local function matchtab_(t, ...)
    for i, rule in ipairs(t) do
        local match, action, tag = table.unpack(rule)
        if match(...) then
            return action, tag
        end
    end
    return t[0], "default"
end

local function route_(addr)
    -- check redirect table
    local redirtab = _G.redirect
    if redirtab then
        local action, tag = matchtab_(redirtab, addr)
        if action then
            if tag then
                printf("redirect: [%s] %q", tag, addr)
            end
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
        local ip = neosocksd.parse_ipv4(host)
        local action, tag = matchtab_(routetab, ip)
        if action then
            if tag then
                printf("route: [%s] %q", tag, addr)
            end
            return action(addr)
        end
    end
    -- global default
    printf("route default: %q", addr)
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
        local action, tag = matchtab_(redirtab, addr)
        if action then
            if tag then
                printf("redirect6: [%s] %q", tag, addr)
            end
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
        local ip1, ip2 = neosocksd.parse_ipv6(host)
        local action, tag = matchtab_(routetab, ip1, ip2)
        if action then
            if tag then
                printf("route6: [%s] %q", tag, addr)
            end
            return action(addr)
        end
    end
    -- global default
    printf("route6 default: %q", addr)
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
        local action, tag = matchtab_(redirtab, addr)
        if action then
            if tag then
                printf("redirect_name: [%s] %q", tag, addr)
            end
            local ret = table.pack(action(addr))
            if #ret ~= 1 then
                return table.unpack(ret)
            end
            addr = ret[1]
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
    printf("resolve default: %q", addr)
    local action = _G.route_default
    if action then
        return action(addr)
    end
    return addr
end

local function render_(w)
    local requests = {}
    local last_requests = 0
    for i, n in ipairs(stat_requests) do
        if i > 1 then
            table.insert(requests, n - stat_requests[i - 1])
        end
        last_requests = n
    end
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
    if card > 0 then
        card = card - 1
    end
    table.insert(w, string.format("%s* (max=%d)", string.rep("-", card), max))
end

local function stats_(dt)
    local w = {}
    local appendf = function(w, s, ...)
        table.insert(w, string.format(s, ...))
    end
    local clock = os.clock()
    if clock > 0.0 then
        if last_clock then
            appendf(w, "%-16s: %.03f %%", "Server Load", (clock - last_clock) / dt * 100.0)
        end
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
    return resolve_(addr)
end

function ruleset.route(addr)
    num_requests = num_requests + 1
    if not _G.is_enabled() then
        printf("ruleset.route: service not enabled, reject %q", addr)
        return nil
    end
    return route_(addr)
end

function ruleset.route6(addr)
    num_requests = num_requests + 1
    if not _G.is_enabled() then
        printf("ruleset.route6: service not enabled, reject %q", addr)
        return nil
    end
    return route6_(addr)
end

function ruleset.tick(now)
    table.insert(stat_requests, num_requests)
    if stat_requests[MAX_STAT_REQUESTS + 1] then
        table.remove(stat_requests, 1)
    end
end
neosocksd.setinterval(60.0)

function ruleset.stats(dt)
    return stats_(dt)
end

return ruleset
