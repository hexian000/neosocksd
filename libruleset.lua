-- [[ useful library routines ]] --
function _G.printf(...)
    return print(string.format(...))
end

function _G.errorf(s, ...)
    local level = tonumber(s)
    if level then
        return error(string.format(...), level + 1)
    end
    return error(string.format(s, ...), 2)
end

function _G.assertf(v, s, ...)
    if v then
        return
    end
    local level = tonumber(s)
    if level then
        return error(string.format(...), level + 1)
    end
    return error(string.format(s, ...), 2)
end

function _G.eval(s, ...)
    return assert(load(s, "=eval"))(...)
end

function string:startswith(sub)
    local n = string.len(sub)
    return string.sub(self, 1, n) == sub
end

function string:endswith(sub)
    local n = string.len(sub)
    return string.sub(self, -n) == sub
end

local list = {
    iter = ipairs,
    insert = table.insert,
    remove = table.remove,
    unpack = table.unpack,
    concat = table.concat
}

local list_mt = {
    __index = list
}

function list:new(t)
    return setmetatable(t or {}, list_mt)
end

function list:pack(...)
    return setmetatable({...}, list_mt)
end

function list:totable()
    return setmetatable(self, nil)
end

function list:insertf(s, ...)
    return self:insert(string.format(s, ...))
end

function list:append(t)
    return table.move(t, 1, #t, #self + 1, self)
end

function list:clone()
    return list:new():append(self)
end

function list:map(f)
    for i, v in ipairs(self) do
        self[i] = f(v)
    end
    return self
end

function list:reverse()
    local n = #self
    for i = 1, n / 2 do
        local j = n - i + 1
        self[i], self[j] = self[j], self[i]
    end
    return self
end
_G.list = list

_G.MAX_RECENT_EVENTS = 10
_G.recent_events = _G.recent_events or list:new()
local function addevent_(tstamp, msg)
    local entry = recent_events[1]
    if entry and entry.msg == msg then
        entry.count = entry.count + 1
        entry.tstamp = tstamp
        return
    end
    entry = {
        msg = msg,
        count = 1,
        tstamp = tstamp
    }
    recent_events[MAX_RECENT_EVENTS] = nil
    return recent_events:insert(1, entry)
end

function _G.log(...)
    local msg = list:pack(...):map(tostring):concat("\t")
    local now = os.time()
    addevent_(now, msg)
    if _G.NDEBUG then
        return
    end
    local timestamp = os.date("%Y-%m-%dT%T%z", now)
    local info = debug.getinfo(2, "Sl")
    local source = info.source
    if source:startswith("@") then
        source = source:sub(2)
        source = source:match("^.*/([^/]+)$") or source
    elseif source:startswith("=") then
        source = "<" .. source:sub(2) .. ">"
    else
        source = info.short_src
    end
    local line = info.currentline
    return _G.printf("D %s %s:%d %s", timestamp, source, line, msg)
end

function _G.logf(s, ...)
    return _G.log(string.format(s, ...))
end

local splithostport = neosocksd.splithostport
local parse_ipv4 = neosocksd.parse_ipv4
local parse_ipv6 = neosocksd.parse_ipv6

function _G.parse_cidr(s)
    local addr, shift = s:match("^(.+)/(%d+)$")
    local shift = tonumber(shift)
    if not shift or shift < 0 or shift > 32 then
        errorf(2, "invalid prefix size %q", s)
    end
    local mask = ~((1 << (32 - shift)) - 1)
    local subnet = parse_ipv4(addr)
    if not subnet or (subnet & mask ~= subnet) then
        errorf(2, "invalid subnet %q", s)
    end
    return subnet, shift
end

function _G.parse_cidr6(s)
    local addr, shift = s:match("^(.+)/(%d+)$")
    local shift = tonumber(shift)
    if not shift or shift < 0 or shift > 128 then
        errorf(2, "invalid prefix size %q", s)
    end
    local subnet1, subnet2 = parse_ipv6(addr)
    if shift > 64 then
        local mask = ~((1 << (128 - shift)) - 1)
        if not subnet1 or (subnet2 & mask ~= subnet2) then
            errorf(2, "invalid subnet %q", s)
        end
    else
        local mask = ~((1 << (64 - shift)) - 1)
        if not subnet1 or (subnet1 & mask ~= subnet1) or subnet2 ~= 0 then
            errorf(2, "invalid subnet %q", s)
        end
    end
    return subnet1, subnet2, shift
end

-- [[ route table matchers ]] --
local inet = {}
function inet.subnet(s)
    if type(s) ~= "table" then
        local subnet, shift = parse_cidr(s)
        local mask = ~((1 << (32 - shift)) - 1)
        subnet = subnet & mask
        return function(ip)
            return (ip & mask) == subnet
        end
    end
    local prefix = {}
    for _, v in pairs(s) do
        local subnet, shift = parse_cidr(v)
        local mask = ~((1 << (32 - shift)) - 1)
        local t = prefix[shift] or {}
        t[tostring(subnet & mask)] = true
        prefix[shift] = t
    end
    return function(ip)
        for shift, t in pairs(prefix) do
            local mask = ~((1 << (32 - shift)) - 1)
            if t[tostring(ip & mask)] then
                return true
            end
        end
        return false
    end
end
_G.inet = inet

local inet6 = {}
function inet6.subnet(s)
    if type(s) ~= "table" then
        local subnet1, subnet2, shift = parse_cidr6(s)
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
    local prefix = {}
    for _, v in pairs(s) do
        local subnet1, subnet2, shift = parse_cidr6(v)
        local t = prefix[shift] or {}
        t[subnet1 .. "," .. subnet2] = true
        prefix[shift] = t
    end
    return function(ip1, ip2)
        for shift, t in pairs(prefix) do
            local subnet1, subnet2
            if shift > 64 then
                local mask = ~((1 << (128 - shift)) - 1)
                subnet1, subnet2 = ip1, ip2 & mask
            else
                local mask = ~((1 << (64 - shift)) - 1)
                subnet1, subnet2 = ip1 & mask, 0
            end
            if t[subnet1 .. "," .. subnet2] then
                return true
            end
        end
        return false
    end
end
_G.inet6 = inet6

-- [[ redirect table matchers ]] --
local match = {}
function match.exact(s)
    if type(s) ~= "table" then
        local host, port = splithostport(s)
        assertf(host and port, 2, "exact matcher should contain host and port: %q", s)
        return function(addr)
            return addr == s
        end
    end
    local t = {}
    for _, v in pairs(s) do
        local host, port = splithostport(v)
        assertf(host and port, 2, "exact matcher should contain host and port: %q", v)
        t[v] = true
    end
    return function(addr)
        return not not t[addr]
    end
end

function match.host(s)
    if type(s) ~= "table" then
        return function(addr)
            local host, port = splithostport(addr)
            if not host then
                return false
            end
            return host == s
        end
    end
    local t = {}
    for _, v in pairs(s) do
        t[v] = true
    end
    return function(addr)
        local host, port = splithostport(addr)
        if not host then
            return false
        end
        return not not t[host]
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
    if type(s) ~= "table" then
        assertf(s:startswith("."), 2, [[domain matcher should start with ".": %q]], s)
        return function(addr)
            local host, port = splithostport(addr)
            if not host then
                return false
            end
            return host:endswith(s)
        end
    end
    local tree = {}
    for _, v in pairs(s) do
        assertf(v:startswith("."), 2, [[domain matcher should start with ".": %q]], v)
        local path, n = {}, 0
        for seg in v:gmatch("[^.]+") do
            table.insert(path, seg)
            n = n + 1
        end
        local t = tree
        for i = n, 2, -1 do
            local seg = path[i]
            t[seg] = t[seg] or {}
            t = t[seg]
        end
        t[path[1]] = true
    end
    return match.domaintree(tree)
end

function match.domaintree(tree)
    assertf(type(tree) == "table", 2, "domain tree should be a table")
    return function(addr)
        local host, port = splithostport(addr)
        if not host then
            return false
        end
        local path, n = {}, 0
        for seg in host:gmatch("[^.]+") do
            table.insert(path, seg)
            n = n + 1
        end
        local t = tree
        for i = n, 1, -1 do
            t = t[path[i]]
            if not t then
                break
            elseif t == true then
                return true
            end
        end
        return false
    end
end

function match.pattern(s)
    if type(s) ~= "table" then
        return function(addr)
            return not not addr:find(s)
        end
    end
    return function(addr)
        for _, pat in pairs(s) do
            if addr:find(pat) then
                return true
            end
        end
        return false
    end
end

function match.regex(s)
    if type(s) ~= "table" then
        local reg = regex.compile(s)
        return function(addr)
            return not not reg:find(addr)
        end
    end
    local regs = list:new(s):map(regex.compile):totable()
    return function(addr)
        for _, reg in pairs(regs) do
            if reg:find(addr) then
                return true
            end
        end
        return false
    end
end
_G.match = match

-- [[ composite matchers ]] --
local composite = {}
function composite.anyof(t)
    return function(...)
        for i, match in ipairs(t) do
            if match(...) then
                return true
            end
        end
        return false
    end
end

function composite.maybe(t, k)
    return function(...)
        local match = t[k]
        if match then
            return match(...)
        end
        return false
    end
end
_G.composite = composite

-- [[ rule actions ]] --
local rule = {}
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

function rule.default()
    return function(addr)
        local action = _G.route_default
        if action then
            return action(addr)
        end
        return addr
    end
end

function rule.redirect(dst, ...)
    local chain = list:pack(...):reverse()
    local host, port = splithostport(dst)
    if host == "" then
        return function(addr)
            local host, _ = splithostport(addr)
            return string.format("%s:%s", host, port), chain:unpack()
        end
    end
    if port == "" then
        return function(addr)
            local _, port = splithostport(addr)
            return string.format("%s:%s", host, port), chain:unpack()
        end
    end
    return function(addr)
        return dst, chain:unpack()
    end
end

function rule.proxy(...)
    local chain = list:pack(...):reverse()
    return function(addr)
        return addr, chain:unpack()
    end
end
_G.rule = rule

local lb = {}
function lb.random(t)
    local n = #t
    return function(...)
        return t[math.random(n)]
    end
end

function lb.roundrobin(t)
    local i, n = 0, #t
    return function(...)
        i = i % n + 1
        return t[i]
    end
end
_G.lb = lb

-- [[ internal route functions ]] --
_G.num_requests = _G.num_requests or 0
_G.stat_requests = _G.stat_requests or list:new({0})
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
                logf("[%s] %q", tag, addr)
            end
            return action(addr)
        end
    end
    -- check route table
    local host, port = splithostport(addr)
    if not host then
        logf("route: invalid address %q", addr)
        return nil
    end
    local routetab = _G.route
    if routetab then
        local ip = parse_ipv4(host)
        local action, tag = matchtab_(routetab, ip)
        if action then
            if tag then
                logf("[%s] %q", tag, addr)
            end
            return action(addr)
        end
    end
    -- global default
    logf("[default] %q", addr)
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
                logf("[%s] %q", tag, addr)
            end
            return action(addr)
        end
    end
    -- check route table
    local host, port = splithostport(addr)
    if not host then
        logf("route6: invalid address %q", addr)
        return nil
    end
    local routetab = _G.route6
    if routetab then
        local ip1, ip2 = parse_ipv6(host)
        local action, tag = matchtab_(routetab, ip1, ip2)
        if action then
            if tag then
                logf("[%s] %q", tag, addr)
            end
            return action(addr)
        end
    end
    -- global default
    logf("[default] %q", addr)
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
                logf("[%s] %q", tag, addr)
            end
            return action(addr)
        end
    end
    -- lookup in hosts table
    local host, port = splithostport(addr)
    host = string.lower(host)
    local hosts = _G.hosts
    if hosts then
        local entry = hosts[host]
        if entry then
            host = entry
            addr = string.format("%s:%s", host, port)
        end
    end
    -- check if the addr is a raw address
    if parse_ipv4(host) then
        return route_(addr)
    elseif parse_ipv6(host) then
        return route6_(addr)
    end
    -- global default
    logf("[default] %q", addr)
    local action = _G.route_default
    if action then
        return action(addr)
    end
    return addr
end

local function render_(w)
    local requests, n = list:new(), 0
    local last_requests
    for i, v in stat_requests:iter() do
        if last_requests then
            local delta = v - last_requests
            requests:insert(delta)
            n = n + 1
        end
        last_requests = v
    end
    requests:insert(num_requests - last_requests)
    local peak = math.max(requests:unpack())
    local q = math.max(peak, 1)
    for i, v in ipairs(requests) do
        requests[i] = math.floor(v / q * 5.0 + 0.5)
    end
    for y = 4, 0, -1 do
        local line = list:new()
        for x = 1, n + 1 do
            if requests[x] and requests[x] > y then
                line:insert("|")
            else
                line:insert(" ")
            end
        end
        w:insert(line:concat())
    end
    w:insertf("%s* (peak=%d)", string.rep("-", n), peak)
end

-- [[ ruleset callbacks, see API.md for details ]] --
local ruleset = {}

_G.is_enabled = _G.is_enabled or function()
    return true
end

function ruleset.resolve(addr)
    num_requests = num_requests + 1
    if not _G.is_enabled() then
        logf("service not enabled, reject %q", addr)
        return nil
    end
    return resolve_(addr)
end

function ruleset.route(addr)
    num_requests = num_requests + 1
    if not _G.is_enabled() then
        logf("service not enabled, reject %q", addr)
        return nil
    end
    return route_(addr)
end

function ruleset.route6(addr)
    num_requests = num_requests + 1
    if not _G.is_enabled() then
        logf("service not enabled, reject %q", addr)
        return nil
    end
    return route6_(addr)
end

_G.task_queue = list:new()
local function run_task_()
    local f = task_queue[1]
    if not f then
        return
    end
    task_queue:remove(1)
    neosocksd.setidle()
    f()
end

function _G.queue_task(f)
    task_queue:insert(f)
    neosocksd.setidle()
end

function ruleset.idle()
    run_task_()
end

function ruleset.tick(now)
    stat_requests:insert(num_requests)
    if stat_requests[MAX_STAT_REQUESTS + 1] then
        stat_requests:remove(1)
    end
    run_task_()
end

function ruleset.stats(dt)
    local w = list:new()
    local clock = os.clock()
    if clock > 0.0 then
        local last_clock = _G.last_clock
        if last_clock and clock >= last_clock then
            w:insertf("%-20s: %.03f %%", "Server Load", (clock - last_clock) / dt * 100.0)
        else
            w:insertf("%-20s: (unknown)", "Server Load")
        end
        _G.last_clock = clock
    end
    w:insert("> Recent Events")
    for i, entry in recent_events:iter() do
        if not entry then
            break
        end
        local tstamp = os.date("%Y-%m-%dT%T%z", entry.tstamp)
        if entry.count == 1 then
            w:insertf("%s %s", tstamp, entry.msg)
        else
            w:insertf("%s %s (x%d)", tstamp, entry.msg, entry.count)
        end
    end
    w:insert("> Request Stats")
    render_(w)
    return w:concat("\n")
end

return ruleset
