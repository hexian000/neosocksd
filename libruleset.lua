-- [[ useful library routines ]] --
function _G.printf(...)
    return print(string.format(...))
end

function _G.eval(s, ...)
    return assert(load(s, "=eval"))(...)
end

function package.replace(modname, chunk)
    local module = chunk()
    local loaded = package.loaded[modname]
    package.loaded[modname] = module
    if _G[modname] == loaded then
        _G[modname] = module
    end
end

function string.startswith(s, sub)
    local n = string.len(sub)
    return string.sub(s, 1, n) == sub
end

function string.endswith(s, sub)
    local n = string.len(sub)
    return string.sub(s, -n) == sub
end

local list = {
    iter = ipairs,
    insert = table.insert,
    remove = table.remove,
    unpack = table.unpack,
    concat = table.concat,
    sort = table.sort
}

local list_mt = {
    __index = list
}

function list:new(t)
    return setmetatable(t or {}, list_mt)
end

function list:pack(...)
    return setmetatable({ ... }, list_mt)
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

-- [[ logging utilities ]] --

_G.RECENT_EVENTS_LIMIT = 16
_G.recent_events = _G.recent_events or {}
local function addevent_(tstamp, msg)
    local n = recent_events["#"] or 0
    local i = recent_events["^"] or n
    local entry = recent_events[i]
    if entry and entry.msg == msg then
        entry.count = entry.count + 1
        entry.tstamp = tstamp
        return
    end
    i                = (i % RECENT_EVENTS_LIMIT) + 1
    recent_events[i] = {
        msg = msg,
        count = 1,
        tstamp = tstamp
    }
    if n < i then
        n = i
    end
    recent_events["^"], recent_events["#"] = i, n
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

local function parse_cidr(s)
    local addr, shift = s:match("^(.+)/(%d+)$")
    shift = tonumber(shift)
    if not shift or shift < 0 or shift > 32 then
        error(string.format("invalid prefix size %q", s), 2)
    end
    local mask = ~((1 << (32 - shift)) - 1)
    local subnet = parse_ipv4(addr)
    if not subnet or (subnet & mask ~= subnet) then
        error(string.format("invalid subnet %q", s), 2)
    end
    return subnet, shift
end

_G.parse_cidr = parse_cidr

local function parse_cidr6(s)
    local addr, shift = s:match("^(.+)/(%d+)$")
    shift = tonumber(shift)
    if not shift or shift < 0 or shift > 128 then
        error(string.format("invalid prefix size %q", s), 2)
    end
    local subnet1, subnet2 = parse_ipv6(addr)
    if shift > 64 then
        local mask = ~((1 << (128 - shift)) - 1)
        if not subnet1 or (subnet2 & mask ~= subnet2) then
            error(string.format("invalid subnet %q", s), 2)
        end
    else
        local mask = ~((1 << (64 - shift)) - 1)
        if not subnet1 or (subnet1 & mask ~= subnet1) or subnet2 ~= 0 then
            error(string.format("invalid subnet %q", s), 2)
        end
    end
    return subnet1, subnet2, shift
end

_G.parse_cidr6 = parse_cidr6

-- [[ RPC utilities ]] --

function _G.unmarshal(s)
    return assert(load("return " .. s, "=unmarshal"))()
end

local rpc = _G.rpc or {}
function rpc.echo(...)
    return ...
end

_G.rpc = rpc

function await.rpcall(target, func, ...)
    local code = string.format("return _G.rpc.%s(%s)", func, marshal(...))
    return await.invoke(code, table.unpack(target))
end

-- [[ _G.route table matchers ]] --
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

-- [[ _G.route6 table matchers ]] --
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

-- [[ _G.redirect* table matchers ]] --
local match = {}

function match.any(...)
    return function(addr)
        return true
    end
end

function match.exact(s)
    if type(s) ~= "table" then
        local host, port = splithostport(s)
        if not host or not port then
            error(string.format("exact matcher should contain host and port: %q", s), 2)
        end
        return function(addr)
            return addr == s
        end
    end
    local t = {}
    for _, v in pairs(s) do
        local host, port = splithostport(v)
        if not host or not port then
            error(string.format("exact matcher should contain host and port: %q", s), 2)
        end
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
    if type(from) ~= "table" then
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
    local t = {}
    for _, v in pairs(from) do
        t[tostring(v)] = true
    end
    return function(addr)
        local host, port = splithostport(addr)
        if not port then
            return false
        end
        return not not t[port]
    end
end

function match.domain(s)
    if type(s) ~= "table" then
        local suffix = s
        if s:startswith(".") then
            s = s:sub(2)
        else
            suffix = "." .. s
        end
        return function(addr)
            local host, port = splithostport(addr)
            if not host then
                return false
            end
            return host == s or host:endswith(suffix)
        end
    end
    local tree = {}
    for _, v in pairs(s) do
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
    if type(tree) ~= "table" then
        error("domain tree should be a table", 2)
    end
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

function composite.inverse(f)
    return function(...)
        return not f(...)
    end
end

function composite.anyof(t)
    return function(...)
        for i, matcher in ipairs(t) do
            if matcher(...) then
                return true
            end
        end
        return false
    end
end

function composite.maybe(t, k)
    return function(...)
        local matcher = t[k]
        if matcher then
            return matcher(...)
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

-- [[ load balancing actions ]] --
local lb = {}

function lb.roundrobin(t)
    local i, n = 0, #t
    return function(addr)
        i = i % n + 1
        return t[i]
    end
end

_G.lb = lb

-- [[ ruleset entrypoint functions ]] --
_G.num_requests = _G.num_requests or 0
_G.stat_requests = _G.stat_requests or list:new({ 0 })
_G.MAX_STAT_REQUESTS = 60

local function matchtab_(t, ...)
    for i, rule in ipairs(t) do
        local match, action, tag = table.unpack(rule)
        if match(...) then
            return action, tag
        end
    end
    return nil
end

local function default_(addr)
    local route = _G.route_default
    if route then
        local action, tag = table.unpack(route)
        if action then
            if tag then
                logf("[%s] %q", tag, addr)
            end
            return action(addr)
        end
    end
    return addr
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
    return default_(addr)
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
    return default_(addr)
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
    return default_(addr)
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
    local peak = math.max(0, requests:unpack())
    local q = math.max(1, peak)
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

function ruleset.resolve(addr)
    _G.num_requests = _G.num_requests + 1
    return resolve_(addr)
end

function ruleset.route(addr)
    _G.num_requests = _G.num_requests + 1
    return route_(addr)
end

function ruleset.route6(addr)
    _G.num_requests = _G.num_requests + 1
    return route6_(addr)
end

function ruleset.tick(now)
    stat_requests:insert(num_requests)
    if stat_requests[MAX_STAT_REQUESTS + 1] then
        stat_requests:remove(1)
    end
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
    local n = recent_events["#"] or 0
    local i = recent_events["^"] or n
    for _ = 1, n do
        local entry = recent_events[i]
        if not entry then
            break
        end
        local tstamp = os.date("%Y-%m-%dT%T%z", entry.tstamp)
        if entry.count == 1 then
            w:insertf("%s %s", tstamp, entry.msg)
        else
            w:insertf("%s %s (x%d)", tstamp, entry.msg, entry.count)
        end
        i = i - 1
        if i < 1 then i = n end
    end
    w:insert("> Request Stats")
    render_(w)
    w:insert("")
    return w:concat("\n")
end

return ruleset
