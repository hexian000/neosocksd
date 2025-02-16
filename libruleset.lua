-- neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ libruleset.lua: rule set and RPC facilities ]] --
_G.config = neosocksd.config()

-- [[ useful library routines ]] --
local print = _G.print
local strformat = string.format

local function printf(...)
    return print(strformat(...))
end
_G.printf = printf

-- a fixed-length layout conforming to both ISO 8601 and RFC 3339
local function format_timestamp(t)
    local s = os.date("%FT%T%z", t)
    return s:sub(1, -3) .. ":" .. s:sub(-2, -1)
end
_G.format_timestamp = format_timestamp

function package.replace(modname, chunk)
    local module = chunk(modname)
    local loaded = package.loaded[modname]
    package.loaded[modname] = module
    if rawequal(_G[modname], loaded) then
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

function table.get(t, ...)
    local n = select('#', ...)
    local v = t
    for i = 1, n do
        if v == nil then return nil end
        v = v[select(i, ...)]
    end
    return v
end

-- [[ list: linear list ]] --
local list = {
    iter = ipairs,
    insert = table.insert,
    remove = table.remove,
    unpack = table.unpack,
    concat = table.concat,
}
local list_mt = { __name = "list", __index = list, }

function list:new(t)
    return setmetatable(t or {}, list_mt)
end

function list:check(t)
    local mt = getmetatable(t)
    if mt and mt.__name == list_mt.__name then
        return t
    end
    return nil
end

function list:totable()
    return setmetatable(self, nil)
end

function list:insertf(s, ...)
    return self:insert(strformat(s, ...))
end

function list:append(t)
    return table.move(t, 1, #t, #self + 1, self)
end

function list:map(f)
    for i, v in self:iter() do
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

function list:sort(...)
    table.sort(self, ...)
    return self
end

_G.list = list

-- [[ rlist: ring buffer ]] --
local rlist = {}
local rlist_mt = { __name = "rlist", __index = rlist }

function rlist:new(cap, t)
    t = t or {}
    local n = #t
    t.pos = n % cap + 1
    t.len = n
    t.cap = cap
    return setmetatable(t, rlist_mt)
end

function rlist:check(t)
    local mt = getmetatable(t)
    if mt and mt.__name == rlist_mt.__name then
        return t
    end
    return nil
end

function rlist:push(value)
    local pos = self.pos
    local len = self.len
    local cap = self.cap
    self[pos] = value
    self.pos  = (pos % cap) + 1
    if len < cap then
        self.len = len + 1
    end
end

function rlist:get(i)
    local len = self.len
    if 1 <= i and i <= len then
        local pos = self.pos - i
        if pos < 1 then
            pos = pos + len
        end
        return self[pos]
    end
    if -len <= i and i <= -1 then
        local pos = self.pos - (len + i + 1)
        if pos < 1 then
            pos = pos + len
        end
        return self[pos]
    end
    return nil
end

function rlist:next(i)
    local len = self.len
    if i then i = i + 1 else i = 1 end
    if 1 <= i and i <= len then
        local pos = self.pos - i
        if pos < 1 then
            pos = pos + len
        end
        return i, self[pos]
    end
    return nil, nil
end

function rlist:iter()
    return rlist.next, self, nil
end

_G.rlist = rlist

-- [[ logging utilities ]] --
_G.recent_events = rlist:check(_G.recent_events) or rlist:new(100)
local function evlog_(now, msg)
    local entry = recent_events:get(1)
    if entry and entry.msg == msg then
        entry.count = entry.count + 1
        entry.tstamp = now
        return
    end
    recent_events:push({
        msg = msg,
        count = 1,
        tstamp = now,
    })
end

local function log_(now, info, msg)
    if config.loglevel < 6 then
        return
    end
    local timestamp = format_timestamp(now)
    local source    = info.source:match("^@.-([^/]+)$") or info.short_src
    local line      = info.currentline
    return printf("D %s %s:%d %s", timestamp, source, line, msg)
end

local function log(...)
    local now  = os.time()
    local info = debug.getinfo(2, "Sl")
    local msg  = list:new({ ... }):map(tostring):concat("\t")
    return log_(now, info, msg)
end
_G.log = log

local function logf(s, ...)
    local now  = os.time()
    local info = debug.getinfo(2, "Sl")
    local msg  = strformat(s, ...)
    return log_(now, info, msg)
end
_G.logf = logf

local function evlog(...)
    local now  = os.time()
    local info = debug.getinfo(2, "Sl")
    local msg  = list:new({ ... }):map(tostring):concat("\t")
    evlog_(now, msg)
    return log_(now, info, msg)
end
_G.evlog = evlog

local function evlogf(s, ...)
    local now  = os.time()
    local info = debug.getinfo(2, "Sl")
    local msg  = strformat(s, ...)
    evlog_(now, msg)
    return log_(now, info, msg)
end
_G.evlogf = evlogf

-- [[ IP address utilities ]] --
local splithostport = neosocksd.splithostport
local parse_ipv4 = neosocksd.parse_ipv4
local parse_ipv6 = neosocksd.parse_ipv6

local function parse_cidr(s)
    local addr, shift = s:match("^(.+)/(%d+)$")
    shift = tonumber(shift)
    if not shift or shift < 0 or shift > 32 then
        error(strformat("invalid prefix size %q", s), 2)
    end
    local mask = ~((1 << (32 - shift)) - 1)
    local subnet = parse_ipv4(addr)
    if not subnet or (subnet & mask ~= subnet) then
        error(strformat("invalid subnet %q", s), 2)
    end
    return subnet, shift
end

_G.parse_cidr = parse_cidr

local function parse_cidr6(s)
    local addr, shift = s:match("^(.+)/(%d+)$")
    shift = tonumber(shift)
    if not shift or shift < 0 or shift > 128 then
        error(strformat("invalid prefix size %q", s), 2)
    end
    local subnet1, subnet2 = parse_ipv6(addr)
    if shift > 64 then
        local mask = ~((1 << (128 - shift)) - 1)
        if not subnet1 or (subnet2 & mask ~= subnet2) then
            error(strformat("invalid subnet %q", s), 2)
        end
    else
        local mask = ~((1 << (64 - shift)) - 1)
        if not subnet1 or (subnet1 & mask ~= subnet1) or subnet2 ~= 0 then
            error(strformat("invalid subnet %q", s), 2)
        end
    end
    return subnet1, subnet2, shift
end

_G.parse_cidr6 = parse_cidr6

-- [[ thread: asynchronous routines ]] --
local thread = {}
local thread_mt = { __name = "async", __index = thread }

function thread:wait()
    if self.result then
        return table.unpack(self.result)
    end
    local co = coroutine.running()
    assert(coroutine.isyieldable(co))
    assert(self.co ~= co)
    self.wakeup[co] = true
    coroutine.yield()
    return table.unpack(self.result)
end

function _G.async(f, ...)
    local t = setmetatable({ wakeup = {} }, thread_mt)
    local function finish(ok, ...)
        t.result = table.pack(ok, ...)
        for co, _ in pairs(t.wakeup) do
            t.wakeup[co] = nil
            coroutine.resume(co)
        end
    end
    local co, err = neosocksd.async(finish, f, ...)
    if co then
        t.co = co
    else
        t.result = { false, err }
    end
    return t
end

function await.callback(f, ...)
    local co = coroutine.running()
    assert(coroutine.isyieldable(co))
    local result
    local callback = function(...)
        if co == coroutine.running() then
            result = { ... }
            return
        end
        local ok, err = coroutine.resume(co, ...)
        if not ok then error(err) end
    end
    f(callback, ...)
    if result then
        return table.unpack(result)
    end
    return coroutine.yield()
end

-- [[ RPC utilities ]] --
function _G.unmarshal(s)
    return assert(load("return " .. s, "=(unmarshal)", "t", {}))()
end

local rpc = _G.rpc or {}
function rpc.echo(...)
    -- logf("rpc.echo(%s)", marshal(...))
    return ...
end

_G.rpc = rpc

function await.rpcall(target, func, ...)
    local code = strformat("return rpc.%s(%s)", func, marshal(...))
    local ok, result = await.invoke(code, table.unpack(target))
    if ok then return result() end
    return ok, result
end

local msgh = _G.msgh or {}
function msgh.nop(...)
    -- logf("msgh.nop(%s)", marshal(...))
end

_G.msgh = msgh

function neosocksd.sendmsg(target, func, ...)
    local code = strformat("msgh.%s(%s)", func, marshal(...))
    return neosocksd.invoke(code, table.unpack(target))
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
        local _, _ = splithostport(s)
        return function(addr)
            return addr == s
        end
    end
    local t = {}
    for _, v in pairs(s) do
        local _, _ = splithostport(v)
        t[v] = true
    end
    return function(addr)
        return not not t[addr]
    end
end

function match.host(s)
    if type(s) ~= "table" then
        return function(addr)
            local host, _ = splithostport(addr)
            return host == s
        end
    end
    local t = {}
    for _, v in pairs(s) do
        t[v] = true
    end
    return function(addr)
        local host, _ = splithostport(addr)
        return t[host] ~= nil
    end
end

function match.port(from, to)
    if type(from) ~= "table" then
        if not to then
            to = from
        end
        return function(addr)
            local _, s = splithostport(addr)
            local port = tonumber(s)
            if not port then
                return false
            end
            return from <= port and port <= to
        end
    end
    local t = {}
    for _, v in pairs(from) do
        t[tostring(v)] = true
    end
    return function(addr)
        local _, port = splithostport(addr)
        return t[port] ~= nil
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
            local host, _ = splithostport(addr)
            return host == s or host:endswith(suffix)
        end
    end
    local tree = {}
    for _, v in pairs(s) do
        local path, n = {}, 0
        for seg in v:gmatch("[^.]+") do
            n = n + 1
            path[n] = seg
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
        local host, _ = splithostport(addr)
        local path, n = {}, 0
        for seg in host:gmatch("[^.]+") do
            n = n + 1
            path[n] = seg
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
        for _, matcher in ipairs(t) do
            if matcher(...) then
                return true
            end
        end
        return false
    end
end

function composite.allof(t)
    return function(...)
        for _, matcher in ipairs(t) do
            if not matcher(...) then
                return false
            end
        end
        return true
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
    local chain = list:new({ ... }):reverse()
    local host, port = splithostport(dst)
    if host == "" then
        return function(addr)
            local host, _ = splithostport(addr)
            return strformat("%s:%s", host, port), chain:unpack()
        end
    end
    if port == "" then
        return function(addr)
            local _, port = splithostport(addr)
            return strformat("%s:%s", host, port), chain:unpack()
        end
    end
    return function(addr)
        return dst, chain:unpack()
    end
end

function rule.proxy(...)
    local chain = list:new({ ... }):reverse()
    return function(addr)
        return addr, chain:unpack()
    end
end

function rule.rewrite(pattern, repl, ...)
    local chain = list:new({ ... }):reverse()
    return function(addr)
        return addr:gsub(pattern, repl), chain:unpack()
    end
end

function rule.loopback(pattern, repl)
    return function(addr)
        local ruleset = table.get(_G, "ruleset")
        if not ruleset then
            return nil
        end
        addr = addr:gsub(pattern, repl)
        local host, _ = splithostport(addr)
        if parse_ipv4(host) then
            return ruleset.route(addr)
        end
        if parse_ipv6(host) then
            return ruleset.route6(addr)
        end
        return ruleset.resolve(addr)
    end
end

_G.rule = rule

-- [[ load balancing actions ]] --
local lb = {}

function lb.roundrobin(t)
    local i, n = 0, #t
    return function(...)
        i = i % n + 1
        return t[i](...)
    end
end

-- interleaved weighted round robin
function lb.iwrr(t, cyclesize)
    local max = 0
    for _, v in ipairs(t) do
        max = math.max(max, v[1])
    end
    for _, v in ipairs(t) do
        v[1] = v[1] / max
    end
    local step = 0.01
    if cyclesize then step = 1 / cyclesize end
    local i, r, n = 0, 0, #t
    return function(...)
        repeat
            i = i % n + 1
        until r < t[i][1]
        r = r + step
        if r >= 1 then r = r - 1 end
        return t[i][2](...)
    end
end

_G.lb = lb

-- [[ ruleset entrypoint functions ]] --
_G.num_requests = _G.num_requests or 0
_G.num_authorized = _G.num_authorized or 0
_G.stat_requests = rlist:check(_G.stat_requests) or rlist:new(60, { _G.num_requests })

local function matchtab_(t, ...)
    for _, item in ipairs(t) do
        local matcher, action, tag = table.unpack(item)
        if matcher(...) then
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
                evlogf("[%s] %q", tag, addr)
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
                evlogf("[%s] %q", tag, addr)
            end
            return action(addr)
        end
    end
    -- check route table
    local routetab = _G.route
    if routetab then
        local host, _ = splithostport(addr)
        local ip = parse_ipv4(host)
        local action, tag = matchtab_(routetab, ip)
        if action then
            if tag then
                evlogf("[%s] %q", tag, addr)
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
                evlogf("[%s] %q", tag, addr)
            end
            return action(addr)
        end
    end
    -- check route table
    local routetab = _G.route6
    if routetab then
        local host, _ = splithostport(addr)
        local ip1, ip2 = parse_ipv6(host)
        local action, tag = matchtab_(routetab, ip1, ip2)
        if action then
            if tag then
                evlogf("[%s] %q", tag, addr)
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
                evlogf("[%s] %q", tag, addr)
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
            addr = strformat("%s:%s", host, port)
        end
    end
    -- check if the addr is a raw address
    if parse_ipv4(host) then
        return route_(addr)
    end
    if parse_ipv6(host) then
        return route6_(addr)
    end
    -- global default
    return default_(addr)
end

local function render_(w)
    local requests, n = list:new(), 0
    local last_requests
    for i = stat_requests.len, 1, -1 do
        local v = stat_requests:get(i)
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
    for i, v in requests:iter() do
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
_G.secrets = _G.secrets or {}

local function authenticate(addr, username, password)
    local auth = table.get(_G, "ruleset", "authenticate")
    if auth then
        return auth(addr, username, password)
    end
    local s = table.get(_G, "secrets", username)
    if s and (s == true or s == password) then
        return true
    end
    evlogf("authenticate failed: %q", username)
    return false
end

local function with_authenticate(f)
    if not config.auth_required then
        -- authenticate is not required
        return function(addr, username, password)
            _G.num_requests = _G.num_requests + 1
            _G.num_authorized = _G.num_authorized + 1
            return f(addr)
        end
    end
    return function(addr, username, password)
        _G.num_requests = _G.num_requests + 1
        if not authenticate(addr, username, password) then
            return nil
        end
        _G.num_authorized = _G.num_authorized + 1
        return f(addr)
    end
end

ruleset.resolve = with_authenticate(resolve_)
ruleset.route = with_authenticate(route_)
ruleset.route6 = with_authenticate(route6_)

function ruleset.tick(now)
    stat_requests:push(num_requests)
end

function ruleset.stats(dt)
    local w = list:new()
    w:insert("> Recent Events")
    for i = 1, 10 do
        local entry = recent_events:get(i)
        if not entry then break end
        local tstamp = format_timestamp(entry.tstamp)
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
