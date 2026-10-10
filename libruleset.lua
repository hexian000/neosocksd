-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ libruleset.lua: ruleset and RPC facilities ]] --
-- A live view over neosocksd.config(), never a snapshot: a "config" chunk (-c)
-- requires this module while the table it returns has not been applied yet, and
-- a reload replaces the configuration again later, so a table captured here
-- would answer with the pre-config values for the life of the process. Every
-- read reaches the configuration that is in effect right now.
--
-- The view is kept in an upvalue as well as published as _G.config: a ruleset
-- that assigns its own snapshot to the global must not silently turn the reads
-- below -- the credential policy among them -- back into stale ones.
local getconfig = neosocksd.config
local config = setmetatable({}, {
    __name = "config",
    __index = function(_, key)
        return getconfig()[key]
    end,
    __newindex = function()
        error("config is a read-only view of neosocksd.config()", 2)
    end,
    __pairs = function()
        return next, getconfig(), nil
    end,
})
_G.config = config

-- [[ useful library routines ]] --
local print = _G.print
local strformat = string.format

local function printf(...)
    return print(strformat(...))
end
_G.printf = printf

-- a fixed-length layout conforming to both ISO 8601 and RFC 3339
local function format_timestamp(t)
    local s = os.date("%FT%T%z", math.floor(t))
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
    if n > cap then
        -- seeding is equivalent to pushing each element in order, so an
        -- over-long seed keeps the newest cap elements and drops the rest
        table.move(t, n - cap + 1, n, 1)
        for i = cap + 1, n do
            t[i] = nil
        end
        n = cap
    end
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

-- Renders a string as a quoted literal for a log line. string.format's "%q"
-- escapes every byte that would otherwise break the line except the newline,
-- which it writes as a backslash followed by a real newline: one such byte in
-- a client-supplied name or user name would end the log line there and let the
-- peer append lines of its own.
local function quoted(s)
    return (strformat("%q", s):gsub("\\\n", "\\n"))
end

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

-- [[ asynchronous routines ]] --
local future = {}
local future_mt = { __name = "future", __index = future }

function future:get()
    -- unpack by the recorded count, not by #: a routine returning trailing
    -- nils packs a table with holes, whose length is undefined
    if self.result then
        return table.unpack(self.result, 1, self.result.n)
    end
    local co = coroutine.running()
    assert(coroutine.isyieldable(co))
    assert(self.co ~= co)
    self.wakeup[co] = true
    coroutine.yield()
    return table.unpack(self.result, 1, self.result.n)
end

function _G.async(f, ...)
    local t = setmetatable({ wakeup = {} }, future_mt)
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
        t.result = table.pack(false, err)
    end
    return t
end

function await.callback(f, ...)
    local co = coroutine.running()
    assert(coroutine.isyieldable(co))
    local result
    local callback = function(...)
        if co == coroutine.running() then
            result = table.pack(...)
            return
        end
        local ok, err = coroutine.resume(co, ...)
        if not ok then error(err) end
    end
    f(callback, ...)
    if result then
        return table.unpack(result, 1, result.n)
    end
    return coroutine.yield()
end

-- [[ RPC utilities ]] --
function _G.unmarshal(s)
    return assert(load("return " .. s, "=(unmarshal)", "t", {}))()
end

local rpc = _G.rpc or {}
function rpc.echo(...)
    return ...
end

_G.rpc = rpc

function await.rpcall(target, func, ...)
    -- %q (not %s) so func is spliced in as a quoted string literal and
    -- looked up via table indexing, never as raw code -- matches how
    -- marshal(...) already safely encodes the other arguments
    local code = strformat("return rpc[%q](%s)", func, marshal(...))
    local ok, result = await.invoke(code, table.unpack(target))
    if ok then return result() end
    return ok, result
end

local msgh = _G.msgh or {}
function msgh.nop(...)
end

_G.msgh = msgh

function neosocksd.sendmsg(target, func, ...)
    -- see await.rpcall above: %q + table indexing, not raw splicing
    local code = strformat("msgh[%q](%s)", func, marshal(...))
    return neosocksd.invoke(code, table.unpack(target))
end

-- [[ process a rule chain ]] --
local function runchain_(t, ...)
    for _, item in ipairs(t) do
        local matcher, action, tag = table.unpack(item)
        if action then
            -- { matcher, action, tag }
            if matcher(...) then
                return action, tag
            end
        else
            -- { functional matcher }
            action, tag = matcher(...)
            if action then return action, tag end
        end
    end
    return nil
end

-- routing decision functions (forward-declared): each returns the resolved
-- "addr, proxyN, ..., proxy1" or nil to reject
local default_, route_, route6_, resolve_


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

-- A host name is case-insensitive and a trailing dot only spells out the
-- implicit root label (RFC 1034, RFC 4343), so "foo.INTERNAL", "foo.internal."
-- and "foo.internal" all name the same host. match.exact/host/domain/
-- domaintree and the _G.hosts lookup in resolve_() therefore fold every name
-- to one spelling before comparing or indexing it -- the compiled match
-- table/tree as well as the incoming address, since normalizing one side alone
-- still misses -- so that a request can't dodge a reject/redirect rule by
-- spelling its target differently.
-- The case fold is ASCII-only, the way RFC 4343 defines name comparison.
-- string.lower() would fold through tolower(3), which follows the process
-- locale (the daemon calls setlocale(LC_ALL, "")): in a locale where "I" does
-- not fold to "i" (Turkish) it stops folding exactly the spellings these
-- matchers exist to catch, and a mapping outside 0-255 substitutes a different
-- byte instead. This is the call the C side already makes with
-- utils/ctype_ascii.h.
local lower_replacement = {}
for b = string.byte("A"), string.byte("Z") do
    lower_replacement[string.char(b)] = string.char(b + 0x20)
end

-- folds a bare host name
local function foldname(name)
    name = name:gsub("[A-Z]", lower_replacement)
    if name:endswith(".") then
        return name:sub(1, -2)
    end
    return name
end

-- Folds the host part of a "host:port" address in place: the root dot can
-- only be the last byte of a host name, so it stands directly before the port
-- separator. Rewriting in place keeps an IPv6 literal's brackets, which
-- splitting and rejoining would drop. Ports and IP-literal digits/separators
-- are unaffected, so this is safe for an "ip:port" literal as well.
local function foldaddr(addr)
    addr = addr:gsub("[A-Z]", lower_replacement)
    return (addr:gsub("%.:([^:]*)$", ":%1"))
end

function match.exact(s)
    if type(s) ~= "table" then
        local _, _ = splithostport(s)
        s = foldaddr(s)
        return function(addr)
            return foldaddr(addr) == s
        end
    end
    local t = {}
    for _, v in pairs(s) do
        local _, _ = splithostport(v)
        t[foldaddr(v)] = true
    end
    return function(addr)
        return not not t[foldaddr(addr)]
    end
end

function match.host(s)
    if type(s) ~= "table" then
        s = foldname(s)
        return function(addr)
            local host, _ = splithostport(addr)
            return foldname(host) == s
        end
    end
    local t = {}
    for _, v in pairs(s) do
        t[foldname(v)] = true
    end
    return function(addr)
        local host, _ = splithostport(addr)
        return t[foldname(host)] ~= nil
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
        s = foldname(s)
        local suffix = s
        if s:startswith(".") then
            s = s:sub(2)
        else
            suffix = "." .. s
        end
        return function(addr)
            local host, _ = splithostport(addr)
            host = foldname(host)
            return host == s or host:endswith(suffix)
        end
    end
    local tree = {}
    for _, v in pairs(s) do
        v = foldname(v)
        local path, n = {}, 0
        for seg in v:gmatch("[^.]+") do
            n = n + 1
            path[n] = seg
        end
        local t = tree
        for i = n, 2, -1 do
            local seg = path[i]
            local sub = t[seg]
            if sub == true then
                -- a shorter suffix already in the tree subsumes this entry
                t = nil
                break
            end
            if not sub then
                sub = {}
                t[seg] = sub
            end
            t = sub
        end
        -- in the reverse order an existing subtree is simply replaced by the
        -- terminal true, which subsumes every entry that was under it
        if t then
            t[path[1]] = true
        end
    end
    return match.domaintree(tree)
end

-- Note: match.domaintree() folds only the queried address, not `tree` itself
-- -- a manually-constructed tree (as opposed to one built by match.domain()
-- above, which already folds) should use lowercase keys to match
-- case-insensitively. A trailing dot needs no such care: splitting a name
-- into labels drops the empty root label, so no tree entry can spell it out.
function match.domaintree(tree)
    if type(tree) ~= "table" then
        error("domain tree should be a table", 2)
    end
    return function(addr)
        local host, _ = splithostport(addr)
        host = foldname(host)
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

-- provide basic compatibility for widely-used escape sequences
local escape_replacement = {
    ["\\d"] = "[0-9]",
    ["\\D"] = "[^0-9]",
    ["\\w"] = "[a-zA-Z0-9_]",
    ["\\W"] = "[^a-zA-Z0-9_]",
    ["\\s"] = "[[:space:]]",
    ["\\S"] = "[^[:space:]]",
}
function regex.compat(s)
    s = s:gsub("\\.", function(esc)
        return escape_replacement[esc] or esc
    end)
    return s
end

function match.regex(s)
    if type(s) ~= "table" then
        local reg = regex.compile(regex.compat(s))
        return function(addr)
            return not not reg:find(addr)
        end
    end
    local regs = {}
    for _, pat in pairs(s) do
        local ok, ret = pcall(regex.compile, regex.compat(pat))
        if ok then
            table.insert(regs, ret)
        else
            evlogf("%s: %s", ret, quoted(pat))
        end
    end
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

function composite.subchain(t, k)
    return function(...)
        local chain = t[k]
        if chain then
            return runchain_(chain, ...)
        end
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
        return default_(addr)
    end
end

function rule.resolve()
    return function(addr)
        -- await.resolve takes a bare hostname and returns a bare IP literal,
        -- so the port has to be split off first and joined back afterwards
        local host, port = splithostport(addr)
        local ip = await.resolve(host)
        if not ip then
            return nil
        end
        if parse_ipv4(ip) then
            return route_(strformat("%s:%s", ip, port))
        end
        if parse_ipv6(ip) then
            -- route6_ splits the address again, so bracket the literal
            return route6_(strformat("[%s]:%s", ip, port))
        end
        return resolve_(strformat("%s:%s", ip, port))
    end
end

function rule.redirect(dst, ...)
    local chain = list:new({ ... }):reverse()
    local host, port, _ = splithostport(dst)
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

function rule.maybe(t, k)
    return function(addr)
        local action = t[k]
        if action then
            return action(addr)
        end
        return nil
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
        addr = addr:gsub(pattern, repl)
        local host, _ = splithostport(addr)
        if parse_ipv4(host) then
            return route_(addr)
        end
        if parse_ipv6(host) then
            return route6_(addr)
        end
        return resolve_(addr)
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
-- Entries with a non-positive weight are excluded from rotation (e.g. to
-- drain a backend to zero) rather than corrupting the ratio math: a zero
-- max would otherwise divide every weight into NaN, which never satisfies
-- the dispatcher's comparison and spins forever.
function lb.iwrr(t, cyclesize)
    local max = 0
    for _, v in ipairs(t) do
        if v[1] > 0 then
            max = math.max(max, v[1])
        end
    end
    if max == 0 then
        return function(...) end
    end
    -- normalize into copies: the caller keeps its declared weights, which a
    -- second lb.iwrr over the same entries, or a renderer, still reads back
    local active = {}
    for _, v in ipairs(t) do
        if v[1] > 0 then
            table.insert(active, { v[1] / max, v[2] })
        end
    end
    local step = 0.01
    if cyclesize then step = 1 / cyclesize end
    local i, r, n = 0, 0, #active
    return function(...)
        repeat
            i = i % n + 1
        until r < active[i][1]
        r = r + step
        if r >= 1 then r = r - 1 end
        return active[i][2](...)
    end
end

_G.lb = lb

-- [[ ruleset entrypoint functions ]] --
_G.num_requests = _G.num_requests or 0
_G.num_authorized = _G.num_authorized or 0
_G.stat_requests = rlist:check(_G.stat_requests) or rlist:new(60, { _G.num_requests })

function default_(addr)
    local route = _G.route_default
    if route then
        local action, tag = table.unpack(route)
        if action then
            if tag then
                evlogf("[%s] %s", tag, quoted(addr))
            end
            return action(addr)
        end
    end
    return addr
end

function route_(addr)
    local redirtab = _G.redirect
    if redirtab then
        local action, tag = runchain_(redirtab, addr)
        if action then
            if tag then
                evlogf("[%s] %s", tag, quoted(addr))
            end
            return action(addr)
        end
    end
    local routetab = _G.route
    if routetab then
        local host, _ = splithostport(addr)
        local ip = parse_ipv4(host)
        local action, tag = runchain_(routetab, ip)
        if action then
            if tag then
                evlogf("[%s] %s", tag, quoted(addr))
            end
            return action(addr)
        end
    end
    return default_(addr)
end

function route6_(addr)
    local redirtab = _G.redirect6
    if redirtab then
        local action, tag = runchain_(redirtab, addr)
        if action then
            if tag then
                evlogf("[%s] %s", tag, quoted(addr))
            end
            return action(addr)
        end
    end
    local routetab = _G.route6
    if routetab then
        local host, _ = splithostport(addr)
        local ip1, ip2 = parse_ipv6(host)
        local action, tag = runchain_(routetab, ip1, ip2)
        if action then
            if tag then
                evlogf("[%s] %s", tag, quoted(addr))
            end
            return action(addr)
        end
    end
    return default_(addr)
end

-- resolve_() is reached with a name the client chose: a SOCKS5 DOMAINNAME is a
-- length-prefixed byte string (RFC 1928, 5) and an HTTP CONNECT request-target
-- is not validated before the ruleset sees it either, so the address is that
-- byte string with the port appended. A host name is letters, digits, hyphens
-- and dots (RFC 1035, 2.3.1; RFC 1123, 2.1), so it never holds a colon, and an
-- IPv6 literal is only unambiguous in brackets (RFC 3986, 3.2.2). A name
-- breaking either rule forms no "host:port" authority, and splithostport()
-- raises on it -- in the first rule of _G.redirect_name that reads the address,
-- if not in resolve_ itself. The daemon reports that as a ruleset error: one
-- error line per request carrying bytes the peer chose, plus a traceback under
-- --traceback.
-- Such a request is rejected rather than routed. The dialer parses an authority
-- the same way, so a name refused here could not have been dialed either, and
-- letting it through would only hand the default route an address that no rule
-- was able to match.
local function checkaddr(addr)
    local ok, host = pcall(splithostport, addr)
    if not ok or host == "" then
        return nil
    end
    -- splithostport() strips the brackets, so only the address itself still
    -- says whether the client wrote them
    if addr:startswith("[") and not parse_ipv6(host) then
        return nil
    end
    return addr
end

function resolve_(addr)
    if not checkaddr(addr) then
        evlogf("invalid address: %s", quoted(addr))
        return nil
    end
    local redirtab = _G.redirect_name
    if redirtab then
        local action, tag = runchain_(redirtab, addr)
        if action then
            if tag then
                evlogf("[%s] %s", tag, quoted(addr))
            end
            return action(addr)
        end
    end
    -- checkaddr() above already parsed this address, so the split cannot raise
    local host, port = splithostport(addr)
    -- _G.hosts is expected to be keyed by folded names, and an IP literal
    -- spelled with the root dot ("127.0.0.1.") still names that address, so
    -- the folded name is what decides the route as well
    local name = foldname(host)
    local hosts = _G.hosts
    if hosts then
        local entry = hosts[name]
        if entry then
            name = entry
            addr = strformat("%s:%s", name, port)
        end
    end
    -- route_/route6_ split the address again, so hand them one rebuilt from
    -- the literal they parse (an IPv6 literal bracketed, as splithostport
    -- requires); passing the unfolded spelling on would leave them with an
    -- unparsable address. A name that stays a name is passed on as the client
    -- spelled it, since the root dot also tells a resolver not to apply its
    -- search list.
    if parse_ipv4(name) then
        return route_(strformat("%s:%s", name, port))
    end
    if parse_ipv6(name) then
        return route6_(strformat("[%s]:%s", name, port))
    end
    return default_(addr)
end

local function render_(w)
    local total = 0
    local requests, n = list:new(), 0
    local last_requests
    for i = stat_requests.len, 1, -1 do
        local v = stat_requests:get(i)
        if last_requests then
            local delta = v - last_requests
            requests:insert(delta)
            total = total + delta
            n = n + 1
        end
        last_requests = v
    end
    last_requests = num_requests - last_requests
    requests:insert(last_requests)
    local avg, peak = last_requests, math.max(0, requests:unpack())
    if n > 0 then avg = total / n end
    w:insertf("> Request Stats (avg=%.1f/min, max=%d)", avg, peak)
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
    w:insertf("%s*", string.rep("-", n))
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
    evlogf("authenticate failed: %s", quoted(username))
    return false
end

-- The credential policy is selected per request, not once while this module
-- loads: the configuration that decides it is only applied after a "config"
-- chunk (-c) returns, and a reload may change it again. The C side reads the
-- same setting per request, so the two can never disagree.
local function with_authenticate(f)
    return function(addr, username, password)
        _G.num_requests = _G.num_requests + 1
        if config.auth_required and
            not authenticate(addr, username, password) then
            return nil
        end
        _G.num_authorized = _G.num_authorized + 1
        return f(addr)
    end
end

-- wrap a decision function to forward the request via await.forward()
local function forwarding(decide)
    return function(addr)
        return await.forward(decide(addr))
    end
end

ruleset.resolve = with_authenticate(forwarding(resolve_))
ruleset.route = with_authenticate(forwarding(route_))
ruleset.route6 = with_authenticate(forwarding(route6_))

-- the routing decision functions (return a decision; do not forward)
ruleset.decide = {
    resolve = resolve_,
    route = route_,
    route6 = route6_,
}

-- forward `addr` through each proxy chain until one connects; each chain is a
-- proxy-URI list (empty = direct). returns true on success, false if every
-- chain fails (the request is then rejected by policy).
function ruleset.failover(addr, chains)
    for _, chain in ipairs(chains) do
        if await.forward(addr, table.unpack(chain)) then
            return true
        end
    end
    return false
end

function ruleset.tick()
    stat_requests:push(num_requests)
end

_G.RECENT_EVENTS_STATS = _G.RECENT_EVENTS_STATS or 10
function ruleset.stats(dt)
    local w = list:new()
    w:insert("> Recent Events")
    for i = 1, _G.RECENT_EVENTS_STATS do
        local entry = recent_events:get(i)
        if not entry then break end
        local tstamp = format_timestamp(entry.tstamp)
        if entry.count == 1 then
            w:insertf("%s %s", tstamp, entry.msg)
        else
            w:insertf("%s %s (x%d)", tstamp, entry.msg, entry.count)
        end
    end
    render_(w)
    return w:concat("\n")
end

return ruleset
