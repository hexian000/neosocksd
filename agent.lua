_G.libruleset = require("libruleset")

local agent = {}

-- agent.peername = "peer0"
agent.peername = table.get(_G.agent, "peername")
-- agent.conns[id] = { proxy1, proxy2, ... }
agent.conns = table.get(_G.agent, "conns") or {}
-- agent.hosts = { "host1", "host2", ... }
agent.hosts = table.get(_G.agent, "hosts") or {}

-- _G.peerdb[peername] = { hosts = { hostname, "host1" } }, timestamp = os.time() }
_G.peerdb = _G.peerdb or {}
-- _G.conninfo[connid] = { [peername] = { route = { peername, "peer1" }, rtt = 0, timestamp = os.time() } }
_G.conninfo = _G.conninfo or {}

local API_ENDPOINT = "api.neosocksd.internal:80"
local INTERNAL_DOMAIN = ".internal"
-- <host>.peerN.peer2.peer1.relay.neosocksd.internal
local RELAY_DOMAIN = ".relay.neosocksd.internal"

local BOOTSTRAP_DELAY = 10
local SYNC_INTERVAL_BASE = 600
local SYNC_INTERVAL_RANDOM = 600
local TIMESTAMP_TOLERANCE = 600
local PEERDB_EXPIRY_TIME = 3600

agent.probettl = table.get(_G.agent, "probettl") or 2

local function is_valid(t, expiry_time, now)
    local timestamp = t.timestamp
    if not timestamp then
        return t
    end
    if now < timestamp - TIMESTAMP_TOLERANCE then
        return nil
    end
    if timestamp + expiry_time < now then
        return nil
    end
    return t
end

local function build_index()
    local peers, peer_rtt = {}, {}
    if agent.peername then
        peer_rtt[agent.peername] = 0
    end
    for connid, conn in pairs(_G.conninfo) do
        for peername, info in pairs(conn) do
            local rtt = info.rtt or math.huge
            if not peer_rtt[peername] or rtt < peer_rtt[peername] then
                peer_rtt[peername] = rtt
                peers[peername] = connid
            end
        end
    end
    local hosts, host_rtt = {}, {}
    for peername, data in pairs(_G.peerdb) do
        for _, host in pairs(data.hosts or {}) do
            local rtt = peer_rtt[peername]
            if rtt then
                local knownrtt = host_rtt[host]
                if not knownrtt or rtt < knownrtt then
                    host_rtt[host] = rtt
                    hosts[host] = peername
                end
            elseif not hosts[host] then
                hosts[host] = peername
            end
        end
    end
    return hosts, peers
end
-- hosts[host] = peername
-- peers[peername] = connid
local hosts, peers = build_index()

local function subdomain(host, domain)
    local n = domain:len()
    if host:sub(-n) ~= domain then
        return nil
    end
    return host:sub(1, -n - 1)
end

local splithostport = neosocksd.splithostport
function match.agent()
    return function(addr)
        local fqdn, _ = splithostport(addr)
        if fqdn:endswith(RELAY_DOMAIN) then
            return true
        end
        local sub = subdomain(fqdn, INTERNAL_DOMAIN)
        if not sub then
            return false
        end
        local peername = hosts[sub]
        return peername ~= nil and peername ~= agent.peername
    end
end

local strformat = string.format
function rule.agent()
    return function(addr)
        local fqdn, port = splithostport(addr)
        local sub = subdomain(fqdn, RELAY_DOMAIN)
        if sub then
            local remain, peername = sub:match("^(.+)%.([^.]+)$")
            local domain
            if remain then
                sub = remain
                domain = RELAY_DOMAIN
            else
                peername = hosts[sub]
                domain = INTERNAL_DOMAIN
            end
            addr = strformat("%s%s:%s", sub, domain, port)
            local connid = peers[peername]
            local conn = agent.conns[connid]
            return addr, list:new(conn):reverse():unpack()
        end
        sub = subdomain(fqdn, INTERNAL_DOMAIN)
        assert(sub)
        local peername = hosts[sub]
        assert(peername ~= nil and peername ~= agent.peername)
        local connid = peers[peername]
        local route = table.get(_G.conninfo, connid, peername, "route")
        if not route then
            evlogf("%q: peer not reachable", peername)
            return nil
        end
        local t = list:new():append(route)
        peername = t[#t]
        connid = peers[peername]
        t[1], t[#t] = sub, nil
        if peername ~= hosts[sub] then
            addr = strformat("%s%s:%s", t:concat("."), RELAY_DOMAIN, port)
        end
        local conn = agent.conns[connid]
        return addr, list:new(conn):reverse():unpack()
    end
end

local function format_route(route)
    return list:new():append(route):reverse():map(function(s)
        return strformat("%q", s)
    end):concat("->")
end

local function callbyconn(connid, func, ...)
    if not agent.running then
        error("cancelled")
    end
    local target = list:new():append(agent.conns[connid])
    target:insert(API_ENDPOINT)
    target = target:reverse():totable()
    return await.rpcall(target, func, ...)
end

local function update_peerdb(peername, peerdb)
    local now = os.time()
    for peer, data in pairs(peerdb) do
        if peer == peername then
            _G.peerdb[peer] = peerdb[peer]
        elseif is_valid(data, PEERDB_EXPIRY_TIME, now) then
            local old = _G.peerdb[peer]
            if not old or data.timestamp > old.timestamp then
                _G.peerdb[peer] = data
                evlogf("peerdb: updated peer %q from %q (time=%d)",
                    peer, peername, data.timestamp - now)
            end
        end
    end
    hosts, peers = build_index()
end

function rpc.sync(peername, peerdb)
    if type(peername) == "string" and type(peerdb) == "table" then
        update_peerdb(peername, peerdb)
    end
    return agent.peername, _G.peerdb
end

function agent.sync(connid)
    assert(agent.conns[connid], strformat("unknown connid [%s]", connid))
    local ok, r1, r2 = callbyconn(connid, "sync", agent.peername, _G.peerdb)
    if not ok then
        evlogf("sync failed: [%s] %s", connid, r1)
        return
    end
    local peername, peerdb = r1, r2
    local conn = _G.conninfo[connid] or {}
    for peer, info in pairs(conn) do
        if info.route[#info.route] ~= peername then
            conn[peer] = nil
            evlogf("invalid route: [%s] %q %s", connid, peername, format_route(info.route))
        end
    end
    if not conn[peername] then
        conn[peername] = { route = { peername } }
    end
    _G.conninfo[connid] = conn
    update_peerdb(peername, peerdb)
end

local function findconn(peername, ttl)
    local connid, minrtt, bestroute
    for id, _ in pairs(agent.conns) do
        local info = table.get(_G.conninfo[id], peername)
        if info and #info.route <= ttl then
            local rtt = info.rtt or math.huge
            if not minrtt or rtt < minrtt then
                minrtt = rtt
                connid = id
                bestroute = info.route
            end
        end
    end
    return connid, minrtt, bestroute
end

function rpc.probe(peername, ttl)
    if not agent.peername then
        error("peer is not available for relay")
    end
    if type(peername) ~= "string" or math.type(ttl) ~= "integer" or
        ttl > 16 then
        error("invalid argument")
    end
    if peername == agent.peername then
        return { peername }
    end
    ttl = ttl - 1
    if ttl < 1 then
        error("ttl expired in transit")
    end
    local connid = findconn(peername, ttl)
    if not connid then
        error("peer not reachable")
    end
    local ok, result = callbyconn(connid, "probe", peername, ttl)
    if not ok then
        error(result)
    end
    table.insert(result, agent.peername)
    return result
end

local function probe_via(connid, peername)
    local minrtt, bestroute, err
    for _ = 1, 4 do
        await.sleep(1)
        local probe_start = neosocksd.now()
        local ok, result = callbyconn(connid, "probe", peername, agent.probettl)
        local probe_end = neosocksd.now()
        if ok then
            local rtt = probe_end - probe_start
            if not minrtt or rtt < minrtt then
                minrtt, bestroute = rtt, result
            end
        else
            err = result
        end
    end
    local result = nil
    if minrtt then
        result = { route = bestroute, rtt = minrtt, timestamp = os.time() }
        err = nil
    end
    local conn = _G.conninfo[connid] or {}
    conn[peername] = result
    _G.conninfo[connid] = conn
    hosts, peers = build_index()
    return err
end

function agent.probe(peername)
    assert(_G.peerdb[peername], strformat("unknown peer %q", peername))
    local errors = list:new()
    local t = {}
    for connid, _ in pairs(agent.conns) do
        t[connid] = async(probe_via, connid, peername)
    end
    for connid, r in pairs(t) do
        local ok, err = r:wait()
        if not ok then error(err) end
        if err then
            errors:insertf("[%s] %q", connid, err)
        end
    end
    if #errors < #agent.conns then
        local connid, minrtt, bestroute = findconn(peername, agent.probettl)
        evlogf("probe: [%s] %q %s %.0fms", connid, peername,
            format_route(bestroute), minrtt * 1e+3)
    elseif errors[1] then
        evlogf("probe failed: %q %s", peername, errors:sort():concat(", "))
    end
end

function agent.maintenance()
    -- update self
    if agent.peername then
        _G.peerdb[agent.peername] = {
            hosts = agent.hosts,
            timestamp = os.time(),
        }
    end
    -- sync
    for connid, _ in pairs(agent.conns) do
        agent.sync(connid)
    end
    evlog("agent: sync finished")
    -- probe
    for peername, _ in pairs(_G.peerdb) do
        if peername ~= agent.peername then
            agent.probe(peername)
        end
    end
    evlog("agent: probe finished")
    -- remove stale data
    local now = os.time()
    for peername, data in pairs(_G.peerdb) do
        if not is_valid(data, PEERDB_EXPIRY_TIME, now) then
            evlogf("peer expired: %q (time=%d)", peername, data.timestamp - now)
            _G.peerdb[peername] = nil
        end
    end
    for _, conn in pairs(_G.conninfo) do
        for peername, _ in pairs(conn) do
            if not _G.peerdb[peername] then
                conn[peername] = nil
            end
        end
    end
    hosts, peers = build_index()
end

local function mainloop()
    await.sleep(BOOTSTRAP_DELAY)
    while agent.running do
        agent.maintenance()
        await.sleep(SYNC_INTERVAL_BASE + math.random(SYNC_INTERVAL_RANDOM))
    end
end

function agent.stats(dt)
    if not agent.running then return "" end
    local w = list:new()
    for peername, data in pairs(_G.peerdb) do
        local tag = strformat("%q", peername)
        local timestamp = os.date("%Y-%m-%dT%T%z", data.timestamp)
        local connid, conn, info = peers[peername], nil, nil
        if connid then conn = _G.conninfo[connid] end
        if conn then info = conn[peername] end
        if info and info.rtt then
            w:insertf("%-16s: %s [%s] %4.0fms %s", tag, timestamp, connid,
                info.rtt * 1e+3, format_route(info.route))
        elseif peername ~= agent.peername then
            w:insertf("%-16s: %s no route", tag, timestamp)
        end
    end
    w:sort():insert(1, "> Peers")
    return w:concat("\n")
end

function agent.stop()
    agent.running = false
end

local function main(...)
    local stop = table.get(_G, "agent", "stop")
    if stop then
        local ok, err = pcall(stop)
        if not ok then
            evlogf("agent.stop: %s", err)
        end
    end
    agent.running = true
    async(mainloop)
    return agent
end

return main(...)
