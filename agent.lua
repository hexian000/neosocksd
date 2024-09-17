_G.libruleset = require("libruleset")

local agent = {}

-- agent.peername = "peer0"
agent.peername = table.get(_G, "agent", "peername")
-- agent.conns[id] = { proxy1, proxy2, ... }
agent.conns = table.get(_G, "agent", "conns")
-- agent.services[service] = addr
agent.services = table.get(_G, "agent", "services")

agent.API_ENDPOINT = "api.neosocksd.internal:80"
agent.INTERNAL_DOMAIN = ".internal"

-- _G.peerdb[peername] = { services = { "serv.internal" } }, timestamp = os.time() }
_G.peerdb = _G.peerdb or {}
-- _G.conninfo[connid] = { [peername] = { route = { peername, "peer1" }, rtt = 0, timestamp = os.time() } }
_G.conninfo = _G.conninfo or {}

local BOOTSTRAP_DELAY = 10
local SYNC_INTERVAL_BASE = 600
local SYNC_INTERVAL_RANDOM = 600
local TIMESTAMP_TOLERANCE = 600
local PEERDB_EXPIRY_TIME = 3600
local CONNINFO_EXPIRY_TIME = 3600

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
    local now = os.time()
    local peers, peer_rtt = {}, {}
    for connid, conn in pairs(_G.conninfo) do
        for peername, info in pairs(conn) do
            local rtt = info.rtt or math.huge
            if not peer_rtt[peername] or rtt < peer_rtt[peername] then
                peer_rtt[peername] = rtt
                peers[peername] = connid
            end
        end
    end
    local services, service_rtt = {}, {}
    for peername, data in pairs(_G.peerdb) do
        if is_valid(data, PEERDB_EXPIRY_TIME, now) then
            for _, service in pairs(data.services) do
                local rtt = peer_rtt[peername]
                if rtt then
                    local knownrtt = service_rtt[service]
                    if not knownrtt or rtt < knownrtt then
                        service_rtt[service] = rtt
                        services[service] = peername
                    end
                elseif not services[service] then
                    services[service] = peername
                end
            end
        end
    end
    return services, peers
end
-- services[service] = peername
-- peers[peername] = connid
local services, peers = build_index()

local splithostport = neosocksd.splithostport
function match.agent()
    return function(addr)
        local host, _ = splithostport(addr)
        if not host then
            return false
        end
        return host:endswith(agent.INTERNAL_DOMAIN)
    end
end

function rule.agent(peer)
    if peer then
        if peer == agent.peername then
            return function(addr)
                return addr
            end
        end
        return function(addr)
            local connid = peers[peer]
            local conn = agent.conns[connid]
            return addr, list:new(conn):reverse():unpack()
        end
    end
    return function(addr)
        local peername = services[addr]
        if not peername then
            return nil
        elseif peername == agent.peername then
            return agent.services[addr]
        end
        local connid = peers[peername]
        local conn = agent.conns[connid]
        return addr, list:new(conn):reverse():unpack()
    end
end

local function format_route(route)
    return list:new():append(route):reverse():map(function(s)
        return string.format("%q", s)
    end):concat("->")
end

local function callbyconn(connid, func, ...)
    if not agent.running then
        error("cancelled")
    end
    local target = list:new():append(agent.conns[connid])
    target:insert(agent.API_ENDPOINT)
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
                logf("peerdb: updated peer %q from %q (time=%d)",
                    peer, peername, data.timestamp - now)
            end
        end
    end
    services, peers = build_index()
end

function rpc.sync(peername, peerdb)
    update_peerdb(peername, peerdb)
    return agent.peername, _G.peerdb
end

function agent.sync(connid)
    assert(agent.conns[connid], string.format("unknown connid [%s]", connid))
    local ok, r1, r2 = callbyconn(connid, "sync", agent.peername, _G.peerdb)
    if not ok then
        logf("sync failed: [%s] %s", connid, r1)
        return
    end
    local peername, peerdb = r1, r2
    local conn = _G.conninfo[connid] or {}
    for peer, info in pairs(conn) do
        if info.route[#info.route] ~= peername then
            conn[peer] = nil
            logf("invalid route: [%s] %q %s", connid, peername, format_route(info.route))
        end
    end
    if not conn[peername] then
        conn[peername] = { route = { peername } }
    end
    _G.conninfo[connid] = conn
    update_peerdb(peername, peerdb)
end

local function find_conn(peername, ttl)
    local now = os.time()
    local connid, minrtt
    for id, _ in pairs(agent.conns) do
        local info = table.get(_G.conninfo, id, peername)
        if info and #info.route <= ttl then
            local rtt = info.rtt or math.huge
            if not minrtt or rtt < minrtt then
                minrtt = rtt
                connid = id
            end
        end
    end
    return connid
end

function rpc.probe(peername, ttl)
    if peername == agent.peername then
        return { peername }
    end
    ttl = ttl - 1
    if ttl < 1 then
        error("ttl expired in transit")
    end
    local connid = find_conn(peername, ttl)
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
    local lasterr
    local minrtt, bestroute
    for _ = 1, 4 do
        await.sleep(1)
        local probe_start = neosocksd.now()
        local ok, result = callbyconn(connid, "probe", peername, 2)
        local probe_end = neosocksd.now()
        if ok then
            local rtt = probe_end - probe_start
            if not minrtt or rtt < minrtt then
                minrtt, bestroute = rtt, result
            end
        else
            lasterr = result
        end
    end
    local conn = _G.conninfo[connid] or {}
    _G.conninfo[connid] = conn
    if not minrtt then
        if conn[peername] then
            conn[peername] = nil
            services, peers = build_index()
        end
        return nil, lasterr
    end
    conn[peername] = { route = bestroute, rtt = minrtt, timestamp = os.time() }
    services, peers = build_index()
    return minrtt, bestroute
end

function agent.probe(peername)
    assert(_G.peerdb[peername], string.format("unknown peer %q", peername))
    local now = os.time()
    local err = list:new()
    local updated
    local minrtt, bestconnid, bestroute
    for connid, _ in pairs(agent.conns) do
        local rtt, route
        local info = table.get(_G.conninfo, connid, peername)
        if info and info.rtt and is_valid(info, CONNINFO_EXPIRY_TIME, now) then
            rtt, route = info.rtt, info.route
        else
            rtt, route = probe_via(connid, peername)
            if not rtt then err:insertf("[%s] %q", connid, route) end
            updated = true
        end
        if rtt and (not minrtt or rtt < minrtt) then
            minrtt, bestconnid, bestroute = rtt, connid, route
        end
    end
    if not minrtt then
        logf("probe failed: %q %s", peername, err:concat(", "))
        return
    end
    if updated then
        logf("probe: [%s] %q %s %.0fms", bestconnid, peername,
            format_route(bestroute), minrtt * 1e+3)
    end
end

function agent.maintenance()
    local now = os.time()
    -- update self
    local svclist = {}
    for service, _ in pairs(agent.services) do
        table.insert(svclist, service)
    end
    _G.peerdb[agent.peername] = {
        services = svclist,
        timestamp = now,
    }
    services, peers = build_index()
    -- sync
    for connid, _ in pairs(agent.conns) do
        agent.sync(connid)
    end
    log("agent: sync finished")
    -- probe
    for peername, _ in pairs(_G.peerdb) do
        if peername ~= agent.peername then
            agent.probe(peername)
        end
    end
    log("agent: probe finished")
    -- remove stale data
    now = os.time()
    for peername, data in pairs(_G.peerdb) do
        if not is_valid(data, PEERDB_EXPIRY_TIME, now) then
            logf("peer expired: %q (time=%d)", peername, data.timestamp - now)
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
end

local function mainloop()
    await.sleep(BOOTSTRAP_DELAY)
    if not agent.peername then
        return
    end
    while agent.running do
        agent.maintenance()
        await.sleep(SYNC_INTERVAL_BASE + math.random(SYNC_INTERVAL_RANDOM))
    end
end

function agent.stats(dt)
    if not agent.running then return "" end
    local w = list:new()
    for peername, connid in pairs(peers) do
        local info = table.get(_G.conninfo, connid, peername)
        local tag = string.format("%q", peername)
        if info and info.rtt then
            w:insertf("%-16s: %s [%s] %4.0fms %s", tag, os.date("%Y-%m-%dT%T%z", info.timestamp),
                connid, info.rtt * 1e+3, format_route(info.route))
        else
            w:insertf("%-16s: [%s] no route", tag, connid)
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
            logf("agent.stop: %s", err)
        end
    end
    agent.running = true
    async(mainloop)
    return agent
end

return main(...)
