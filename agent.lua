_G.libruleset = require("libruleset")

local agent = {}

-- agent.peername = "peer0"
-- agent.conns[id] = { proxy1, proxy2, ... }
-- agent.services[service] = addr

agent.API_ENDPOINT = "api.neosocksd.internal:80"
agent.INTERNAL_DOMAIN = ".internal"

-- peerdb[peername] = { services = { "serv.internal" } }, timestamp = os.time() }
_G.peerdb = _G.peerdb or {}
-- _G.conninfo[connid] = { [peername] = { rtt = 0, route = { peername, "peer1" }, timestamp = os.time() } }
_G.conninfo = _G.conninfo or {}

local SYNC_INTERVAL_BASE = 600
local SYNC_INTERVAL_RANDOM = 600
local PEERDB_TIMESTAMP_TOLERANCE = 600
local PEERDB_EXPIRY_TIME = 3600
local CONNINFO_EXPIRY_TIME = 3600

local function build_services()
    local services = {}
    for peer, data in pairs(_G.peerdb) do
        for _, service in pairs(data.services) do
            services[service] = peer
        end
    end
    return services
end
local function build_peers()
    local peers, rtt = {}, {}
    for connid, conn in pairs(_G.conninfo) do
        for peername, info in pairs(conn) do
            if not rtt[peername] or info.rtt < rtt[peername] then
                rtt[peername] = info.rtt
                peers[peername] = connid
            end
        end
    end
    return peers
end
-- services[service] = peername
-- peers[peername] = connid
local services, peers = build_services(), build_peers()

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
    _G.peerdb[peername] = peerdb[peername]
    for peer, data in pairs(peerdb) do
        if data.timestamp < now + PEERDB_TIMESTAMP_TOLERANCE then
            local old = _G.peerdb[peer]
            if not old or data.timestamp > old.timestamp then
                _G.peerdb[peer] = data
                logf("peerdb: updated peer %q from %q", peer, peername)
            end
        else
            logf("peerdb: %q: invalid timestamp %d", peer, data.timestamp)
        end
    end
    for peer, data in pairs(_G.peerdb) do
        if data.timestamp + PEERDB_EXPIRY_TIME < now then
            _G.peerdb[peer] = nil
        end
    end
    services = build_services()
end


local function update_conninfo(connid, peername, rtt, route)
    local conn = _G.conninfo[connid] or {}
    conn[peername] = { rtt = rtt, route = route, timestamp = os.time() }
    _G.conninfo[connid] = conn
    peers = build_peers()
end

function rpc.sync(peername, peerdb)
    update_peerdb(peername, peerdb)
    return agent.peername, _G.peerdb
end

function rpc.probe(peername, ttl)
    if peername == agent.peername then
        return { peername }
    end
    ttl = ttl - 1
    if ttl < 1 then
        error("ttl expired in transit")
    end
    local connid = peers[peername]
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
    if not minrtt then
        return nil, lasterr
    end
    update_conninfo(connid, peername, minrtt, bestroute)
    return minrtt, bestroute
end

local function probe(peername)
    local now = os.time()
    local minrtt, bestconnid, bestroute
    for connid, _ in pairs(agent.conns) do
        local conn = _G.conninfo[connid] or {}
        local info = conn[peername]
        local rtt, route
        if info and now < info.timestamp + CONNINFO_EXPIRY_TIME then
            rtt, route = info.rtt, info.route
        else
            rtt, route = probe_via(connid, peername)
        end
        if rtt and (not minrtt or rtt < minrtt) then
            minrtt, bestconnid, bestroute = rtt, connid, route
        end
    end
    if not minrtt then
        return
    end
    local route = list:new():append(bestroute):reverse():map(function(s)
        return string.format("%q", s)
    end):concat("->")
    logf("probe: [%d] %s %.0fms", bestconnid, route, minrtt * 1e+3)
end

local function sync(connid)
    local ok, r1, r2 = callbyconn(connid, "sync", agent.peername, _G.peerdb)
    if not ok then
        logf("sync failed: connid=%d %s", connid, r1)
        return
    end
    local peername, peerdb = r1, r2
    update_peerdb(peername, peerdb)
end

local function bootstrap()
    await.idle()
    local svclist = {}
    for service, _ in pairs(agent.services) do
        table.insert(svclist, service)
    end
    _G.peerdb[agent.peername] = { services = svclist }
end

local function maintenance()
    await.sleep(10)
    bootstrap()
    while agent.running do
        _G.peerdb[agent.peername].timestamp = os.time()
        for connid, _ in pairs(agent.conns) do
            sync(connid)
        end
        log("agent: sync finished")
        for peername, _ in pairs(_G.peerdb) do
            if peername ~= agent.peername then
                probe(peername)
            end
        end
        log("agent: probe finished")
        await.sleep(SYNC_INTERVAL_BASE + math.random(SYNC_INTERVAL_RANDOM))
    end
end

function agent.stats(dt)
    local w = list:new()
    for peername, connid in pairs(peers) do
        local rtt = table.get(_G.conninfo, connid, peername, "rtt")
        if rtt then
            w:insertf("[%s] %.0fms", peername, rtt * 1e+3)
        end
    end
    return string.format("%-20s: %s", "Peer RTT", w:sort():concat(", "))
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
    async(maintenance)
    return agent
end

return main(...)
