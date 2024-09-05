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

-- peerdb[peername] = { services = { "serv.internal" } }, timestamp = os.time() }
_G.peerdb = _G.peerdb or {}
-- _G.conninfo[connid] = { [peername] = { route = { peername, "peer1" }, rtt = 0, timestamp = os.time() } }
_G.conninfo = _G.conninfo or {}

local BOOTSTRAP_DELAY = 10
local SYNC_INTERVAL_BASE = 600
local SYNC_INTERVAL_RANDOM = 600
local PEERDB_TIMESTAMP_TOLERANCE = 600
local PEERDB_EXPIRY_TIME = 3600
local CONNINFO_EXPIRY_TIME = 3600

local function get_conninfo(connid, peername)
    local info = table.get(_G, "conninfo", connid, peername)
    if not info then return nil end
    if not info.timestamp then
        return info
    end
    local now = os.time()
    if now < info.timestamp + CONNINFO_EXPIRY_TIME then
        return info
    end
    return nil
end

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
    local peers, rtts = {}, {}
    for connid, conn in pairs(_G.conninfo) do
        for peername, info in pairs(conn) do
            local rtt = info.rtt or math.huge
            if not rtts[peername] or rtt < rtts[peername] then
                rtts[peername] = rtt
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

local function update_conninfo(connid, peername, route, rtt)
    local conn = _G.conninfo[connid] or {}
    if rtt then
        conn[peername] = { route = route, rtt = rtt, timestamp = os.time() }
    elseif not conn[peername] then
        conn[peername] = { route = route }
    end
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
    update_conninfo(connid, peername, bestroute, minrtt)
    return minrtt, bestroute
end

local function probe(peername)
    local minrtt, bestconnid, bestroute
    for connid, _ in pairs(agent.conns) do
        local rtt, route
        local info = get_conninfo(connid, peername)
        if info then
            rtt, route = info.rtt or math.huge, info.route
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
    update_conninfo(connid, peername, { peername })
end

local function update_self()
    local svclist = {}
    for service, _ in pairs(agent.services) do
        table.insert(svclist, service)
    end
    _G.peerdb[agent.peername] = {
        services = svclist,
        timestamp = os.time(),
    }
end

local function maintenance()
    await.sleep(BOOTSTRAP_DELAY)
    while agent.running do
        update_self()
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
