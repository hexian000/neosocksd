-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ agent.lua: implements peer discovery and connection relay based on RPC ]] --
_G.libruleset = require("libruleset")

local agent = {}
agent.running = true

-- agent.peername = "peer0"
agent.peername = table.get(_G.agent, "peername")
-- agent.conns[id] = { proxy1, proxy2, ... }
agent.conns = table.get(_G.agent, "conns") or {}
-- agent.hosts = { "host1", "host2", ... }
agent.hosts = table.get(_G.agent, "hosts") or {}

local function connid_of(v)
    for id, conn in pairs(agent.conns) do
        if conn == v then return tostring(id) end
    end
    return "?"
end

-- _G.peerdb[peername] = { hosts = { hostname, "host1" }, conns = { [id] = { peername = "peer1", rtt = 0 } }, timestamp = os.time() }
_G.peerdb = _G.peerdb or {}

local API_ENDPOINT = "api.neosocksd.internal:80"
local INTERNAL_DOMAIN = ".internal"
-- <host>.peerN.peer2.peer1.relay.neosocksd.internal
local RELAY_DOMAIN = ".relay.neosocksd.internal"

local BOOTSTRAP_DELAY = 10
local SYNC_INTERVAL_BASE = 600
local SYNC_INTERVAL_RANDOM = 600
local TIMESTAMP_TOLERANCE = 600
local PEERDB_EXPIRY_TIME = 3600

agent.verbose = table.get(_G.agent, "verbose")

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

local function dijkstra(source)
    local nodes = {}
    for node, info in pairs(_G.peerdb) do
        nodes[node] = true
        if info.conns then
            for _, conn in pairs(info.conns) do
                nodes[conn.peername] = true
            end
        end
    end

    if not nodes[source] then return {} end

    local dist, prev, visited = {}, {}, {}
    for node, _ in pairs(nodes) do
        dist[node] = math.huge
        prev[node] = nil
        visited[node] = false
    end
    dist[source] = 0

    while true do
        -- find the unvisited node with the smallest distance
        local min_dist, u = math.huge, nil
        for node, _ in pairs(nodes) do
            if not visited[node] and dist[node] < min_dist then
                min_dist = dist[node]
                u = node
            end
        end

        -- all nodes visited or remaining nodes unreachable
        if not u then break end
        visited[u] = true

        -- update neighbor nodes' distance
        local u_info = _G.peerdb[u]
        if u_info and u_info.conns then
            for _, conn in pairs(u_info.conns) do
                local v = conn.peername
                local weight = conn.rtt
                if not visited[v] then
                    local alt = dist[u] + weight
                    if alt < dist[v] then
                        dist[v] = alt
                        prev[v] = u
                    end
                end
            end
        end
    end

    -- build relay paths
    local paths = {}
    for node, _ in pairs(nodes) do
        if node ~= source and dist[node] < math.huge then
            local path, n = { rtt = dist[node] }, 1
            local curr = node
            while curr ~= source do
                path[n] = curr
                n = n + 1
                curr = prev[curr]
            end
            paths[node] = path
        end
    end

    return paths
end

local function build_index()
    local hosts = setmetatable({}, { __mode = "kv" })
    for peername, data in pairs(_G.peerdb) do
        for _, host in pairs(data.hosts or {}) do
            hosts[host] = peername
        end
    end
    local peers = {}
    local peerinfo = _G.peerdb[agent.peername] or {}
    for connid, conninfo in pairs(peerinfo.conns or {}) do
        peers[conninfo.peername] = agent.conns[connid]
    end
    local paths = dijkstra(agent.peername)
    for _, path in pairs(paths) do
        local peername = path[#path]
        local conn     = peername and peers[peername]
        if conn then
            path.conn = conn
        else
            paths[peername] = nil
        end
    end
    return hosts, paths
end
-- hosts[hostname] = peername
-- routes[peername] = { rtt = rtt, conn = conn, peernameN, ..., peername2, peername1 }
local hosts, routes = build_index()

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
            local route = routes[peername]
            local conn = route and route.conn
            if not conn then
                evlogf("%q: peer not reachable", addr)
                return nil
            end
            addr = strformat("%s%s:%s", sub, domain, port)
            local proxies = list:new(conn):reverse()
            if agent.verbose then
                evlogf("relay: [%s] %s %s,%s", connid_of(conn), peername, addr, proxies:concat(","))
            end
            return addr, proxies:unpack()
        end
        sub = subdomain(fqdn, INTERNAL_DOMAIN)
        assert(sub)
        local peername = hosts[sub]
        assert(peername ~= nil and peername ~= agent.peername)
        local route = routes[peername]
        if not route then
            evlogf("peer %q is not reachable", peername)
            return nil
        end
        local t = list:new():append(route)
        peername = t[#t]
        local conn = route.conn
        t[1], t[#t] = sub, nil
        if peername ~= hosts[sub] then
            addr = strformat("%s%s:%s", t:concat("."), RELAY_DOMAIN, port)
        end
        local proxies = list:new(conn):reverse()
        if agent.verbose then
            evlogf("agent: [%s] %s %s,%s", connid_of(conn), peername, addr, proxies:concat(","))
        end
        return addr, proxies:unpack()
    end
end

local function format_route(route)
    return list:new():append(route):reverse():map(function(s)
        return strformat("%q", s)
    end):concat("->")
end

local function callbyconn(conn, func, ...)
    if not agent.running then
        error("cancelled")
    end
    local target = list:new():append(conn)
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
end

function rpc.sync(peername, peerdb)
    if type(peername) == "string" and type(peerdb) == "table" then
        update_peerdb(peername, peerdb)
        hosts, routes = build_index()
    end
    return agent.peername, _G.peerdb
end

local function sync_via(conn)
    local ok, r1, r2 = callbyconn(conn, "sync", agent.peername, _G.peerdb)
    if not ok then
        evlogf("sync failed: [%s] %s", connid_of(conn), r1)
        return
    end
    local peername, peerdb = r1, r2
    update_peerdb(peername, peerdb)
end

local function sync_all()
    local t = {}
    for connid, conn in pairs(agent.conns) do
        t[connid] = async(sync_via, conn)
    end
    for _, r in pairs(t) do
        local ok, err = r:get()
        if not ok then error(err) end
    end
end

function rpc.probe()
    if not agent.peername then
        error("peer is not available for relay")
    end
    return agent.peername
end

local function probe_via(connid)
    local conn = agent.conns[connid]
    local minrtt, peername, lasterr
    for _ = 1, 4 do
        await.sleep(1)
        local probe_start = time.monotonic()
        local ok, result = callbyconn(conn, "probe")
        local probe_end = time.monotonic()
        if ok then
            local rtt = probe_end - probe_start
            if not minrtt or rtt < minrtt then
                minrtt = rtt
            end
            peername = result
        else
            lasterr = result
        end
    end
    if not minrtt then
        evlogf("probe failed: [%s] %s", connid, lasterr:match("^(.-)\n") or lasterr)
        return nil
    end
    evlogf("probe: [%s] %q %.0fms", connid, peername, minrtt * 1e+3)
    return { peername = peername, rtt = minrtt }
end

local function probe_all()
    local t = {}
    for connid, _ in pairs(agent.conns) do
        t[connid] = async(probe_via, connid)
    end
    local conns = {}
    for connid, r in pairs(t) do
        local ok, result = r:get()
        if ok then
            if result then conns[connid] = result end
        else
            evlogf("probe error: [%d] %s", connid, result:match("^(.-)\n") or result)
        end
    end
    if agent.peername then
        local info = _G.peerdb[agent.peername] or {}
        info.conns = conns
        _G.peerdb[agent.peername] = info
    end
end

function agent.maintenance()
    -- sync to pull latest data
    sync_all()
    evlog("agent: sync finished")
    -- probe
    probe_all()
    evlog("agent: probe finished")
    -- update self
    if agent.peername then
        local info = _G.peerdb[agent.peername] or {}
        info.hosts = agent.hosts
        info.conns = info.conns or {}
        info.timestamp = os.time()
        _G.peerdb[agent.peername] = info
    end
    -- sync again to publish updates
    sync_all()
    -- remove stale data
    local now = os.time()
    for peername, data in pairs(_G.peerdb) do
        if not is_valid(data, PEERDB_EXPIRY_TIME, now) then
            evlogf("peer expired: %q (time=%d)", peername, data.timestamp - now)
            _G.peerdb[peername] = nil
        end
    end
    hosts, routes = build_index()
    evlog("agent: maintenance finished")
end

local function mainloop()
    await.sleep(BOOTSTRAP_DELAY)
    while agent.running do
        agent.maintenance()
        local update = table.get(_G, "ruleset", "update")
        if update then
            local ok, err = pcall(update)
            if not ok then
                evlogf("ruleset.update: %s", err)
            end
        end
        await.sleep(SYNC_INTERVAL_BASE + math.random(SYNC_INTERVAL_RANDOM))
    end
end

function agent.stats(dt)
    if not agent.running then return "" end
    local w = list:new()
    for peername, data in pairs(_G.peerdb) do
        local tag = strformat("%q", peername)
        local timestamp = format_timestamp(data.timestamp)
        local route = routes[peername]
        if route then
            w:insertf("%-16s: %s [%s] %4.0fms %s", tag, timestamp, connid_of(route.conn),
                route.rtt * 1e+3, format_route(route))
        elseif peername ~= agent.peername then
            w:insertf("%-16s: %s (unreachable)", tag, timestamp)
        end
    end
    local title = "> Peers"
    if agent.peername then
        title = title .. string.format(" (self=%q)", agent.peername)
    end
    return title .. "\n" .. w:sort():concat("\n")
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
    async(mainloop)
    return agent
end

return main(...)
