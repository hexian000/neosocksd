-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ agent.lua: implements peer discovery and connection relay based on RPC ]] --
_G.libruleset = require("libruleset")

local agent = {}
agent.running = true

agent.api_endpoint = "127.0.0.1:9080"
-- agent.peername = "peer0"
agent.peername = table.get(_G.agent, "peername")
-- agent.conns[id] = { proxy1, proxy2, ... }
agent.conns = table.get(_G.agent, "conns") or {}
-- agent.hosts = { "host1", "host2", ... }
agent.hosts = table.get(_G.agent, "hosts") or {}

local function connid_of(v)
    for id, conn in pairs(agent.conns) do
        if conn == v then
            return tostring(id)
        end
    end
    return "?"
end

-- _G.peerdb[peername] = { hosts = { hostname, "host1" }, conns = { [id] = { peername = "peer1", rtt = 0 } }, timestamp = os.time() }
_G.peerdb = _G.peerdb or {}

agent.API_ENDPOINT = "api.neosocksd.internal:80"
agent.INTERNAL_DOMAIN = ".internal"
-- <host>.peerN.peer2.peer1.relay.neosocksd.internal
agent.RELAY_DOMAIN = ".relay.neosocksd.internal"

agent.BOOTSTRAP_DELAY = 10
agent.SYNC_INTERVAL_BASE = 600
agent.SYNC_INTERVAL_RANDOM = 600
agent.TIMESTAMP_TOLERANCE = 600
agent.PEERDB_EXPIRY_TIME = 7200

agent.verbose = table.get(_G.agent, "verbose")

local function is_valid(data, now)
    local timestamp = data.timestamp
    return
        (type(timestamp) == "number")                 -- malformed peer data
        and
        (now - agent.PEERDB_EXPIRY_TIME < timestamp)  -- lower bound to expire peer data
        and
        (timestamp < now + agent.TIMESTAMP_TOLERANCE) -- upper bound to detect clock skew
end

local strformat = string.format
local function format_path(path)
    return list:new():append(path):reverse():map(function(s)
        return strformat("%q", s)
    end):concat("->")
end

local function dijkstra(peerdb, source)
    local nodes = {}
    for node, info in pairs(peerdb) do
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
        local u_info = peerdb[u]
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
            local path, n = {}, 1
            local curr = node
            while curr ~= source do
                path[n] = curr
                n = n + 1
                curr = prev[curr]
            end
            paths[node] = { path = path, rtt = dist[node] }
        end
    end

    return paths
end

local function build_index(peerdb)
    local hosts = {}
    for peername, data in pairs(peerdb) do
        for _, host in pairs(data.hosts or {}) do
            hosts[host] = peername
        end
    end
    local peers = {}
    local selfinfo = peerdb[agent.peername] or {}
    for connid, conninfo in pairs(selfinfo.conns or {}) do
        peers[conninfo.peername] = agent.conns[connid]
    end
    local routes = {}
    local paths = dijkstra(peerdb, agent.peername)
    for dest, info in pairs(paths) do
        local path     = info.path
        local peername = path[#path]
        local conn     = peername and peers[peername]
        if conn then
            routes[dest] = { conn = conn, path = path, rtt = info.rtt }
        end
    end
    return hosts, routes
end
-- hosts[hostname] = peername
-- routes[peername] = { conn = conn, path = { peernameN, ..., peername2, peername1 }, rtt = rtt }
local hosts, routes = build_index(_G.peerdb)

-- extracts subdomain from FQDN
local function subdomain(fqdn, domain)
    local n = domain:len()
    if fqdn:sub(-n) ~= domain then
        return nil
    end
    return fqdn:sub(1, -n - 1)
end

local ERR_UNKNOWN_HOST = "unknown host"
local ERR_NOT_REACHABLE = "peer not reachable"

local function resolve_internal(host, port)
    local peername = hosts[host]
    if not peername then
        return ERR_UNKNOWN_HOST
    end
    assert(peername ~= agent.peername)
    local route = routes[peername]
    if not route then
        return ERR_NOT_REACHABLE
    end
    local t = list:new():append(route.path)
    peername = t[#t]
    local conn = route.conn
    t[1], t[#t] = host, nil
    local addr
    if peername == hosts[host] then
        addr = strformat("%s%s:%s", host, agent.INTERNAL_DOMAIN, port)
    else
        addr = strformat("%s%s:%s", t:concat("."), agent.RELAY_DOMAIN, port)
    end
    return addr, conn
end

local splithostport = neosocksd.splithostport
function agent.proxy(...)
    local t = { ... }
    return function(addr)
        local chain = list:new()
        for i, proxy in ipairs(t) do
            if i == 1 then
                local proxyscheme, proxyaddr = proxy:match("^(%a[0-9A-Za-z+-.]*://)(.+)$")
                assert(proxyscheme and proxyaddr)
                local fqdn, port = splithostport(proxyaddr)
                local sub = subdomain(fqdn, agent.INTERNAL_DOMAIN)
                assert(sub)
                local result, conn = resolve_internal(sub, port)
                if not conn then
                    error(strformat("%s: %s", fqdn, result))
                end
                chain:append(conn)
                chain:insert(proxyscheme .. result)
            else
                chain:insert(proxy)
            end
        end
        return addr, chain:reverse():unpack()
    end
end

function agent.rpcall(addr, func, ...)
    return await.rpcall({ agent.proxy(addr)(agent.API_ENDPOINT) }, func, ...)
end

local function matcher(addr)
    if addr == agent.API_ENDPOINT then
        return function()
            return agent.api_endpoint
        end
    end
    local fqdn, port = splithostport(addr)
    local sub = subdomain(fqdn, agent.RELAY_DOMAIN)
    if not sub then
        sub = subdomain(fqdn, agent.INTERNAL_DOMAIN)
        if not sub then
            return nil -- unhandled
        end
        local result, conn = resolve_internal(sub, port)
        if not conn then
            error(strformat("%s: %s", fqdn, result))
        end
        if agent.verbose then
            evlogf("agent [%s]: %s -> %s", connid_of(conn), addr, result)
        end
        local proxies = list:new():append(conn):reverse()
        return function()
            return result, proxies:unpack()
        end
    end
    -- resolve relay
    local remain, peername = sub:match("^(.+)%.([^.]+)$")
    local domain
    if remain then
        sub = remain
        domain = agent.RELAY_DOMAIN
    else
        peername = hosts[sub]
        domain = agent.INTERNAL_DOMAIN
    end
    local route = routes[peername]
    if not route or #route.path ~= 1 then
        error(strformat("%q: %s", peername, ERR_NOT_REACHABLE)) -- break matching
    end
    addr = strformat("%s%s:%s", sub, domain, port)
    local conn = route.conn
    if agent.verbose then
        evlogf("relay [%s] %q: %s", connid_of(conn), peername, addr)
    end
    local proxies = list:new(conn):reverse()
    return function()
        return addr, proxies:unpack()
    end
end

agent.chain = { { matcher } }

local function callbyconn(conn, func, ...)
    if not agent.running then
        error("cancelled")
    end
    local target = list:new():append(conn)
    target:insert(agent.API_ENDPOINT)
    target = target:reverse():totable()
    return await.rpcall(target, func, ...)
end

local function update_peerdb(peername, peerdb)
    local now = os.time()
    -- remove stale data
    for peer, data in pairs(_G.peerdb) do
        if not is_valid(data, now) then
            evlogf("peer expired: %q (time=%d)", peer, data.timestamp - now)
            _G.peerdb[peer] = nil
        end
    end
    -- update peerdb
    for peer, data in pairs(peerdb) do
        if peer == peername then
            local old = _G.peerdb[peer]
            _G.peerdb[peer] = data
            if not old or data.timestamp ~= old.timestamp then
                evlogf("peerdb: updated peer %q (time=%d)",
                    peer, data.timestamp - now)
            end
        elseif peer == agent.peername then
            -- ignore updates to self
        elseif is_valid(data, now) then
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
    if type(peername) ~= "string" or type(peerdb) ~= "table" then
        return agent.peername, _G.peerdb
    end
    update_peerdb(peername, peerdb)
    hosts, routes = build_index(_G.peerdb)

    local peerdiff = {}
    for name, info in pairs(_G.peerdb) do
        if name ~= peername then
            local known = peerdb[name]
            if not known or known.timestamp ~= info.timestamp then
                peerdiff[name] = info
            end
        end
    end
    peerdiff[agent.peername] = _G.peerdb[agent.peername]
    return agent.peername, peerdiff
end

local function sync_via(conn)
    local ok, r1, r2 = callbyconn(conn, "sync", agent.peername, _G.peerdb)
    if not ok then
        error(r1)
    end
    local peername, peerdb = r1, r2
    update_peerdb(peername, peerdb)
end

function rpc.probe()
    if not agent.peername then
        error("peer is not available for relay")
    end
    return agent.peername
end

local function probe_via(conn)
    sync_via(conn)
    local minrtt, peername
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
            error(result)
        end
    end
    evlogf("probe: [%s] %q %.0fms", connid_of(conn), peername, minrtt * 1e+3)
    return { peername = peername, rtt = minrtt }
end

local function parallel_for(tag, t, func)
    local tasks = {}
    for k, v in pairs(t) do
        tasks[k] = async(func, k, v)
    end
    for k, future in pairs(tasks) do
        local ok, result = future:get()
        if not ok then
            evlogf("%s error: [%s] %s", tag, tostring(k), result:match("^(.-)\n") or result)
        end
    end
end

function agent.maintenance()
    -- probe
    local conns = {}
    parallel_for("probe", agent.conns, function(connid, conn)
        conns[connid] = probe_via(conn)
    end)
    -- update self
    if agent.peername then
        local info = _G.peerdb[agent.peername] or {}
        info.hosts = agent.hosts
        info.conns = conns
        info.timestamp = os.time()
        _G.peerdb[agent.peername] = info
    end
    evlog("agent: probe finished")
    -- sync
    parallel_for("sync", agent.conns, function(_, conn)
        sync_via(conn)
    end)
    evlog("agent: sync finished")
    hosts, routes = build_index(_G.peerdb)
    evlog("agent: maintenance finished")
end

local function mainloop()
    await.sleep(agent.BOOTSTRAP_DELAY)
    while agent.running do
        agent.maintenance()
        local update = table.get(_G, "ruleset", "update")
        if update then
            local ok, err = pcall(update)
            if not ok then
                evlogf("ruleset.update: %s", err)
            end
        end
        await.sleep(agent.SYNC_INTERVAL_BASE + math.random(agent.SYNC_INTERVAL_RANDOM))
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
                route.rtt * 1e+3, format_path(route.path))
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
