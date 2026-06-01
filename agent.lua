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
-- agent.conn_state[id] = { peername, rtt_win } (local only)
agent.conn_state = table.get(_G.agent, "conn_state") or {}
-- agent.last_seen[peername] = monotonic seconds when the entry was last refreshed (local only)
agent.last_seen = table.get(_G.agent, "last_seen") or {}

local function connid_of(v)
    for id, conn in pairs(agent.conns) do
        if conn == v then
            return tostring(id)
        end
    end
    return "?"
end

-- _G.peerdb[peername] = { version = N, timestamp = T, hosts = { "host1", ... }, conns = { [id] = { peername = "peer1", rtt = 0 } } }
_G.peerdb = _G.peerdb or {}

agent.API_ENDPOINT = "api.neosocksd.internal:80"
agent.INTERNAL_DOMAIN = ".internal"
-- <host>.peerN.peer2.peer1.relay.neosocksd.internal
agent.RELAY_DOMAIN = ".relay.neosocksd.internal"

agent.BOOTSTRAP_DELAY = 10
-- fast probe loop: one round performs liveness + RTT + digest-pull anti-entropy
agent.PROBE_INTERVAL_BASE = 50
agent.PROBE_INTERVAL_RANDOM = 10
-- windowed minimum RTT window size in seconds (Kathleen Nichols, 2012)
agent.RTT_WINDOW = 600
-- only switch the chosen route when a candidate is at least this much faster
agent.ROUTE_HYSTERESIS = 0.2
-- expire a peer entry when not refreshed within this period (local clock only)
agent.PEERDB_EXPIRY_TIME = 60

agent.verbose = table.get(_G.agent, "verbose")

local strformat = string.format
local monotonic = time.monotonic

local function oneline(err)
    if not err then return "unknown" end
    err = tostring(err)
    return err:match("^(.-)\n") or err
end

-- windowed minimum filter (Kathleen Nichols, 2012)
-- win: array used as a monotone deque of {rtt, expiry} pairs
local function winmin_update(win, rtt, now)
    -- expire entries from the front
    while win[1] and win[1].expiry <= now do
        table.remove(win, 1)
    end
    -- drop dominated entries from the back
    local n = #win
    while n > 0 and win[n].rtt >= rtt do
        win[n] = nil
        n = n - 1
    end
    win[n + 1] = { rtt = rtt, expiry = now + agent.RTT_WINDOW }
    return win[1].rtt
end

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

local function build_index(peerdb, prev)
    prev = prev or {}
    local hosts = {}
    for peername, data in pairs(peerdb) do
        for _, host in pairs(data.hosts or {}) do
            hosts[host] = peername
        end
    end
    -- group direct conns by neighbor peername
    local bypeer = {}
    local selfinfo = peerdb[agent.peername] or {}
    for connid, conninfo in pairs(selfinfo.conns or {}) do
        local name = conninfo.peername
        local cands = bypeer[name]
        if not cands then
            cands = {}
            bypeer[name] = cands
        end
        cands[#cands + 1] = { conn = agent.conns[connid], rtt = conninfo.rtt }
    end
    -- pick the best conn per neighbor, with hysteresis toward the previous choice
    local peers = {}
    for name, cands in pairs(bypeer) do
        local best = cands[1]
        for i = 2, #cands do
            if cands[i].rtt < best.rtt then best = cands[i] end
        end
        local prevroute = prev[name]
        local prevconn = prevroute and #prevroute.path == 1 and prevroute.conn
        if prevconn then
            for _, c in ipairs(cands) do
                if c.conn == prevconn and
                    best.rtt >= c.rtt * (1 - agent.ROUTE_HYSTERESIS) then
                    best = c -- improvement below threshold, keep the previous conn
                    break
                end
            end
        end
        peers[name] = best
    end
    local routes = {}
    local paths = dijkstra(peerdb, agent.peername)
    for dest, info in pairs(paths) do
        local path     = info.path
        local peername = path[#path]
        local entry    = peername and peers[peername]
        if entry then
            routes[dest] = { conn = entry.conn, path = path, rtt = info.rtt }
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
            if addr == result then
                evlogf("agent [%s]: %s (passthrough)", connid_of(conn), addr)
            else
                evlogf("agent [%s]: %s -> %s", connid_of(conn), addr, result)
            end
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
    local proxies = list:new():append(conn):reverse()
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

local function apply_delta(from, delta)
    local changed = false
    local now = monotonic()
    for peer, data in pairs(delta) do
        if peer == agent.peername then
            -- ignore updates to self; this node owns its own entry
        elseif type(data) == "table" and type(data.version) == "number" then
            local old = _G.peerdb[peer]
            local is_newer = not old or data.version > old.version or
                (data.version == old.version and
                    type(data.timestamp) == "number" and
                    (not old.timestamp or data.timestamp > old.timestamp))
            if is_newer then
                _G.peerdb[peer] = data
                agent.last_seen[peer] = now
                changed = true
                if agent.verbose then
                    evlogf("peerdb: updated %q v%d from %q (time=%s)",
                        peer, data.version, from,
                        data.timestamp and format_timestamp(data.timestamp) or "?")
                end
            elseif data.version == old.version then
                agent.last_seen[peer] = now -- refresh liveness without a version change
            end
        end
    end
    return changed
end

local function expire(now)
    for peer, _ in pairs(_G.peerdb) do
        if peer ~= agent.peername then
            local seen = agent.last_seen[peer]
            if not seen or now - seen > agent.PEERDB_EXPIRY_TIME then
                evlogf("peer expired: %q", peer)
                _G.peerdb[peer] = nil
                agent.last_seen[peer] = nil
            end
        end
    end
end

-- a digest carries only versions: { [peername] = version }
local function build_digest()
    local digest = {}
    for peer, data in pairs(_G.peerdb) do
        digest[peer] = data.version
    end
    return digest
end

local function next_version()
    local selfinfo = _G.peerdb[agent.peername]
    local ver = selfinfo and selfinfo.version
    if type(ver) ~= "number" then
        return 1
    end
    return ver + 1
end


-- probe: cheap liveness check and RTT measurement; returns own digest so the
-- caller can decide whether a full rpc.sync is worth the extra round trip.
function rpc.probe(peername)
    if not agent.peername then
        error("peer is not available for relay")
    end
    return agent.peername, build_digest()
end

-- digest-pull: the caller sends its versions, the callee returns entries the
-- caller is missing or has an older version of. Because every link is probed
-- from both ends each interval, both directions converge without a separate
-- gossip fanout.
function rpc.sync(peername, digest)
    if not agent.peername then
        error("peer is not available for relay")
    end
    local delta = {}
    if type(digest) == "table" then
        for peer, data in pairs(_G.peerdb) do
            local known = digest[peer]
            if not known or data.version >= known then
                delta[peer] = data
            end
        end
    else
        for peer, data in pairs(_G.peerdb) do
            delta[peer] = data
        end
    end
    return agent.peername, delta
end

local function probe_via(conn)
    local digest = build_digest()
    local start = monotonic()
    local ok, peername, remote_digest = callbyconn(conn, "probe", agent.peername)
    local rtt = monotonic() - start
    if not ok then
        error(peername) -- holds the error message on failure
    end
    -- refresh last_seen immediately after confirming liveness via probe
    agent.last_seen[peername] = monotonic()
    -- only pull a full delta when remote has entries we are missing or behind on
    if type(remote_digest) == "table" then
        local needs_sync = false
        for peer, remote_ver in pairs(remote_digest) do
            local local_entry = _G.peerdb[peer]
            if not local_entry or local_entry.version < remote_ver then
                needs_sync = true
                break
            end
        end
        if needs_sync then
            local ok2, _, delta = callbyconn(conn, "sync", agent.peername, digest)
            if ok2 and type(delta) == "table" then
                apply_delta(peername, delta)
            end
        end
    end
    if agent.verbose then
        evlogf("probe: [%s] %q %.0fms", connid_of(conn), peername, rtt * 1e+3)
    end
    return { peername = peername, rtt = rtt }
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
    -- probe every conn: one round-trip yields liveness, an RTT sample, and a
    -- digest-pull delta that is merged into _G.peerdb
    local probe_results = {}
    parallel_for("probe", agent.conns, function(connid, conn)
        local ok, result = pcall(probe_via, conn)
        probe_results[connid] = { ok = ok, result = result }
    end)
    local now = monotonic()
    -- fold probe results into conn_state and build the advertised conns map
    local selfentry = agent.peername and _G.peerdb[agent.peername]
    local prev_conns = selfentry and selfentry.conns or {}
    local changed = not selfentry or selfentry.hosts ~= agent.hosts
    local conns = {}
    for connid, _ in pairs(agent.conns) do
        local r = probe_results[connid]
        local state = agent.conn_state[connid]
        if r and r.ok then
            local info = r.result
            local win = state and state.rtt_win or {}
            local rtt = winmin_update(win, info.rtt, now)
            agent.conn_state[connid] = {
                peername = info.peername,
                rtt_win = win,
            }
            conns[connid] = { peername = info.peername, rtt = rtt }
            local prev = prev_conns[connid]
            if not prev or prev.peername ~= info.peername then
                changed = true
            elseif prev.rtt > 0 then
                if math.abs(rtt - prev.rtt) / prev.rtt >= agent.ROUTE_HYSTERESIS then
                    changed = true
                end
            elseif prev.rtt ~= rtt then
                changed = true
            end
        elseif state then
            evlogf("conn lost: [%s] %q (%s)",
                tostring(connid), state.peername, oneline(r and r.result))
            agent.conn_state[connid] = nil
            if prev_conns[connid] then changed = true end
        else
            if prev_conns[connid] then changed = true end
            evlogf("probe error: [%s] %s", tostring(connid), oneline(r and r.result))
        end
    end
    -- drop state for connections that no longer exist
    for connid, _ in pairs(agent.conn_state) do
        if agent.conns[connid] == nil then
            agent.conn_state[connid] = nil
            if prev_conns[connid] then changed = true end
        end
    end
    -- expire peers not refreshed recently
    expire(now)
    -- update self entry when changed, bumping the version
    if agent.peername then
        if changed then
            _G.peerdb[agent.peername] = {
                version = next_version(),
                timestamp = os.time(),
                hosts = agent.hosts,
                conns = conns,
            }
        end
        agent.last_seen[agent.peername] = now
    end
    hosts, routes = build_index(_G.peerdb, routes)
    if agent.verbose then
        evlog("agent: probe round finished")
    end
end

local function mainloop()
    await.sleep(agent.BOOTSTRAP_DELAY)
    while agent.running do
        local ok, err = pcall(agent.maintenance)
        if not ok then
            evlogf("agent.maintenance: %s", oneline(err))
        end
        local update = table.get(_G, "ruleset", "update")
        if update then
            local ok, err = pcall(update)
            if not ok then
                evlogf("ruleset.update: %s", err)
            end
        end
        await.sleep(agent.PROBE_INTERVAL_BASE + math.random(agent.PROBE_INTERVAL_RANDOM))
    end
end

function agent.stats(dt)
    if not agent.running then return "" end
    local w = list:new()
    for peername, data in pairs(_G.peerdb) do
        local tag = strformat("%q", peername)
        local ts = data.timestamp and format_timestamp(data.timestamp) or "?"
        local route = routes[peername]
        if route then
            w:insertf("%-16s: %s [%s] %4.0fms %s", tag, ts,
                connid_of(route.conn), route.rtt * 1e+3, format_path(route.path))
        elseif peername ~= agent.peername then
            w:insertf("%-16s: %s (unreachable)", tag, ts)
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
