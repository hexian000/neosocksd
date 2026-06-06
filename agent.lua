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

local function connid_of(v)
    for id, conn in pairs(agent.conns) do
        if conn == v then
            return tostring(id)
        end
    end
    return "?"
end

-- _G.peerdb[peername] = { version = N, timestamp = T, hosts = { "host1", ... }, conns = { [id] = { peername = "peer1", rtt = 0 } } }
_G.peerdb                     = _G.peerdb or {}

agent.API_ENDPOINT            = "api.neosocksd.internal:80"
agent.INTERNAL_DOMAIN         = ".internal"
-- <host>.peerN.peer2.peer1.relay.neosocksd.internal
agent.RELAY_DOMAIN            = ".relay.neosocksd.internal"

agent.BOOTSTRAP_DELAY         = 10
-- adaptive probe interval: reset to MIN on any change, exponentially back
-- off to MAX when the topology is quiescent (jitter +/-10% applied each round)
agent.PROBE_INTERVAL_MIN      = 10
agent.PROBE_INTERVAL_MAX      = 600
agent.PROBE_BACKOFF           = 1.5
agent.PROBE_JITTER            = 0.1

local probe_interval          = agent.PROBE_INTERVAL_MIN

-- treat a conn as lost only after this many consecutive failed probes, so a
-- transient outage (e.g. a peer restarting) does not flap the route
agent.CONN_FAILURE_LIMIT      = 2
-- windowed minimum RTT window size in seconds (Kathleen Nichols, 2012)
agent.RTT_WINDOW              = 600
-- only switch the chosen route when a candidate is at least this much faster
agent.ROUTE_HYSTERESIS        = 0.2
-- expire a peer entry when its owner's wall-clock timestamp is older than
-- this threshold. Requires accurate system clock (NTP).
agent.PEERDB_EXPIRY_TIME      = 3600
-- additional tolerance for clock skew between peers (wall-clock based)
agent.PEERDB_EXPIRY_TOLERANCE = 600

agent.verbose                 = table.get(_G.agent, "verbose")

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
        return string.format("%q", s)
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
    local pre = fqdn:sub(1, -n - 1)
    if pre == "" then
        return nil
    end
    return pre
end

local ERR_UNKNOWN_HOST = "unknown host"
local ERR_NOT_REACHABLE = "peer not reachable"

local function resolve_internal(host, port)
    local peername = hosts[host]
    if not peername then
        return ERR_UNKNOWN_HOST
    end
    if peername == agent.peername then
        return nil
    end
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
        addr = string.format("%s%s:%s", host, agent.INTERNAL_DOMAIN, port)
    else
        addr = string.format("%s%s:%s", t:concat("."), agent.RELAY_DOMAIN, port)
    end
    return addr, conn
end

agent._subdomain = subdomain
agent._resolve_internal = resolve_internal

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
                    error(string.format("%s: %s", fqdn, result))
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

function agent.matcher(addr)
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
        if not result then
            return nil -- local host, pass to next handler
        end
        if not conn then
            error(string.format("%s: %s", fqdn, result))
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
        error(string.format("%q: %s", peername, ERR_NOT_REACHABLE)) -- break matching
    end
    addr = string.format("%s%s:%s", sub, domain, port)
    local conn = route.conn
    if agent.verbose then
        evlogf("relay [%s] %q: %s", connid_of(conn), peername, addr)
    end
    local proxies = list:new():append(conn):reverse()
    return function()
        return addr, proxies:unpack()
    end
end

agent.chain = { { agent.matcher } }

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
                -- version bump proves the owner is alive and has new data
                _G.peerdb[peer] = data
                changed = true
                if agent.verbose then
                    evlogf("peerdb: updated %q v%d from %q (time=%s)",
                        peer, data.version, from,
                        data.timestamp and format_timestamp(data.timestamp) or "?")
                end
                -- an older-or-equal entry carries no fresher timestamp, so it
                -- is ignored: only the owner's version bump (with a new
                -- wall-clock timestamp) can extend a peer's liveness
            end
        end
    end
    return changed
end

local function expire()
    local now = time.unix()
    local threshold = agent.PEERDB_EXPIRY_TIME + agent.PEERDB_EXPIRY_TOLERANCE
    for peer, data in pairs(_G.peerdb) do
        if peer ~= agent.peername then
            local age = now - (data.timestamp or 0)
            if age > threshold then
                evlogf("peer expired: %q (age=%ds)", peer, age)
                _G.peerdb[peer] = nil
            end
        end
    end
end

-- a digest carries versions and timestamps: { [peername] = { v = version, t = timestamp } }
local function build_digest()
    local digest = {}
    for peer, data in pairs(_G.peerdb) do
        digest[peer] = { v = data.version, t = data.timestamp }
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
            local known_ver = type(known) == "table" and known.v
            if not known_ver or data.version >= known_ver then
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
    local start = time.monotonic()
    local ok, peername, remote_digest = callbyconn(conn, "probe", agent.peername)
    local rtt = time.monotonic() - start
    if not ok then
        error(peername) -- holds the error message on failure
    end
    -- every successful probe proves the remote peer is alive
    do
        local entry = _G.peerdb[peername]
        if entry then
            entry.timestamp = time.unix()
        end
    end
    -- only pull a full delta when remote has entries we are missing or behind on;
    -- merge timestamps from digest independently of the sync decision
    local changed = false
    if type(remote_digest) == "table" then
        local needs_sync = false
        for peer, remote_info in pairs(remote_digest) do
            local remote_ver = remote_info.v
            local local_entry = _G.peerdb[peer]
            if local_entry then
                if local_entry.version < remote_ver then
                    needs_sync = true
                end
            elseif remote_ver then
                needs_sync = true
            end
            -- merge timestamps independently of sync decision
            local remote_ts = remote_info.t
            if peer ~= agent.peername and peer ~= peername and type(remote_ts) == "number" then
                local entry = _G.peerdb[peer]
                if entry and (not entry.timestamp or remote_ts > entry.timestamp) then
                    entry.timestamp = remote_ts
                end
            end
        end
        if needs_sync then
            local ok2, _, delta = callbyconn(conn, "sync", agent.peername, digest)
            if ok2 and type(delta) == "table" then
                changed = apply_delta(peername, delta)
            end
        end
    end
    if agent.verbose then
        evlogf("probe: [%s] %q %.0fms", connid_of(conn), peername, rtt * 1e+3)
    end
    return { peername = peername, rtt = rtt, changed = changed }
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
    local t = time.monotonic()
    -- fold probe results into conn_state and build the advertised conns map
    local selfentry = agent.peername and _G.peerdb[agent.peername]
    local prev_conns = selfentry and selfentry.conns or {}
    local changed = not selfentry or selfentry.hosts ~= agent.hosts
    local any_delta = false
    local conns = {}
    for connid, _ in pairs(agent.conns) do
        local r = probe_results[connid]
        local state = agent.conn_state[connid]
        if r and r.ok then
            local info = r.result
            if info.changed then
                any_delta = true
            end
            local win = state and state.rtt_win or {}
            local rtt = winmin_update(win, info.rtt, t)
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
            -- tolerate transient failures: only treat the conn as lost after
            -- CONN_FAILURE_LIMIT consecutive misses, so a brief outage (e.g. a
            -- peer restarting) does not flap the route
            local fails = (state.fails or 0) + 1
            if fails >= agent.CONN_FAILURE_LIMIT then
                evlogf("conn lost: [%s] %q (%s) [%d/%d]",
                    tostring(connid), state.peername, oneline(r and r.result),
                    fails, agent.CONN_FAILURE_LIMIT)
                agent.conn_state[connid] = nil
                if prev_conns[connid] then changed = true end
            else
                -- keep the last advertised entry so routing stays stable
                state.fails = fails
                conns[connid] = prev_conns[connid]
                evlogf("probe miss: [%s] %q (%s) [%d/%d]",
                    tostring(connid), state.peername, oneline(r and r.result),
                    fails, agent.CONN_FAILURE_LIMIT)
            end
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
    -- expire stale peer entries (wall-clock based)
    expire()
    -- update self entry when changed, bumping the version
    if agent.peername then
        if changed then
            _G.peerdb[agent.peername] = {
                version = next_version(),
                timestamp = time.unix(),
                hosts = agent.hosts,
                conns = conns,
            }
        end
    end
    hosts, routes = build_index(_G.peerdb, routes)
    if changed or any_delta then
        probe_interval = agent.PROBE_INTERVAL_MIN
    else
        probe_interval = math.min(probe_interval * agent.PROBE_BACKOFF, agent.PROBE_INTERVAL_MAX)
    end
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
        local jitter = probe_interval * agent.PROBE_JITTER * (math.random() * 2 - 1)
        await.sleep(probe_interval + jitter)
    end
end

function agent.stats(dt)
    if not agent.running then return "" end
    local w = list:new()
    for peername, data in pairs(_G.peerdb) do
        local tag = string.format("%q", peername)
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
    title = title .. string.format(" probe=%.0fs", probe_interval)
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
    if not table.get(_G, "agent", "passive") then
        async(mainloop)
    end
    return agent
end

return main(...)
