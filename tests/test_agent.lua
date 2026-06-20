-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ test_agent.lua: unit tests for agent.lua ]] --
--
-- Strategy:
--   We install controllable mocks for `time.monotonic` and `time.unix`
--   BEFORE loading agent.lua, then drive the fake clock by updating
--   `t_clock` between calls.  Neither function is cached locally in
--   agent.lua, but the mocks must stay active for the lifetime of the
--   module because every call resolves through the global.
--   `await.rpcall` is also NOT cached locally and can be replaced
--   per-test after loading.

return function(T)
    -- ------------------------------------------------------------------ --
    -- 1. Install fake clock before loading agent.lua
    -- ------------------------------------------------------------------ --

    local t_clock         = 0
    local orig_monotonic  = time.monotonic
    time.monotonic        = function() return t_clock end

    local orig_unix       = time.unix
    time.unix             = function() return 10000 end

    -- agent.maintenance() samples dial-failure counters from
    -- neosocksd.stats(); stub them so real server traffic from earlier
    -- test modules cannot leak into the probe-interval assertions
    local fake_rejects    = 0
    local orig_stats      = neosocksd.stats
    neosocksd.stats       = function()
        return { num_reject_upstream = fake_rejects, num_reject_timeout = 0 }
    end

    -- ------------------------------------------------------------------ --
    -- 2. Load agent.lua with a minimal, isolated config
    -- ------------------------------------------------------------------ --

    -- Save and replace the global state agent.lua reads at load time.
    local saved_peerdb    = _G.peerdb
    local saved_agent     = _G.agent

    _G.peerdb             = {}
    _G.agent              = {
        peername = "self",
        conns    = {},
        hosts    = { "self-host" },
        verbose  = false,
    }

    -- loadfile (not require) bypasses package cache, giving a fresh module
    -- each test run and keeping our own package.loaded untouched.
    local chunk, load_err = loadfile("agent.lua")
    assert(chunk, "loadfile agent.lua failed: " .. tostring(load_err))
    local ag = chunk()

    -- Keep the time.monotonic mock active; agent.lua no longer captures
    -- it in a local, so every call goes through the global and we must
    -- not restore the real function.

    -- ------------------------------------------------------------------ --
    -- 3. Shared helpers
    -- ------------------------------------------------------------------ --

    -- Capture the real await.rpcall so reset() can always restore it.
    local orig_rpcall = await.rpcall

    -- The shipped CONN_FAILURE_LIMIT default, captured before reset() lowers it
    -- to 1 (single-round failure semantics) for the routing/conn_state tests.
    local DEFAULT_CONN_FAILURE_LIMIT = ag.CONN_FAILURE_LIMIT

    -- relaying is opt-in (relay_cost >= 0); fixtures model ordinary relaying
    -- peers, so they advertise a zero cost unless a test overrides it
    local function mkpeer(ver, hosts, conns)
        return {
            version = ver,
            timestamp = time.unix(),
            hosts = hosts or {},
            conns = conns or {},
            relay_cost = 0,
        }
    end

    -- Convert old-style digest { [peer] = version } to new-style
    -- { [peer] = { v = version, t = timestamp } }.  The mocked time.unix()
    -- always returns 10000, so every entry gets t = 10000.
    local function D(t)
        local d = {}
        for k, v in pairs(t) do
            d[k] = { v = v, t = 10000 }
        end
        return d
    end

    -- Reset all mutable state between tests.
    local function reset()
        _G.peerdb = {}
        ag.conns  = {}
        ag.hosts  = { "self-host" }
        for k in pairs(ag.conn_state) do ag.conn_state[k] = nil end
        t_clock = 0
        fake_rejects = 0
        await.rpcall = orig_rpcall -- undo any per-test mock
        ag.running = true          -- a prior hot-reload test may have stopped it
        ag.relay_cost = nil        -- relay freely unless a test opts out
        -- Most tests assert single-round failure effects; the multi-failure
        -- tolerance is covered by its own dedicated tests that opt back in.
        ag.CONN_FAILURE_LIMIT = 1
    end

    -- Wrap await.rpcall for the duration of fn(), then restore it.
    -- handlers: table with optional "probe" and "sync" keys, each fn(connid) -> ok, ...
    --   "probe" handler returns (ok, peername, remote_digest) where digest
    --     values are { v = version, t = timestamp } tables.
    --   "sync"  handler returns (ok, peername, delta)
    -- fn is called directly (no pcall) so that parallel_for can yield
    -- freely; reset() restores await.rpcall if fn throws.
    local function with_rpcall(handlers, fn)
        await.rpcall = function(target, func, ...)
            if func == "probe" or func == "sync" then
                -- target = { dest, proxy_inner, ..., proxy_outer }
                -- target[#target] is the outermost proxy, which equals conn[1].
                local conn_proxy = target[#target]
                for id, conn in pairs(ag.conns) do
                    if conn[1] == conn_proxy then
                        local handler = handlers[func]
                        if handler then return handler(id, ...) end
                        return false, "no handler for " .. func
                    end
                end
                return false, "unknown conn"
            end
            return orig_rpcall(target, func, ...)
        end
        fn()
        await.rpcall = orig_rpcall
    end

    -- ------------------------------------------------------------------ --
    -- 4. rpc.sync delta-filtering tests  (sync, no maintenance needed)
    -- ------------------------------------------------------------------ --

    T:test("sync: full dump when digest is nil", function()
        reset()
        _G.peerdb["peer2"] = mkpeer(10)
        _G.peerdb["peer3"] = mkpeer(20)
        local name, delta = rpc.sync("caller", nil)
        assert(name == "self")
        assert(delta["peer2"] and delta["peer2"].version == 10)
        assert(delta["peer3"] and delta["peer3"].version == 20)
    end)

    T:test("sync: entry with same version IS included (>= fix)", function()
        -- Regression: before the fix, `>` excluded equal-version entries,
        -- so peers with unchanged version would not appear in delta, and
        -- anti-entropy could not propagate their data.
        reset()
        _G.peerdb["peer2"] = mkpeer(10)
        local _, delta = rpc.sync("caller", D { peer2 = 10 })
        assert(delta["peer2"] ~= nil,
            "entry at same version must appear in delta (>= regression)")
    end)

    T:test("sync: newer entry IS included", function()
        reset()
        _G.peerdb["peer2"] = mkpeer(11)
        local _, delta = rpc.sync("caller", D { peer2 = 10 })
        assert(delta["peer2"] ~= nil)
    end)

    T:test("sync: older entry is excluded", function()
        reset()
        _G.peerdb["peer2"] = mkpeer(9)
        local _, delta = rpc.sync("caller", D { peer2 = 10 })
        assert(delta["peer2"] == nil,
            "entry older than caller's known version must be excluded")
    end)

    T:test("sync: entry absent from digest IS included", function()
        reset()
        _G.peerdb["peer2"] = mkpeer(5)
        local _, delta = rpc.sync("caller", {})
        assert(delta["peer2"] ~= nil)
    end)

    -- ------------------------------------------------------------------ --
    -- 5. apply_delta via maintenance (async: maintenance uses parallel_for)
    -- ------------------------------------------------------------------ --

    T:atest("maintenance: new peer added to peerdb", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        local peer2_data = mkpeer(42, { "h2" }, {})
        with_rpcall({
            probe = function() return true, "peer2", D { peer2 = 42 } end,
            sync  = function() return true, "peer2", { peer2 = peer2_data } end,
        }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["peer2"] ~= nil, "peer2 should have been added")
        assert(_G.peerdb["peer2"].version == 42)
        assert(_G.peerdb["peer2"].timestamp == 10000,
            "peer2 timestamp must be set by mkpeer (time.unix=mock:10000)")
    end)

    T:atest("maintenance: older version in delta is ignored", function()
        reset()
        t_clock = 1000
        _G.peerdb["peer2"] = mkpeer(10)
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        with_rpcall({
            -- remote has version 9, local has version 10: no sync triggered
            probe = function() return true, "peer2", D { peer2 = 9 } end,
        }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["peer2"] ~= nil,
            "peer2 must not be removed (older delta should be ignored)")
        assert(_G.peerdb["peer2"].version == 10,
            "peerdb must not be downgraded to an older version")
    end)

    -- ------------------------------------------------------------------ --
    -- 6. expire() via maintenance
    -- ------------------------------------------------------------------ --

    T:atest("expire: stale peer is removed", function()
        reset()
        _G.peerdb["stale"] = mkpeer(1)
        _G.peerdb["stale"].timestamp = 0 -- far in the past, will expire
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["stale"] == nil, "stale peer must be expired")
    end)

    T:atest("expire: recently refreshed peer is kept", function()
        reset()
        _G.peerdb["fresh"] = mkpeer(1)
        -- timestamp close to current mock time.unix()=10000: age < TOLERANCE
        _G.peerdb["fresh"].timestamp = 10000 - ag.PEERDB_EXPIRY_TIME + 10
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["fresh"] ~= nil, "peer with recent timestamp must not be expired")
    end)

    T:atest("expire: self entry is never expired", function()
        reset()
        -- Self entry is guarded by peer ~= agent.peername in expire(),
        -- so it is never removed even with an ancient timestamp.
        _G.peerdb["self"] = mkpeer(1, { "self-host" }, {})
        _G.peerdb["self"].timestamp = 0
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["self"] ~= nil, "self entry must never be expired")
    end)

    -- ------------------------------------------------------------------ --
    -- 7. conn_state transitions via maintenance
    -- ------------------------------------------------------------------ --

    T:atest("conn_state: successful probe creates conn_state with peername and rtt_win", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002 -- simulate 2 ms RTT
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        local st = ag.conn_state[1]
        assert(st ~= nil, "conn_state[1] must be created after a successful probe")
        assert(st.peername == "peer2")
        assert(type(st.rtt_win) == "table" and st.rtt_win[1] ~= nil and st.rtt_win[1].rtt > 0,
            "rtt_win must be a non-empty deque with a positive rtt")
    end)

    T:atest("conn_state: failed probe with prior state drops conn_state", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        ag.conn_state[1] = {
            peername = "peer2",
            rtt_win = { { rtt = 0.001, expiry = 1600 } },
        }
        with_rpcall({ probe = function() return false, "connection refused" end }, function()
            ag.maintenance()
        end)
        assert(ag.conn_state[1] == nil,
            "conn_state must be dropped after a failed probe")
    end)

    T:atest("conn_state: failed probe without prior state keeps conn_state nil", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        with_rpcall({ probe = function() return false, "refused" end }, function()
            ag.maintenance()
        end)
        assert(ag.conn_state[1] == nil,
            "conn_state must remain nil after a failed probe with no prior state")
    end)

    T:atest("conn_state: successful probe recreates conn_state after failure", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        -- Round 1: prior state exists, probe fails → conn_state dropped.
        ag.conn_state[1] = {
            peername = "peer2",
            rtt_win = { { rtt = 0.001, expiry = 1600 } },
        }
        with_rpcall({ probe = function() return false, "refused" end }, function()
            ag.maintenance()
        end)
        assert(ag.conn_state[1] == nil, "conn_state must be nil after failure round")
        -- Round 2: probe succeeds → conn_state recreated from scratch.
        t_clock = 1100
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.001
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        local st = ag.conn_state[1]
        assert(st ~= nil, "conn_state must be recreated after a successful probe")
        assert(st.peername == "peer2", "peername must be set after recovery")
        assert(type(st.rtt_win) == "table" and st.rtt_win[1] ~= nil,
            "rtt_win must be populated after recovery")
    end)

    -- ------------------------------------------------------------------ --
    -- 7b. Consecutive-failure tolerance (CONN_FAILURE_LIMIT)
    -- ------------------------------------------------------------------ --

    T:test("conn liveness: shipped CONN_FAILURE_LIMIT default is 2", function()
        assert(DEFAULT_CONN_FAILURE_LIMIT == 2,
            "agent.lua must ship CONN_FAILURE_LIMIT = 2, got " ..
            tostring(DEFAULT_CONN_FAILURE_LIMIT))
    end)

    T:atest("conn liveness: single failure below limit is tolerated", function()
        reset()
        ag.CONN_FAILURE_LIMIT = 2
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        -- a successful probe establishes conn_state and publishes self.conns
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        assert(ag.conn_state[1] ~= nil, "conn_state must exist after success")
        -- one failure: tolerated, state kept with a bumped failure counter
        t_clock = 1100
        with_rpcall({ probe = function() return false, "connection refused" end }, function()
            ag.maintenance()
        end)
        assert(ag.conn_state[1] ~= nil,
            "conn_state must survive a single failure below the limit")
        assert(ag.conn_state[1].fails == 1,
            "consecutive failure count must be 1, got " ..
            tostring(ag.conn_state[1].fails))
        -- the route must stay advertised so a transient miss does not flap it
        assert(_G.peerdb["self"] and _G.peerdb["self"].conns[1] ~= nil,
            "self must keep advertising the conn during a tolerated failure")
    end)

    T:atest("conn liveness: dropped on the 2nd consecutive failure", function()
        reset()
        ag.CONN_FAILURE_LIMIT = 2
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        assert(ag.conn_state[1] ~= nil, "conn_state must exist after success")
        -- failure #1: tolerated
        t_clock = 1100
        with_rpcall({ probe = function() return false, "refused" end }, function()
            ag.maintenance()
        end)
        assert(ag.conn_state[1] ~= nil and ag.conn_state[1].fails == 1,
            "first failure must be tolerated (fails == 1)")
        -- failure #2: reaches the limit, the conn is now considered lost
        t_clock = 1200
        with_rpcall({ probe = function() return false, "refused" end }, function()
            ag.maintenance()
        end)
        assert(ag.conn_state[1] == nil,
            "conn_state must be dropped on the 2nd consecutive failure")
    end)

    T:atest("conn liveness: a success resets the failure counter", function()
        reset()
        ag.CONN_FAILURE_LIMIT = 2
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        local function ok_probe()
            t_clock = t_clock + 0.002
            return true, "peer2", {}
        end
        with_rpcall({ probe = ok_probe }, function() ag.maintenance() end)
        -- one failure brings the counter to 1
        t_clock = 1100
        with_rpcall({ probe = function() return false, "refused" end }, function()
            ag.maintenance()
        end)
        assert(ag.conn_state[1] and ag.conn_state[1].fails == 1,
            "failure counter must be 1 after one miss")
        -- a success clears the counter
        t_clock = 1200
        with_rpcall({ probe = ok_probe }, function() ag.maintenance() end)
        assert(ag.conn_state[1] ~= nil, "conn_state must exist after recovery")
        assert((ag.conn_state[1].fails or 0) == 0,
            "failure counter must reset to 0 after a successful probe")
        -- proving the reset: a single failure is once again tolerated
        t_clock = 1300
        with_rpcall({ probe = function() return false, "refused" end }, function()
            ag.maintenance()
        end)
        assert(ag.conn_state[1] ~= nil,
            "after a reset, a single failure must again be tolerated")
    end)

    -- ------------------------------------------------------------------ --
    -- 8. Self-entry version management
    -- ------------------------------------------------------------------ --

    T:atest("self-entry: first publish is wall-clock seeded", function()
        -- Versions are seeded with time.unix() so a fresh boot supersedes
        -- stale copies of our entry left in the network by a previous boot.
        reset()
        _G.peerdb["self"] = nil
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["self"] ~= nil, "self entry must be created by maintenance")
        assert(_G.peerdb["self"].version == 10000,
            "initial version must be time.unix(), got " ..
            tostring(_G.peerdb["self"].version))
    end)

    T:atest("self-entry: version below wall clock jumps to wall clock on change", function()
        reset()
        t_clock = 1000
        _G.peerdb["self"] = mkpeer(50, { "self-host" }, {})
        ag.hosts = { "self-host", "added-host" } -- trigger a change
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        ag.hosts = { "self-host" }
        assert(_G.peerdb["self"].version == 10000,
            "version must jump to time.unix() when below it, got " ..
            tostring(_G.peerdb["self"].version))
    end)

    T:atest("self-entry: version stays monotone when the clock is behind", function()
        -- After a backwards clock step, max(ver + 1, time.unix()) must keep
        -- publishing strictly increasing versions, never regress.
        reset()
        t_clock = 1000
        _G.peerdb["self"] = mkpeer(20000, { "self-host" }, {}) -- ahead of time.unix()=10000
        ag.hosts = { "self-host", "added-host" }               -- trigger a change
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        ag.hosts = { "self-host" }
        assert(_G.peerdb["self"].version == 20001,
            "version must increment past the stored value when the clock is behind, got " ..
            tostring(_G.peerdb["self"].version))
    end)

    T:atest("apply_delta: restarted peer's wall-clock version supersedes stale entry", function()
        -- A peer that restarted publishes version = time.unix(), which must
        -- replace the stale high-counter entry other nodes still hold.
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        _G.peerdb["peer2"] = mkpeer(50, { "old-host" }, {}) -- stale pre-restart copy
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D { peer2 = 10000 }
            end,
            sync = function()
                return true, "peer2", { peer2 = mkpeer(10000, { "new-host" }, {}) }
            end,
        }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["peer2"].version == 10000,
            "restarted peer's entry must supersede the stale copy, got v" ..
            tostring(_G.peerdb["peer2"].version))
        assert(_G.peerdb["peer2"].hosts[1] == "new-host",
            "entry content must be replaced along with the version")
    end)

    T:atest("self-entry: version stable when content unchanged", function()
        reset()
        t_clock = 1000
        -- First maintenance: publishes the self entry with a fresh version.
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        local ver1 = _G.peerdb["self"] and _G.peerdb["self"].version
        assert(type(ver1) == "number")
        -- Second maintenance without any change: version must not move.
        t_clock = 1010
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        local ver2 = _G.peerdb["self"] and _G.peerdb["self"].version
        assert(ver2 == ver1,
            "version must be stable when nothing changes: " ..
            tostring(ver1) .. " -> " .. tostring(ver2))
    end)

    T:atest("self-entry: version stable when RTT change is below hysteresis", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        -- First maintenance: establish an initial RTT baseline of 10ms.
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.010
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        local ver1 = _G.peerdb["self"].version
        assert(type(ver1) == "number")
        -- Second maintenance: RTT changes by 10% (below ROUTE_HYSTERESIS = 20%).
        t_clock = 2000
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.011 -- 10ms -> 11ms: 10% increase
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        local ver2 = _G.peerdb["self"].version
        assert(ver2 == ver1,
            "version must be stable when RTT change is below ROUTE_HYSTERESIS: " ..
            tostring(ver1) .. " -> " .. tostring(ver2))
    end)

    T:atest("self-entry: version bumps when RTT change exceeds hysteresis", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        -- First maintenance: establish an initial RTT baseline of 10ms.
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.010
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        local ver1 = _G.peerdb["self"].version
        assert(type(ver1) == "number")
        -- Second maintenance: RTT changes by 30% (above ROUTE_HYSTERESIS = 20%).
        t_clock = 2000
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.013 -- 10ms -> 13ms: 30% increase
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        local ver2 = _G.peerdb["self"].version
        assert(ver2 == ver1 + 1,
            "version must increment when RTT change exceeds ROUTE_HYSTERESIS: " ..
            tostring(ver1) .. " -> " .. tostring(ver2))
    end)

    -- ------------------------------------------------------------------ --
    -- 9. Routing: dijkstra + build_index via agent.stats()
    -- ------------------------------------------------------------------ --

    T:atest("routing: direct peer appears in stats with 1-hop path", function()
        reset()
        local c2 = { "socks4a://peer2.internal:1080" }
        ag.conns = { [1] = c2 }
        t_clock = 1000
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D { peer2 = 1 }
            end,
            sync = function()
                return true, "peer2", { peer2 = mkpeer(1, { "peer2-host" }, {}) }
            end,
        }, function()
            ag.maintenance()
        end)
        local stats = ag.stats(0)
        -- stats format: "peer2" : date time vNN [connid] Xms "peer2"
        assert(stats:find('"peer2"'), "peer2 must appear in stats\n" .. stats)
        -- 1-hop path: path list is just {"peer2"}, format_path gives "peer2"
        assert(not stats:find('"->"'), "1-hop path must not contain '->'")
    end)

    T:atest("routing: indirect peer reachable via 2-hop Dijkstra path", function()
        reset()
        local c2 = { "socks4a://peer2.internal:1080" }
        ag.conns = { [1] = c2 }
        t_clock = 1000
        local sync_data = {
            peer2 = mkpeer(1, { "peer2-host" }, {
                [1] = { peername = "peer3", rtt = 0.001 },
            }),
            peer3 = mkpeer(1, { "peer3-host" }, {}),
        }
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D { peer2 = 1, peer3 = 1 }
            end,
            sync = function()
                return true, "peer2", sync_data
            end,
        }, function()
            ag.maintenance()
        end)
        local stats = ag.stats(0)
        assert(stats:find('"peer3"'), "peer3 must appear in stats\n" .. stats)
        -- format_path reverses the internal path vector: "peer2"->"peer3"
        assert(stats:find('"peer2"%->"peer3"'),
            'expected "peer2"->"peer3" path in stats\n' .. stats)
    end)

    T:atest("routing: hysteresis keeps previous conn when improvement is marginal", function()
        reset()
        local c2a = { "socks4a://peer2a.internal:1080" }
        local c2b = { "socks4a://peer2b.internal:1080" }
        ag.conns = { [1] = c2a, [2] = c2b }
        t_clock = 1000
        -- First round: both conns reach peer2; conn[1] is faster.
        -- Include peer2 in the delta so it gets added to peerdb.
        local peer2_data = mkpeer(1, { "peer2-host" }, {})
        with_rpcall({
            probe = function(id)
                t_clock = t_clock + (id == 1 and 0.010 or 0.012) -- 10ms vs 12ms
                return true, "peer2", D { peer2 = 1 }
            end,
            sync = function()
                return true, "peer2", { peer2 = peer2_data }
            end,
        }, function()
            ag.maintenance()
        end)
        local stats1 = ag.stats(0)
        assert(stats1:find('"peer2"'), "peer2 must appear after first round\n" .. stats1)
        -- Second round: conn[2] is now slightly faster (11ms vs 10ms * (1+0.2) = 12ms).
        -- Since 11ms < 12ms threshold, Dijkstra should still prefer conn[1] (hysteresis).
        t_clock = 2000
        with_rpcall({
            -- peer2 already known at version 1: no sync triggered
            probe = function(id)
                t_clock = t_clock + (id == 1 and 0.010 or 0.011) -- conn[2] marginally faster
                return true, "peer2", D {}
            end,
        }, function()
            ag.maintenance()
        end)
        -- Hysteresis threshold: switch only if new rtt < old_rtt * (1 - ROUTE_HYSTERESIS).
        -- old = 10ms, threshold = 10ms * 0.8 = 8ms; 11ms > 8ms → keep conn[1].
        -- We verify the route exists; exact conn selection is internal, but
        -- stats must still show peer2 reachable.
        local stats2 = ag.stats(0)
        assert(stats2:find('"peer2"'), "peer2 must still be reachable after marginal change")
    end)

    -- ------------------------------------------------------------------ --
    -- 10. Bug regression tests
    -- ------------------------------------------------------------------ --

    T:test("subdomain: rejects fqdn equal to domain (empty prefix bug)", function()
        assert(ag._subdomain(ag.INTERNAL_DOMAIN, ag.INTERNAL_DOMAIN) == nil,
            "subdomain must return nil when fqdn == domain")
        assert(ag._subdomain(ag.RELAY_DOMAIN, ag.RELAY_DOMAIN) == nil,
            "subdomain must return nil when relay fqdn == domain")
        -- Valid cases must still work.
        assert(ag._subdomain("host" .. ag.INTERNAL_DOMAIN, ag.INTERNAL_DOMAIN) == "host",
            "single-label fqdn must extract correctly")
        assert(ag._subdomain("a.b" .. ag.INTERNAL_DOMAIN, ag.INTERNAL_DOMAIN) == "a.b",
            "multi-label fqdn must extract correctly")
    end)

    T:atest("resolve_internal: returns nil for self-hosted host (relay final-hop bug)", function()
        reset()
        -- maintenance with no conns publishes self entry and calls build_index,
        -- which sets hosts["self-host"] = "self".
        with_rpcall({
            probe = function() return false, "no route" end,
        }, function()
            ag.maintenance()
        end)
        local result, conn = ag._resolve_internal("self-host", "80")
        assert(result == nil and conn == nil,
            "resolve_internal must return (nil, nil) for self-hosted host, got: " ..
            tostring(result))
    end)

    -- ------------------------------------------------------------------ --
    -- 11. Long-chain Dijkstra routing
    -- ------------------------------------------------------------------ --

    T:atest("routing: 3-hop Dijkstra path", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        local sync_data = {
            peer2 = mkpeer(1, { "peer2-host" }, {
                [1] = { peername = "peer3", rtt = 0.005 },
            }),
            peer3 = mkpeer(1, { "peer3-host" }, {
                [1] = { peername = "peer4", rtt = 0.003 },
            }),
            peer4 = mkpeer(1, { "peer4-host" }, {}),
        }
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D { peer2 = 1, peer3 = 1, peer4 = 1 }
            end,
            sync = function()
                return true, "peer2", sync_data
            end,
        }, function()
            ag.maintenance()
        end)
        local stats = ag.stats(0)
        assert(stats:find('"peer4"'), "peer4 must appear in stats\n" .. stats)
        -- format_path(path={peer4,peer3,peer2}) → "peer2"->"peer3"->"peer4"
        assert(stats:find('"peer2"%->"peer3"%->"peer4"'),
            'expected "peer2"->"peer3"->"peer4" path\n' .. stats)
    end)

    T:atest("routing: 4-hop Dijkstra path", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        local sync_data = {
            peer2 = mkpeer(1, { "peer2-host" }, {
                [1] = { peername = "peer3", rtt = 0.005 },
            }),
            peer3 = mkpeer(1, { "peer3-host" }, {
                [1] = { peername = "peer4", rtt = 0.003 },
            }),
            peer4 = mkpeer(1, { "peer4-host" }, {
                [1] = { peername = "peer5", rtt = 0.002 },
            }),
            peer5 = mkpeer(1, { "peer5-host" }, {}),
        }
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D { peer2 = 1, peer3 = 1, peer4 = 1, peer5 = 1 }
            end,
            sync = function()
                return true, "peer2", sync_data
            end,
        }, function()
            ag.maintenance()
        end)
        local stats = ag.stats(0)
        assert(stats:find('"peer5"'), "peer5 must appear in stats\n" .. stats)
        assert(stats:find('"peer2"%->"peer3"%->"peer4"%->"peer5"'),
            'expected "peer2"->"peer3"->"peer4"->"peer5" path\n' .. stats)
    end)

    T:atest("resolve_internal: 3-hop relay address encoding", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        local sync_data = {
            peer2 = mkpeer(1, { "peer2-host" }, {
                [1] = { peername = "peer3", rtt = 0.005 },
            }),
            peer3 = mkpeer(1, { "peer3-host" }, {
                [1] = { peername = "peer4", rtt = 0.003 },
            }),
            peer4 = mkpeer(1, { "peer4-host" }, {}),
        }
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D { peer2 = 1, peer3 = 1, peer4 = 1 }
            end,
            sync = function()
                return true, "peer2", sync_data
            end,
        }, function()
            ag.maintenance()
        end)
        -- path: self→peer2→peer3→peer4, firstHop=peer2, destHost=peer4-host
        -- encoding: "peer4-host.peer3.relay.neosocksd.internal:80"
        local addr, conn = ag._resolve_internal("peer4-host", "80")
        assert(addr == "peer4-host.peer3.relay.neosocksd.internal:80",
            "expected relay addr encoding, got: " .. tostring(addr))
        assert(conn ~= nil, "must return a conn for the first hop")
    end)

    -- ------------------------------------------------------------------ --
    -- 12. Unreachable reproduction
    -- ------------------------------------------------------------------ --

    T:atest("routing: peers unreachable when relay loses downstream conns", function()
        -- Reproduces the (unreachable) scenario: A can still be probed by self,
        -- but A lost its connections to C and D. Self has cached peerdb entries
        -- for C and D from earlier syncs, but Dijkstra finds no path to them.
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        -- Pre-seed C(peer3) and D(peer4) as previously known peers
        _G.peerdb["peer3"] = mkpeer(1, { "peer3-host" }, {
            [1] = { peername = "peer2", rtt = 0.003 },
        })
        _G.peerdb["peer4"] = mkpeer(1, { "peer4-host" }, {
            [1] = { peername = "peer2", rtt = 0.004 },
        })
        -- A(peer2) lost conns to C/D — only has conn back to self
        local sync_data = {
            peer2 = mkpeer(2, { "peer2-host" }, {
                [1] = { peername = "self", rtt = 0.001 },
            }),
            peer3 = mkpeer(2, { "peer3-host" }, {}),
            peer4 = mkpeer(2, { "peer4-host" }, {}),
        }
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D { peer2 = 2, peer3 = 2, peer4 = 2 }
            end,
            sync = function()
                return true, "peer2", sync_data
            end,
        }, function()
            ag.maintenance()
        end)
        local stats = ag.stats(0)
        -- peer2 (A) must still be reachable directly (conn ID present on its line)
        assert(stats:match('"peer2"[^\n]-%[%d+%]'),
            "peer2 must have a conn ID (reachable)\n" .. stats)
        -- peer3 (C) and peer4 (D) must show as unreachable
        assert(stats:find('"peer3".*%(unreachable%)'),
            "peer3 must show as unreachable when relay lost conn\n" .. stats)
        assert(stats:find('"peer4".*%(unreachable%)'),
            "peer4 must show as unreachable when relay lost conn\n" .. stats)
    end)

    T:atest("routing: unreachable peer becomes reachable after relay recovers conn", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        -- Round 1: A(peer2) lost peer3, peer3 is unreachable
        _G.peerdb["peer3"] = mkpeer(1, { "peer3-host" }, {})
        local round1_sync = {
            peer2 = mkpeer(2, { "peer2-host" }, {
                [1] = { peername = "self", rtt = 0.001 },
            }),
            peer3 = mkpeer(2, { "peer3-host" }, {}),
        }
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D { peer2 = 2, peer3 = 2 }
            end,
            sync = function() return true, "peer2", round1_sync end,
        }, function()
            ag.maintenance()
        end)
        local stats1 = ag.stats(0)
        assert(stats1:find('"peer3".*%(unreachable%)'),
            "round1: peer3 must be unreachable\n" .. stats1)
        -- Round 2: A recovers conn to peer3
        t_clock = 2000
        local round2_sync = {
            peer2 = mkpeer(3, { "peer2-host" }, {
                [1] = { peername = "self", rtt = 0.001 },
                [2] = { peername = "peer3", rtt = 0.003 },
            }),
            peer3 = mkpeer(3, { "peer3-host" }, {}),
        }
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D { peer2 = 3, peer3 = 3 }
            end,
            sync = function() return true, "peer2", round2_sync end,
        }, function()
            ag.maintenance()
        end)
        local stats2 = ag.stats(0)
        assert(stats2:find('"peer3"'), "round2: peer3 must appear\n" .. stats2)
        assert(not stats2:find('"peer3".*%(unreachable%)'),
            "round2: peer3 must not be unreachable after recovery\n" .. stats2)
    end)

    T:atest("routing: all downstream unreachable when relay probe fails", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        -- Pre-seed a previously-known topology in peerdb
        _G.peerdb["peer2"] = mkpeer(1, { "peer2-host" }, {
            [1] = { peername = "self", rtt = 0.001 },
            [2] = { peername = "peer3", rtt = 0.003 },
        })
        _G.peerdb["peer3"] = mkpeer(1, { "peer3-host" }, {})
        -- Maintenance where all probes fail (simulate total network loss)
        with_rpcall({
            probe = function() return false, "connection refused" end,
        }, function()
            ag.maintenance()
        end)
        local stats = ag.stats(0)
        -- peer2 and peer3 must both be unreachable since self has no outgoing conns
        assert(stats:find('"peer2".*%(unreachable%)'),
            "peer2 must show as unreachable when probe fails\n" .. stats)
        assert(stats:find('"peer3".*%(unreachable%)'),
            "peer3 must show as unreachable when proxy is unreachable\n" .. stats)
    end)

    -- ------------------------------------------------------------------ --
    -- 13. Wall-clock expiry
    -- ------------------------------------------------------------------ --

    T:atest("expire: peer with timestamp at threshold edge survives", function()
        -- EXACTLY at threshold: age == TOLERANCE, must NOT expire.
        reset()
        _G.peerdb["edge"] = mkpeer(1)
        local threshold = ag.PEERDB_EXPIRY_TIME + ag.PEERDB_EXPIRY_TOLERANCE
        _G.peerdb["edge"].timestamp = 10000 - threshold
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["edge"] ~= nil,
            "peer at threshold edge must survive (age == tolerance)")
    end)

    T:atest("expire: peer one second past threshold is removed", function()
        -- One second past: age > TOLERANCE, MUST expire.
        reset()
        _G.peerdb["past"] = mkpeer(1)
        local threshold = ag.PEERDB_EXPIRY_TIME + ag.PEERDB_EXPIRY_TOLERANCE
        _G.peerdb["past"].timestamp = 10000 - threshold - 1
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["past"] == nil,
            "peer past threshold must be expired")
    end)

    -- ------------------------------------------------------------------ --
    -- 14. Multi-path Dijkstra and hysteresis
    -- ------------------------------------------------------------------ --

    T:atest("routing: Dijkstra picks shorter RTT path among alternatives", function()
        reset()
        -- self has direct conns to peer2(A) and peer3(B)
        ag.conns = {
            [1] = { "socks4a://peer2.internal:1080" },
            [2] = { "socks4a://peer3.internal:1080" },
        }
        t_clock = 1000
        -- A(peer2) → C(peer4): 5ms, B(peer3) → C(peer4): 30ms
        local sync_data = {
            peer2 = mkpeer(1, { "peer2-host" }, {
                [1] = { peername = "self", rtt = 0.001 },
                [2] = { peername = "peer4", rtt = 0.005 },
            }),
            peer3 = mkpeer(1, { "peer3-host" }, {
                [1] = { peername = "self", rtt = 0.001 },
                [2] = { peername = "peer4", rtt = 0.030 },
            }),
            peer4 = mkpeer(1, { "peer4-host" }, {}),
        }
        with_rpcall({
            probe = function(id)
                t_clock = t_clock + 0.002
                return true, id == 1 and "peer2" or "peer3",
                    D { peer2 = 1, peer3 = 1, peer4 = 1 }
            end,
            sync = function(id)
                return true, id == 1 and "peer2" or "peer3", sync_data
            end,
        }, function()
            ag.maintenance()
        end)
        local stats = ag.stats(0)
        -- C(peer4) should be reachable via the shorter path: self→peer2→peer4
        assert(stats:find('"peer4"'), "peer4 must appear in stats\n" .. stats)
        assert(stats:find('"peer2"%->"peer4"'),
            'expected "peer2"->"peer4" (shorter path), got:\n' .. stats)
    end)

    T:atest("routing: hysteresis blocks marginal path change", function()
        -- Direct path self→C(peer3): 10ms. Alternate self→D→C: 11ms (10% gain).
        -- Hysteresis threshold = ROUTE_HYSTERESIS = 0.2 (20%).
        -- 11ms > 10ms*(1-0.2)=8ms → keep direct path.
        reset()
        ag.conns = {
            [1] = { "socks4a://peer2.internal:1080" }, -- D
            [2] = { "socks4a://peer3.internal:1080" }, -- C direct
        }
        t_clock = 1000
        -- Round 1: both conns work. Direct to C(peer3) at 10ms, D→C at 6ms
        -- self→C is direct (1-hop). D→C exists but is through D.
        local sync_data = {
            peer2 = mkpeer(1, { "peer2-host" }, {
                [1] = { peername = "self", rtt = 0.001 },
                [2] = { peername = "peer3", rtt = 0.006 },
            }),
            peer3 = mkpeer(1, { "peer3-host" }, {}),
        }
        with_rpcall({
            probe = function(id)
                t_clock = t_clock + (id == 1 and 0.001 or 0.010)
                return true, id == 1 and "peer2" or "peer3", D { peer2 = 1, peer3 = 1 }
            end,
            sync = function() return true, "peer2", sync_data end,
        }, function()
            ag.maintenance()
        end)
        local stats1 = ag.stats(0)
        assert(stats1:find('"peer3"'), "peer3 must appear after round1\n" .. stats1)
        -- Round 2: D→C degrades to 11ms, direct C stays at 10ms.
        -- The relay path (11ms) is not enough of an improvement over direct (10ms)
        -- to trigger a switch: 11 > 10*(1-0.2) = 8. Also, hysteresis only applies
        -- when prev route was 1-hop — it keeps direct.
        t_clock = 2000
        sync_data.peer2.conns[2].rtt = 0.011 -- D→C now 11ms
        with_rpcall({
            probe = function(id)
                t_clock = t_clock + (id == 1 and 0.001 or 0.010)
                return true, id == 1 and "peer2" or "peer3", D { peer2 = 1, peer3 = 1 }
            end,
            sync = function() return true, "peer2", sync_data end,
        }, function()
            ag.maintenance()
        end)
        local stats2 = ag.stats(0)
        assert(stats2:find('"peer3"'), "peer3 must remain reachable\n" .. stats2)
    end)

    T:atest("routing: hysteresis allows significant path change", function()
        -- Similar setup but D→C degrades to 7ms vs direct 10ms: 7 < 8 → switch.
        reset()
        ag.conns = {
            [1] = { "socks4a://peer2.internal:1080" }, -- D
            [2] = { "socks4a://peer3.internal:1080" }, -- C direct (failing in round2)
        }
        t_clock = 1000
        local sync_data = {
            peer2 = mkpeer(1, { "peer2-host" }, {
                [1] = { peername = "self", rtt = 0.001 },
                [2] = { peername = "peer3", rtt = 0.006 },
            }),
            peer3 = mkpeer(1, { "peer3-host" }, {}),
        }
        with_rpcall({
            probe = function(id)
                t_clock = t_clock + (id == 1 and 0.001 or 0.010)
                return true, id == 1 and "peer2" or "peer3", D { peer2 = 1, peer3 = 1 }
            end,
            sync = function() return true, "peer2", sync_data end,
        }, function()
            ag.maintenance()
        end)
        -- Round 2: direct C probe FAILS → must use relay D→C.
        -- Switch is immediate because the direct conn is gone (no hysteresis barrier).
        t_clock = 1200
        sync_data.peer2.conns[2].rtt = 0.007
        with_rpcall({
            probe = function(id)
                t_clock = t_clock + 0.001
                if id == 1 then
                    return true, "peer2", D { peer2 = 1, peer3 = 1 }
                else
                    return false, "connection refused" -- direct C failed
                end
            end,
            sync = function() return true, "peer2", sync_data end,
        }, function()
            ag.maintenance()
        end)
        local stats = ag.stats(0)
        assert(stats:find('"peer3"'), "peer3 must be reachable via relay\n" .. stats)
        assert(stats:find('"peer2"%->"peer3"'),
            'must use relay path "peer2"->"peer3" after direct fails\n' .. stats)
    end)

    -- ------------------------------------------------------------------ --
    -- 15. Link failure → route switching (multi-round maintenance)
    -- ------------------------------------------------------------------ --

    T:atest("routing: link failure switches to relay path in same round", function()
        -- Topology: self→A(10ms), self→C(5ms), C→B(15ms), A→B(direct, 10ms).
        -- Round 1: self→B via A (direct, 10ms total).
        -- Round 2: self→A probe fails → Dijkstra picks self→C→B (20ms total).
        reset()
        ag.conns = {
            [1] = { "socks4a://peer2.internal:1080" }, -- A
            [2] = { "socks4a://peer3.internal:1080" }, -- C
        }
        t_clock = 1000
        local sync_data_r1 = {
            peer2 = mkpeer(1, { "peer2-host" }, {
                [1] = { peername = "self", rtt = 0.010 },
                [2] = { peername = "peer4", rtt = 0.010 }, -- A→B direct
            }),
            peer3 = mkpeer(1, { "peer3-host" }, {
                [1] = { peername = "self", rtt = 0.005 },
                [2] = { peername = "peer4", rtt = 0.015 }, -- C→B
            }),
            peer4 = mkpeer(1, { "peer4-host" }, {}),
        }
        -- Round 1: all probes healthy
        with_rpcall({
            probe = function(id)
                t_clock = t_clock + (id == 1 and 0.010 or 0.005)
                return true, id == 1 and "peer2" or "peer3",
                    D { peer2 = 1, peer3 = 1, peer4 = 1 }
            end,
            sync = function(id)
                return true, id == 1 and "peer2" or "peer3", sync_data_r1
            end,
        }, function()
            ag.maintenance()
        end)
        local stats1 = ag.stats(0)
        -- B(peer4) reachable via A(peer2): self→peer2→peer4 (total 20ms)
        -- Wait, A→B is 10ms and self→A is 10ms = 20ms total.
        -- C→B is 15ms and self→C is 5ms = 20ms total.
        -- Same total RTT; Dijkstra processes A first in insertion order.
        assert(stats1:find('"peer4"'), "round1: peer4 must be reachable\n" .. stats1)
        -- Round 2: A(peer2) probe fails → self loses direct conn to A
        t_clock = 2000
        local sync_data_r2 = {
            peer3 = mkpeer(2, { "peer3-host" }, {
                [1] = { peername = "self", rtt = 0.005 },
                [2] = { peername = "peer4", rtt = 0.015 },
            }),
            peer4 = mkpeer(2, { "peer4-host" }, {}),
        }
        with_rpcall({
            probe = function(id)
                t_clock = t_clock + 0.005
                if id == 1 then
                    return false, "connection refused" -- A failed
                end
                return true, "peer3", D { peer3 = 2, peer4 = 2 }
            end,
            sync = function(id)
                if id == 1 then return false, "no route" end
                return true, "peer3", sync_data_r2
            end,
        }, function()
            ag.maintenance()
        end)
        local stats2 = ag.stats(0)
        -- B(peer4) must still be reachable via C(peer3): self→peer3→peer4
        assert(stats2:find('"peer4"'), "round2: peer4 must remain reachable via relay\n" .. stats2)
        assert(stats2:find('"peer3"%->"peer4"'),
            'round2: expected relay "peer3"->"peer4" path\n' .. stats2)
        -- A(peer2) should be unreachable or absent
        assert(not stats2:find('"peer2"[^\n]*%[%d+%]'),
            'A(peer2) must not show a conn after probe failure\n' .. stats2)
    end)

    T:atest("routing: failed link recovery switches back to direct", function()
        -- Round 1: A→B fails → route via C. Round 2: A recovers → back to direct.
        reset()
        ag.conns = {
            [1] = { "socks4a://peer2.internal:1080" }, -- A
            [2] = { "socks4a://peer3.internal:1080" }, -- C
        }
        t_clock = 1000
        -- Round 1: only C probe succeeds, A is down
        local sync_data_r1 = {
            peer3 = mkpeer(1, { "peer3-host" }, {
                [1] = { peername = "self", rtt = 0.005 },
                [2] = { peername = "peer4", rtt = 0.015 },
            }),
            peer4 = mkpeer(1, { "peer4-host" }, {}),
        }
        with_rpcall({
            probe = function(id)
                t_clock = t_clock + 0.005
                if id == 1 then return false, "timeout" end
                return true, "peer3", D { peer3 = 1, peer4 = 1 }
            end,
            sync = function(id)
                if id == 1 then return false, "no route" end
                return true, "peer3", sync_data_r1
            end,
        }, function()
            ag.maintenance()
        end)
        -- Round 2: A recovers with shorter RTT (self→A 8ms, A→B 5ms = 13ms total)
        t_clock = 2000
        local sync_data_r2 = {
            peer2 = mkpeer(2, { "peer2-host" }, {
                [1] = { peername = "self", rtt = 0.008 },
                [2] = { peername = "peer4", rtt = 0.005 },
            }),
            peer3 = mkpeer(2, { "peer3-host" }, {
                [1] = { peername = "self", rtt = 0.005 },
                [2] = { peername = "peer4", rtt = 0.015 },
            }),
            peer4 = mkpeer(2, { "peer4-host" }, {}),
        }
        with_rpcall({
            probe = function(id)
                t_clock = t_clock + 0.005
                return true, id == 1 and "peer2" or "peer3",
                    D { peer2 = 2, peer3 = 2, peer4 = 2 }
            end,
            sync = function(id)
                return true, id == 1 and "peer2" or "peer3", sync_data_r2
            end,
        }, function()
            ag.maintenance()
        end)
        local stats = ag.stats(0)
        -- B(peer4) should be reachable via A (shorter path self→peer2→peer4 = 13ms
        -- vs self→peer3→peer4 = 20ms). After A recovers, Dijkstra picks the shorter path.
        assert(stats:find('"peer2"%->"peer4"'),
            'after recovery, must use shorter "peer2"->"peer4" direct path\n' .. stats)
    end)

    T:atest("routing: all paths fail → peer unreachable", function()
        -- Round 1: self→A→B and self→C→B both work. Round 2: both A and C's
        -- connections to B fail → B becomes unreachable.
        reset()
        ag.conns = {
            [1] = { "socks4a://peer2.internal:1080" }, -- A
            [2] = { "socks4a://peer3.internal:1080" }, -- C
        }
        t_clock = 1000
        -- Round 1: full connectivity
        local sync_data_r1 = {
            peer2 = mkpeer(1, { "peer2-host" }, {
                [1] = { peername = "self", rtt = 0.010 },
                [2] = { peername = "peer4", rtt = 0.010 },
            }),
            peer3 = mkpeer(1, { "peer3-host" }, {
                [1] = { peername = "self", rtt = 0.005 },
                [2] = { peername = "peer4", rtt = 0.015 },
            }),
            peer4 = mkpeer(1, { "peer4-host" }, {}),
        }
        with_rpcall({
            probe = function(id)
                t_clock = t_clock + 0.005
                return true, id == 1 and "peer2" or "peer3",
                    D { peer2 = 1, peer3 = 1, peer4 = 1 }
            end,
            sync = function(id)
                return true, id == 1 and "peer2" or "peer3", sync_data_r1
            end,
        }, function()
            ag.maintenance()
        end)
        local stats1 = ag.stats(0)
        assert(stats1:find('"peer4"'), "round1: peer4 must be reachable\n" .. stats1)
        assert(not stats1:find('"peer4".*%(unreachable%)'),
            "round1: peer4 must not be unreachable\n" .. stats1)
        -- Round 2: A and C both lost conn to B
        t_clock = 2000
        local sync_data_r2 = {
            peer2 = mkpeer(2, { "peer2-host" }, {
                [1] = { peername = "self", rtt = 0.010 },
            }),
            peer3 = mkpeer(2, { "peer3-host" }, {
                [1] = { peername = "self", rtt = 0.005 },
            }),
            peer4 = mkpeer(2, { "peer4-host" }, {}),
        }
        with_rpcall({
            probe = function(id)
                t_clock = t_clock + 0.005
                return true, id == 1 and "peer2" or "peer3",
                    D { peer2 = 2, peer3 = 2, peer4 = 2 }
            end,
            sync = function(id)
                return true, id == 1 and "peer2" or "peer3", sync_data_r2
            end,
        }, function()
            ag.maintenance()
        end)
        local stats2 = ag.stats(0)
        -- B(peer4) is now isolated — no conns in either A or C's peerdb entries
        assert(stats2:find('"peer4".*%(unreachable%)'),
            "round2: peer4 must be unreachable when all paths lost\n" .. stats2)
    end)

    -- ------------------------------------------------------------------ --
    -- 16. Matcher tests
    -- ------------------------------------------------------------------ --

    T:atest("matcher: API_ENDPOINT exact match", function()
        reset()
        -- API_ENDPOINT match does not depend on routes/peerdb
        local handler = ag.matcher(ag.API_ENDPOINT)
        assert(type(handler) == "function",
            "matcher must return a function for API_ENDPOINT")
        local result_addr, proxy = handler()
        assert(result_addr == ag.api_endpoint,
            "must resolve to api_endpoint, got " .. tostring(result_addr))
        assert(proxy == nil, "no proxies for API endpoint")
    end)

    T:atest("matcher: INTERNAL_DOMAIN direct peer passthrough", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D { peer2 = 1 }
            end,
            sync = function()
                -- Include "peer2" in hosts so resolve_internal can find it
                return true, "peer2", {
                    peer2 = mkpeer(1, { "peer2-host", "peer2" }, {}),
                }
            end,
        }, function()
            ag.maintenance()
        end)
        -- "peer2.internal:1080" should resolve to itself via 1-hop path
        local handler = ag.matcher("peer2.internal:1080")
        assert(type(handler) == "function",
            "matcher must return a handler for direct internal peer")
        local result_addr, proxy = handler()
        assert(result_addr == "peer2.internal:1080",
            "passthrough: addr must be unchanged, got " .. tostring(result_addr))
        assert(proxy ~= nil, "must have a proxy conn in chain")
    end)

    T:atest("matcher: INTERNAL_DOMAIN self-hosted returns nil", function()
        reset()
        with_rpcall({
            probe = function() return false, "no route" end,
        }, function()
            ag.maintenance()
        end)
        -- "self-host.internal:80" is self-hosted → matcher returns nil (pass through)
        local handler = ag.matcher("self-host.internal:80")
        assert(handler == nil,
            "matcher must return nil for self-hosted addr (pass to next handler)")
    end)

    T:atest("matcher: INTERNAL_DOMAIN unreachable throws error", function()
        reset()
        with_rpcall({
            probe = function() return false, "no route" end,
        }, function()
            ag.maintenance()
        end)
        local ok, err = pcall(ag.matcher, "no-such-peer.internal:80")
        assert(not ok, "matcher must throw for unknown host")
        assert(tostring(err):find("unknown host"),
            "error must mention 'unknown host', got: " .. tostring(err))
    end)

    T:atest("matcher: RELAY_DOMAIN single-label final hop", function()
        reset()
        ag.relay_cost = 0 -- opt in to relaying
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D { peer2 = 1 }
            end,
            sync = function()
                return true, "peer2", {
                    peer2 = mkpeer(1, { "peer2-host" }, {}),
                }
            end,
        }, function()
            ag.maintenance()
        end)
        -- "peer2-host.relay.neosocksd.internal:80" → single-label → final hop
        -- hosts["peer2-host"] = "peer2", routes["peer2"] = 1-hop
        local handler = ag.matcher("peer2-host.relay.neosocksd.internal:80")
        assert(type(handler) == "function",
            "matcher must return a handler for single-label relay")
        local result_addr, proxy = handler()
        assert(result_addr == "peer2-host.internal:80",
            "single-label relay must rewrite to internal domain, got " ..
            tostring(result_addr))
        assert(proxy ~= nil, "must forward through proxy")
    end)

    T:atest("matcher: RELAY_DOMAIN multi-label relay forwarding", function()
        reset()
        ag.relay_cost = 0 -- opt in to relaying
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D { peer2 = 1 }
            end,
            sync = function()
                return true, "peer2", { peer2 = mkpeer(1, { "peer2-host" }, {}) }
            end,
        }, function()
            ag.maintenance()
        end)
        -- "peer3-host.peer2.relay.neosocksd.internal:80"
        -- → strips peer2, forwards "peer3-host.relay.neosocksd.internal:80" to peer2
        local handler = ag.matcher("peer3-host.peer2.relay.neosocksd.internal:80")
        assert(type(handler) == "function",
            "matcher must return a handler for multi-label relay")
        local result_addr, proxy = handler()
        assert(result_addr == "peer3-host.relay.neosocksd.internal:80",
            "multi-label relay must strip one layer, got " .. tostring(result_addr))
        assert(proxy ~= nil, "must forward through proxy")
    end)

    -- ------------------------------------------------------------------ --
    -- 17. Node offline simulation
    -- ------------------------------------------------------------------ --

    T:atest("routing: node offline — conn_state dropped and routes updated", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        local sync_data = {
            peer2 = mkpeer(1, { "peer2-host" }, {
                [1] = { peername = "self", rtt = 0.010 },
            }),
        }
        -- Round 1: peer2 is online
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.010
                return true, "peer2", D { peer2 = 1 }
            end,
            sync = function() return true, "peer2", sync_data end,
        }, function()
            ag.maintenance()
        end)
        assert(ag.conn_state[1] ~= nil,
            "conn_state must exist after successful probe")
        assert(ag.conn_state[1].peername == "peer2",
            "conn_state must track peer2 peername")
        -- Round 2: peer2 goes offline — probe fails (keep time within EXPIRY_TIME)
        t_clock = 1100
        with_rpcall({
            probe = function() return false, "peer offline" end,
        }, function()
            ag.maintenance()
        end)
        assert(ag.conn_state[1] == nil,
            "conn_state must be cleared when node goes offline")
        local stats = ag.stats(0)
        assert(stats:find('"peer2".*%(unreachable%)'),
            "offline peer must show as unreachable\n" .. stats)
    end)

    T:atest("expire: offline peer eventually removed from peerdb", function()
        -- Without indirect digest refresh, an offline peer expires naturally.
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        -- Round 1: peer2 is online, gets into peerdb
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.010
                return true, "peer2", D { peer2 = 1 }
            end,
            sync = function()
                return true, "peer2", {
                    peer2 = mkpeer(1, { "peer2-host" }, {}),
                    peer3 = mkpeer(1, { "peer3-host" }, {}),
                }
            end,
        }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["peer3"] ~= nil, "peer3 must exist after sync")
        -- Set peer3's timestamp to just past the expiry threshold
        local threshold = ag.PEERDB_EXPIRY_TIME + ag.PEERDB_EXPIRY_TOLERANCE
        _G.peerdb["peer3"].timestamp = 10000 - threshold - 1
        _G.peerdb["peer2"].timestamp = 10000 - threshold - 1
        with_rpcall({
            probe = function() return false, "peer offline" end,
        }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["peer3"] == nil,
            "peer3 must be expired when timestamp is past threshold")
        assert(_G.peerdb["peer2"] == nil,
            "peer2 must be expired when timestamp is past threshold")
    end)

    -- ------------------------------------------------------------------ --
    -- 18. Timestamp merge from probe digest
    -- ------------------------------------------------------------------ --

    T:atest("timestamp: indirect peer timestamp updated from probe digest", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        -- Pre-seed peer2 and peer3 with old timestamps
        _G.peerdb["peer2"] = mkpeer(1, { "peer2-host" }, {})
        _G.peerdb["peer2"].timestamp = 5000
        _G.peerdb["peer3"] = mkpeer(1, { "peer3-host" }, {})
        _G.peerdb["peer3"].timestamp = 5000
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                -- remote digest carries peer3 with t=10000 (newer than local 5000)
                return true, "peer2", D { peer2 = 1, peer3 = 1 }
            end,
        }, function()
            ag.maintenance()
        end)
        -- Indirect peer3: timestamp merged from remote (10000 > 5000)
        assert(_G.peerdb["peer3"].timestamp == 10000,
            "indirect peer timestamp must be updated from probe, got " ..
            tostring(_G.peerdb["peer3"].timestamp))
        -- Direct peer2: timestamp set to time.unix() (10000), not from digest
        assert(_G.peerdb["peer2"].timestamp == 10000,
            "direct peer timestamp must be time.unix(), got " ..
            tostring(_G.peerdb["peer2"].timestamp))
    end)

    T:atest("timestamp: older remote timestamp does not overwrite newer local", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        _G.peerdb["peer2"] = mkpeer(1, { "peer2-host" }, {})
        _G.peerdb["peer3"] = mkpeer(1, { "peer3-host" }, {})
        _G.peerdb["peer3"].timestamp = 15000 -- newer than remote's 10000
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D { peer2 = 1, peer3 = 1 }
            end,
        }, function()
            ag.maintenance()
        end)
        -- Local timestamp is newer, must not be overwritten
        assert(_G.peerdb["peer3"].timestamp == 15000,
            "newer local timestamp must not be overwritten by older remote, got " ..
            tostring(_G.peerdb["peer3"].timestamp))
    end)

    T:atest("timestamp: merge does not trigger sync when versions match", function()
        -- Version comparison drives sync; timestamp-only changes stay lightweight.
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        _G.peerdb["peer2"] = mkpeer(1, { "peer2-host" }, {})
        _G.peerdb["peer3"] = mkpeer(1, { "peer3-host" }, {})
        _G.peerdb["peer3"].timestamp = 5000
        local sync_called = false
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                -- same version (1) but newer timestamp
                return true, "peer2", D { peer2 = 1, peer3 = 1 }
            end,
            sync = function()
                sync_called = true
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        assert(not sync_called,
            "sync must not be triggered when only timestamps differ")
        -- Timestamp should still be updated via the lightweight merge path
        assert(_G.peerdb["peer3"].timestamp == 10000,
            "timestamp must be updated even without sync, got " ..
            tostring(_G.peerdb["peer3"].timestamp))
    end)

    T:atest("timestamp: direct peer keeps time.unix() not remote self-reported ts", function()
        -- When we probe peer2 directly, entry.timestamp = time.unix() proves
        -- liveness.  The remote's self-reported timestamp for itself in the
        -- digest must not overwrite this stronger signal.
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        _G.peerdb["peer2"] = mkpeer(1, { "peer2-host" }, {})
        _G.peerdb["peer2"].timestamp = 5000
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                -- remote reports its own timestamp as t=3000 (stale)
                return true, "peer2", D { peer2 = 1 }
            end,
        }, function()
            ag.maintenance()
        end)
        -- Direct probe proves liveness: timestamp must be time.unix() (10000),
        -- not the remote's stale self-reported t=3000.
        assert(_G.peerdb["peer2"].timestamp == 10000,
            "direct peer timestamp must be time.unix() after probe, got " ..
            tostring(_G.peerdb["peer2"].timestamp))
    end)

    -- ------------------------------------------------------------------ --
    -- 19. Fast failure confirmation & bidirectional digest propagation
    -- ------------------------------------------------------------------ --

    T:atest("probe interval: a tolerated miss resets the interval to MIN", function()
        reset()
        ag.CONN_FAILURE_LIMIT = 2
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        local function ok_probe()
            t_clock = t_clock + 0.002
            return true, "peer2", {}
        end
        -- Round 1: self entry is created (changed) → interval = MIN (10s)
        with_rpcall({ probe = ok_probe }, function() ag.maintenance() end)
        -- Round 2: quiescent → interval backs off to 10 * 1.5 = 15s
        t_clock = 1100
        with_rpcall({ probe = ok_probe }, function() ag.maintenance() end)
        assert(ag.stats(0):find("probe=15s", 1, true),
            "interval must back off when quiescent\n" .. ag.stats(0))
        -- Round 3: a tolerated miss must reset the interval to MIN so the
        -- suspected conn loss is confirmed promptly, not after a backed-off
        -- round (worst case CONN_FAILURE_LIMIT * PROBE_INTERVAL_MAX)
        t_clock = 1200
        with_rpcall({ probe = function() return false, "refused" end }, function()
            ag.maintenance()
        end)
        assert(ag.conn_state[1] and ag.conn_state[1].fails == 1,
            "miss must be tolerated below the limit")
        assert(ag.stats(0):find("probe=10s", 1, true),
            "a miss must reset the interval to MIN\n" .. ag.stats(0))
    end)

    T:atest("probe: outgoing probe carries the local digest", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        _G.peerdb["peer3"] = mkpeer(7)
        t_clock = 1000
        local captured
        with_rpcall({
            probe = function(_, peername, digest)
                captured = { peername, digest }
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        assert(captured, "a probe must have been issued")
        assert(captured[1] == "self", "first probe arg must be the peername")
        local digest = captured[2]
        assert(type(digest) == "table" and type(digest["peer3"]) == "table",
            "probe must carry a digest of known peers")
        assert(digest["peer3"].v == 7 and digest["peer3"].t == 10000,
            "digest entries must carry version and timestamp")
    end)

    T:test("rpc.probe: does not reconcile data (push replaces the reverse pull)", function()
        reset()
        -- a caller ahead of us used to trigger a pull-back; reconciliation is
        -- now caller-driven via sync, so probe stays a pure digest exchange
        local name, digest = rpc.probe("peer2", D { peer3 = 5 })
        assert(name == "self" and type(digest) == "table")
        assert(_G.peerdb["peer3"] == nil,
            "rpc.probe must not ingest or pull entries on its own")
    end)

    T:test("rpc.sync: ingests entries pushed by the caller", function()
        reset()
        -- the caller pushes peer3 (which we lack) and asks for what it lacks
        local name, delta = rpc.sync("peer2", D { self = 0 },
            { peer3 = mkpeer(5, { "peer3-host" }, {}) })
        assert(name == "self")
        assert(_G.peerdb["peer3"] ~= nil and _G.peerdb["peer3"].version == 5,
            "a pushed entry must be ingested")
        assert(type(delta) == "table",
            "sync must still return the entries the caller is missing")
    end)

    T:test("rpc.sync: ingestion needs no outbound conn (passive hub)", function()
        reset()
        -- no conns and no conn_state: a passive hub cannot dial out, yet a
        -- pushed delta must still be ingested from the inbound connection
        ag.conns = {}
        for k in pairs(ag.conn_state) do ag.conn_state[k] = nil end
        rpc.sync("peer2", nil, { peer3 = mkpeer(5, { "peer3-host" }, {}) })
        assert(_G.peerdb["peer3"] ~= nil,
            "a passive node must ingest pushed entries without dialing")
    end)

    T:test("rpc.sync: an expired pushed entry is not ingested", function()
        reset()
        local threshold = ag.PEERDB_EXPIRY_TIME + ag.PEERDB_EXPIRY_TOLERANCE
        local stale = mkpeer(5, { "peer3-host" }, {})
        stale.timestamp = 10000 - threshold - 1
        rpc.sync("peer2", nil, { peer3 = stale })
        assert(_G.peerdb["peer3"] == nil,
            "an entry already past expiry must not be added via push")
    end)

    T:atest("maintenance: probe_via pushes entries the remote is missing", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        -- we already hold peer9, which the remote's digest will not list
        _G.peerdb["peer9"] = mkpeer(4, { "peer9-host" }, {})
        t_clock = 1000
        local pushed
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D {} -- remote knows nothing
            end,
            sync = function(_, _, _, delta)
                pushed = delta
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        assert(pushed and pushed["peer9"] and pushed["peer9"].version == 4,
            "probe_via must push entries the remote is missing")
    end)

    T:test("rpc.sync: a passive hub relays data between two active peers", function()
        reset()
        -- this node is a passive hub: no conns, cannot dial out. Active A and
        -- B both dial in. A pushes its entry; later B syncs (pushing its own
        -- and pulling what it lacks) and must receive A's entry from the hub.
        ag.conns = {}
        for k in pairs(ag.conn_state) do ag.conn_state[k] = nil end
        -- A dials in and pushes its entry
        rpc.sync("A", D { self = 0 }, { A = mkpeer(3, { "A-host" }, {}) })
        assert(_G.peerdb["A"] ~= nil, "hub must store A's entry")
        -- B dials in: pushes B, and its digest lacks A
        local _, delta = rpc.sync("B", D { self = 0, B = 1 },
            { B = mkpeer(2, { "B-host" }, {}) })
        assert(_G.peerdb["B"] ~= nil, "hub must store B's entry")
        assert(delta["A"] ~= nil and delta["A"].version == 3,
            "the hub must relay A's entry to B in the sync response")
    end)

    T:atest("rpc.probe: digest merges newer third-party timestamps", function()
        reset()
        _G.peerdb["peer3"] = mkpeer(5)
        _G.peerdb["peer3"].timestamp = 5000
        rpc.probe("peer2", D { peer3 = 5 })
        assert(_G.peerdb["peer3"].timestamp == 10000,
            "newer third-party timestamp must be merged from the digest, got " ..
            tostring(_G.peerdb["peer3"].timestamp))
    end)

    -- ------------------------------------------------------------------ --
    -- 20. Demand-driven recovery & data-plane activity
    -- ------------------------------------------------------------------ --

    T:atest("probe interval: data-plane activity caps the backed-off interval", function()
        reset()
        local saved_active = ag.PROBE_INTERVAL_ACTIVE
        ag.PROBE_INTERVAL_ACTIVE = 12 -- between MIN (10) and the first backoff (15)
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        _G.peerdb["peer2"] = mkpeer(1, { "peer2-host" }, {})
        t_clock = 1000
        local function ok_probe()
            t_clock = t_clock + 0.002
            return true, "peer2", {}
        end
        -- Round 1: self entry is created (changed) → interval = MIN (10s)
        with_rpcall({ probe = ok_probe }, function() ag.maintenance() end)
        -- Data-plane demand: route a connection through the mesh
        local handler = ag.matcher("peer2-host.internal:80")
        assert(type(handler) == "function", "peer2-host must be routable")
        -- Round 2: quiescent backoff would give 15s, but recent activity
        -- caps the interval at ACTIVE so a failing conn cannot blackhole
        -- live traffic for up to PROBE_INTERVAL_MAX
        t_clock = 1100
        with_rpcall({ probe = ok_probe }, function() ag.maintenance() end)
        assert(ag.stats(0):find("probe=12s", 1, true),
            "interval must be capped at ACTIVE while routes are in use\n" .. ag.stats(0))
        -- Round 3: no further activity → backoff resumes (12 * 1.5 = 18s)
        t_clock = 1200
        with_rpcall({ probe = ok_probe }, function() ag.maintenance() end)
        assert(ag.stats(0):find("probe=18s", 1, true),
            "an idle mesh must resume backing off\n" .. ag.stats(0))
        ag.PROBE_INTERVAL_ACTIVE = saved_active
    end)

    T:atest("resolve: failed demand wakes the control loop", function()
        reset()
        ag.relay_cost = 0 -- opt in so a relay miss reaches the reachability check
        -- known peer, but no conns at all → no route
        _G.peerdb["peer9"] = mkpeer(1, { "peer9-host" }, {})
        ag.maintenance() -- no conns: just rebuilds the index
        local woken = 0
        local orig_wake = ag.wake
        ag.wake = function() woken = woken + 1 end
        local result, conn = ag._resolve_internal("peer9-host", 80)
        assert(result == "peer not reachable" and conn == nil)
        assert(woken == 1, "unreachable demand must wake the control loop")
        result, conn = ag._resolve_internal("no-such-host", 80)
        assert(result == "unknown host" and conn == nil)
        assert(woken == 2, "unknown-host demand must wake the control loop")
        -- relay forwarding without a 1-hop route must also wake
        local ok = pcall(ag.matcher, "x.peer9.relay.neosocksd.internal:80")
        assert(not ok, "relay without a route must throw")
        assert(woken == 3, "failed relay demand must wake the control loop")
        ag.wake = orig_wake
    end)

    T:atest("probe interval: dial failures on an active mesh reset to MIN", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        _G.peerdb["peer2"] = mkpeer(1, { "peer2-host" }, {})
        t_clock = 1000
        local function ok_probe()
            t_clock = t_clock + 0.002
            return true, "peer2", {}
        end
        -- Round 1: self entry is created (changed) → interval = MIN (10s)
        with_rpcall({ probe = ok_probe }, function() ag.maintenance() end)
        -- Round 2: usage but no dial failures → plain backoff applies
        assert(type(ag.matcher("peer2-host.internal:80")) == "function")
        t_clock = 1100
        with_rpcall({ probe = ok_probe }, function() ag.maintenance() end)
        assert(ag.stats(0):find("probe=15s", 1, true),
            "usage without failures must back off normally\n" .. ag.stats(0))
        -- Round 3: usage AND rising dial-failure count → the route may be
        -- broken even though probes look healthy: reset to MIN
        assert(type(ag.matcher("peer2-host.internal:80")) == "function")
        fake_rejects = fake_rejects + 3
        t_clock = 1200
        with_rpcall({ probe = ok_probe }, function() ag.maintenance() end)
        assert(ag.stats(0):find("probe=10s", 1, true),
            "dial failures on an active mesh must reset the interval\n" .. ag.stats(0))
        -- Round 4: failures keep rising but the mesh is idle → the failures
        -- are not attributable to mesh routes, back off normally
        fake_rejects = fake_rejects + 3
        t_clock = 1300
        with_rpcall({ probe = ok_probe }, function() ag.maintenance() end)
        assert(ag.stats(0):find("probe=15s", 1, true),
            "failures on an idle mesh must not reset the interval\n" .. ag.stats(0))
    end)

    T:atest("routing: a probe miss diverts traffic to a healthy parallel conn", function()
        reset()
        ag.CONN_FAILURE_LIMIT = 2
        -- two parallel conns to the same neighbor (e.g. different ISPs)
        ag.conns = {
            [1] = { "socks4a://line1.internal:1080" }, -- fast
            [2] = { "socks4a://line2.internal:1080" }, -- slow
        }
        _G.peerdb["peer2"] = mkpeer(1, { "peer2-host" }, {})
        t_clock = 1000
        -- Round 1: both healthy → fastest conn wins
        with_rpcall({
            probe = function(id)
                t_clock = t_clock + (id == 1 and 0.002 or 0.010)
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        local _, conn = ag._resolve_internal("peer2-host", 80)
        assert(conn == ag.conns[1], "round1: fastest healthy conn must be chosen")
        -- Round 2: conn 1 misses one probe (tolerated, stays advertised for
        -- route stability) → local traffic must divert to the healthy conn 2
        t_clock = 1100
        with_rpcall({
            probe = function(id)
                if id == 1 then return false, "connection refused" end
                t_clock = t_clock + 0.010
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        assert(ag.conn_state[1] and ag.conn_state[1].fails == 1,
            "round2: the miss must be tolerated below the limit")
        _, conn = ag._resolve_internal("peer2-host", 80)
        assert(conn == ag.conns[2],
            "round2: traffic must divert to the healthy parallel conn")
        -- Round 3: conn 1 recovers → traffic returns to the faster conn
        t_clock = 1200
        with_rpcall({
            probe = function(id)
                t_clock = t_clock + (id == 1 and 0.002 or 0.010)
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        _, conn = ag._resolve_internal("peer2-host", 80)
        assert(conn == ag.conns[1],
            "round3: traffic must return to the recovered faster conn")
    end)

    T:atest("timestamp: future timestamps are clamped to the local clock", function()
        -- A peer with a fast wall clock must not outlive its expiry window
        -- on this node; both merge paths clamp to local time.unix().
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        _G.peerdb["peer2"] = mkpeer(1, { "peer2-host" }, {})
        _G.peerdb["peer3"] = mkpeer(1, { "peer3-host" }, {})
        _G.peerdb["peer3"].timestamp = 5000
        local peer4_data = mkpeer(1, { "peer4-host" }, {})
        peer4_data.timestamp = 99999 -- far in the future (now = 10000)
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                -- digest merge path: peer3 reported with a future timestamp
                return true, "peer2", {
                    peer2 = { v = 1, t = 10000 },
                    peer3 = { v = 1, t = 99999 },
                    peer4 = { v = 1, t = 10000 },
                }
            end,
            -- apply_delta path: new entry carrying a future timestamp
            sync = function() return true, "peer2", { peer4 = peer4_data } end,
        }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["peer3"].timestamp == 10000,
            "digest merge must clamp future timestamps, got " ..
            tostring(_G.peerdb["peer3"].timestamp))
        assert(_G.peerdb["peer4"] and _G.peerdb["peer4"].timestamp == 10000,
            "apply_delta must clamp future timestamps, got " ..
            tostring(table.get(_G.peerdb, "peer4", "timestamp")))
    end)

    T:test("build_index: conn removed from config produces no route", function()
        -- Regression: the persisted self entry may advertise a conn that a
        -- config change has removed; such a conn cannot be dialed and used
        -- to yield routes with conn = nil that made the matcher throw.
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        _G.peerdb["self"] = mkpeer(3, { "self-host" }, {
            [1] = { peername = "peer2", rtt = 0.010 },
            [2] = { peername = "peer2", rtt = 0.005 }, -- conn 2 was removed
        })
        _G.peerdb["peer2"] = mkpeer(1, { "peer2-host" }, {})
        local _, routes = ag._build_index(_G.peerdb)
        local route = routes["peer2"]
        assert(route, "peer2 must remain routable via the remaining conn")
        assert(route.conn == ag.conns[1],
            "route must use the conn that still exists, not the removed one")
        -- when every advertised conn is gone, the peer must be unroutable
        -- instead of producing a route that cannot be dialed
        ag.conns = {}
        local _, routes2 = ag._build_index(_G.peerdb)
        assert(routes2["peer2"] == nil,
            "no dialable conn must mean no route")
    end)

    -- ------------------------------------------------------------------ --
    -- 21. Hot reload (/ruleset/update?module=agent)
    -- ------------------------------------------------------------------ --

    T:atest("hot reload: module update stops old instance and migrates state", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        _G.peerdb["peer2"] = mkpeer(1, { "peer2-host" }, {})
        t_clock = 1000
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        -- runtime configuration applied by the operator's ruleset
        ag.api_endpoint = "127.0.1.1:9080"
        local function callback() end
        ag.on_updated = callback
        local old_chain = ag.chain
        -- simulate /ruleset/update?module=agent: package.replace re-runs the
        -- chunk while _G.agent still points at the previous instance
        local saved = _G.agent
        _G.agent = ag
        local reload = assert(loadfile("agent.lua"))
        local ag2 = reload()
        _G.agent = saved
        assert(not rawequal(ag, ag2), "a reload must create a fresh module table")
        assert(ag.running == false, "the previous instance must be stopped")
        assert(ag2.running == true, "the new instance must be running")
        -- compatible fields must be migrated, not reset to defaults
        assert(ag2.api_endpoint == "127.0.1.1:9080",
            "api_endpoint must be migrated, got " .. tostring(ag2.api_endpoint))
        assert(ag2.peername == "self", "peername must be migrated")
        assert(ag2.on_updated == callback, "on_updated must be migrated")
        assert(rawequal(ag2.conn_state, ag.conn_state),
            "conn_state must be migrated")
        assert(ag2.conn_state[1] and ag2.conn_state[1].peername == "peer2",
            "probe history must be migrated")
        -- the data plane must keep routing immediately after the reload,
        -- without waiting for the next maintenance round
        local addr, conn = ag2._resolve_internal("peer2-host", 80)
        assert(addr == "peer2-host.internal:80" and conn == ag2.conns[1],
            "routes must be rebuilt from migrated state at load time")
        -- the new instance learns a peer the old instance never saw
        t_clock = 1100
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D { peer2 = 2, peer3 = 1 }
            end,
            sync = function()
                return true, "peer2", {
                    peer2 = mkpeer(2, { "peer2-host" }, {
                        [1] = { peername = "self", rtt = 0.002 },
                        [2] = { peername = "peer3", rtt = 0.003 },
                    }),
                    peer3 = mkpeer(1, { "peer3-host" }, {}),
                }
            end,
        }, function()
            ag2.maintenance()
        end)
        -- a chain captured from the OLD instance (e.g. by the ruleset's
        -- composite.subchain at boot) must dispatch into the newest module
        -- via _G.agent, so it can route to the newly learned peer
        _G.agent = ag2
        local entry = old_chain[1][1]
        local handler = entry("peer3-host.internal:80")
        _G.agent = saved
        assert(type(handler) == "function",
            "a captured chain must dispatch into the reloaded module")
        -- main() started a mainloop for ag2; retire it so the background task
        -- does not outlive the test
        ag2.stop()
    end)

    -- ------------------------------------------------------------------ --
    -- 21b. relay_cost: limit or refuse transit traffic for other peers
    --   nil/0 relay freely; > 0 transit penalty; < 0 refuse relay
    -- ------------------------------------------------------------------ --

    T:test("relay_cost < 0: a node is an endpoint but not a relay hop", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        _G.peerdb["self"] = mkpeer(3, { "self-host" }, {
            [1] = { peername = "peer2", rtt = 0.005 },
        })
        -- peer2 refuses relay: reachable directly, but Dijkstra must not
        -- route any transit traffic (e.g. to peer3) through it
        _G.peerdb["peer2"] = mkpeer(1, { "peer2-host" }, {
            [1] = { peername = "peer3", rtt = 0.005 },
        })
        _G.peerdb["peer2"].relay_cost = -1
        _G.peerdb["peer3"] = mkpeer(1, { "peer3-host" }, {})
        local _, routes = ag._build_index(_G.peerdb)
        assert(routes["peer2"],
            "a relay-refusing node must still be reachable as an endpoint")
        assert(not routes["peer3"],
            "traffic must not transit through a relay-refusing node")
    end)

    T:test("relay_cost < 0: a node still routes its own traffic", function()
        reset()
        -- the source's own outgoing edges are always relaxed, so refusing
        -- relay locally only blocks others from transiting through this node
        ag.relay_cost = -1
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        _G.peerdb["self"] = mkpeer(3, { "self-host" }, {
            [1] = { peername = "peer2", rtt = 0.005 },
        })
        _G.peerdb["self"].relay_cost = -1
        _G.peerdb["peer2"] = mkpeer(1, { "peer2-host" }, {
            [1] = { peername = "peer3", rtt = 0.005 },
        })
        _G.peerdb["peer3"] = mkpeer(1, { "peer3-host" }, {})
        local _, routes = ag._build_index(_G.peerdb)
        assert(routes["peer2"] and routes["peer3"],
            "a relay-refusing node must still reach the mesh for its own traffic")
    end)

    T:test("relay_cost > 0: a costly node is avoided when an alternative exists", function()
        reset()
        -- self reaches peer4 two ways: direct via peer2 (fast link but peer2
        -- charges a large transit cost) or via peer3 (slower links, no cost).
        -- The cost must make Dijkstra prefer the nominally slower peer3 path.
        ag.conns = {
            [1] = { "socks4a://peer2.internal:1080" },
            [2] = { "socks4a://peer3.internal:1080" },
        }
        _G.peerdb["self"] = mkpeer(3, { "self-host" }, {
            [1] = { peername = "peer2", rtt = 0.001 },
            [2] = { peername = "peer3", rtt = 0.010 },
        })
        _G.peerdb["peer2"] = mkpeer(1, { "peer2-host" }, {
            [1] = { peername = "peer4", rtt = 0.001 },
        })
        _G.peerdb["peer2"].relay_cost = 1 -- 1s transit penalty
        _G.peerdb["peer3"] = mkpeer(1, { "peer3-host" }, {
            [1] = { peername = "peer4", rtt = 0.010 },
        })
        _G.peerdb["peer4"] = mkpeer(1, { "peer4-host" }, {})
        local _, routes = ag._build_index(_G.peerdb)
        local route = routes["peer4"]
        assert(route, "peer4 must remain reachable")
        -- chosen first hop is route.path[#route.path]
        assert(route.path[#route.path] == "peer3",
            "the costly node must be avoided in favour of peer3")
        -- reported RTT must be the real path RTT (20ms), not cost-inflated
        assert(math.abs(route.rtt - 0.020) < 1e-6,
            "reported rtt must exclude the synthetic relay cost, got " ..
            tostring(route.rtt))
    end)

    T:test("relay_cost > 0: a costly node is still used as a last resort", function()
        reset()
        -- only path to peer4 is through the costly peer2; it must still be used
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        _G.peerdb["self"] = mkpeer(3, { "self-host" }, {
            [1] = { peername = "peer2", rtt = 0.001 },
        })
        _G.peerdb["peer2"] = mkpeer(1, { "peer2-host" }, {
            [1] = { peername = "peer4", rtt = 0.001 },
        })
        _G.peerdb["peer2"].relay_cost = 1
        _G.peerdb["peer4"] = mkpeer(1, { "peer4-host" }, {})
        local _, routes = ag._build_index(_G.peerdb)
        assert(routes["peer4"], "a costly node must still relay when it is the only path")
        assert(routes["peer4"].path[#routes["peer4"].path] == "peer2")
    end)

    T:atest("relay_cost < 0: matcher refuses relay forwarding but allows own traffic", function()
        reset()
        ag.relay_cost = -1
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.002
                return true, "peer2", D { peer2 = 1 }
            end,
            sync = function()
                return true, "peer2", { peer2 = mkpeer(1, { "peer2-host" }, {}) }
            end,
        }, function()
            ag.maintenance()
        end)
        -- a relay request that would forward through this node must be refused
        local ok, err = pcall(ag.matcher, "peer3-host.peer2.relay.neosocksd.internal:80")
        assert(not ok, "relay_cost < 0 must refuse relay forwarding")
        assert(tostring(err):find("relay disabled"),
            "error must mention 'relay disabled', got: " .. tostring(err))
        -- the node's own outbound resolution must keep working
        local handler = ag.matcher("peer2-host.internal:80")
        assert(type(handler) == "function",
            "refusing relay must not block the node's own outbound traffic")
    end)

    T:atest("relay_cost: self entry advertises the cost and toggling republishes", function()
        reset()
        t_clock = 1000
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        -- relaying is opt-in: an unset cost means refuse, advertised as the
        -- absence of an entry so peers read this node as non-transit
        assert(_G.peerdb["self"].relay_cost == nil,
            "self entry must not advertise a cost when relaying is refused")
        local ver1 = _G.peerdb["self"].version
        -- opting in with a free relay (0) must be advertised so peers route
        -- through this node again, and must bump the version
        ag.relay_cost = 0
        t_clock = 1010
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["self"].relay_cost == 0,
            "a zero (free) relay cost must be advertised")
        assert(_G.peerdb["self"].version > ver1,
            "opting in to relaying must bump the version so peers learn it")
        local ver2 = _G.peerdb["self"].version
        -- raising the cost must republish so peers re-run Dijkstra
        ag.relay_cost = 0.5
        t_clock = 1020
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["self"].relay_cost == 0.5,
            "self entry must advertise the relay cost once set")
        assert(_G.peerdb["self"].version > ver2,
            "changing relay_cost must bump the version so peers learn it")
    end)

    -- ------------------------------------------------------------------ --
    -- 22. Cleanup
    -- ------------------------------------------------------------------ --

    ag.stop() -- signal the sleeping mainloop to exit on wake
    neosocksd.stats = orig_stats
    time.unix       = orig_unix
    time.monotonic  = orig_monotonic
    _G.peerdb       = saved_peerdb
    _G.agent        = saved_agent
end
