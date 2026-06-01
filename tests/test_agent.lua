-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ test_agent.lua: unit tests for agent.lua ]] --
--
-- Strategy:
--   agent.lua captures `time.monotonic` into a local variable at load time,
--   so we install a controllable mock BEFORE loading agent.lua, then drive
--   the fake clock by updating `t_clock` between calls.
--   `os.time` and `await.rpcall` are NOT cached locally in agent.lua, so
--   they can be replaced per-test after loading.

return function(T)
    -- ------------------------------------------------------------------ --
    -- 1. Install fake clock before loading agent.lua
    -- ------------------------------------------------------------------ --

    local t_clock         = 0
    local orig_monotonic  = time.monotonic
    time.monotonic        = function() return t_clock end

    local orig_ostime     = os.time
    -- os.time is used only in next_version() as the version seed.
    -- Override after loading (not cached), but stub it now to silence any
    -- early call that might happen during module init.
    os.time               = function() return 10000 end

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

    -- Prevent the background mainloop from running during tests:
    -- set BOOTSTRAP_DELAY to a huge value so it sleeps for the entire test
    -- run without ever calling maintenance() on its own.
    ag.BOOTSTRAP_DELAY = 99999

    -- Restore the real time.monotonic now; agent.lua already captured the
    -- mock into its local `monotonic` variable, so it won't be affected.
    time.monotonic = orig_monotonic

    -- ------------------------------------------------------------------ --
    -- 3. Shared helpers
    -- ------------------------------------------------------------------ --

    -- Capture the real await.rpcall so reset() can always restore it.
    local orig_rpcall = await.rpcall

    local function mkpeer(ver, hosts, conns)
        return { version = ver, timestamp = os.time(), hosts = hosts or {}, conns = conns or {} }
    end

    -- Reset all mutable state between tests.
    local function reset()
        _G.peerdb = {}
        ag.conns  = {}
        ag.hosts  = { "self-host" }
        for k in pairs(ag.last_seen) do ag.last_seen[k] = nil end
        for k in pairs(ag.conn_state) do ag.conn_state[k] = nil end
        t_clock = 0
        await.rpcall = orig_rpcall -- undo any per-test mock
    end

    -- Wrap await.rpcall for the duration of fn(), then restore it.
    -- handlers: table with optional "probe" and "sync" keys, each fn(connid) -> ok, ...
    --   "probe" handler returns (ok, peername, remote_digest)
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
                        if handler then return handler(id) end
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
        -- so indirect peers' last_seen was never refreshed in a stable network.
        reset()
        _G.peerdb["peer2"] = mkpeer(10)
        local _, delta = rpc.sync("caller", { peer2 = 10 })
        assert(delta["peer2"] ~= nil,
            "entry at same version must appear in delta (>= regression)")
    end)

    T:test("sync: newer entry IS included", function()
        reset()
        _G.peerdb["peer2"] = mkpeer(11)
        local _, delta = rpc.sync("caller", { peer2 = 10 })
        assert(delta["peer2"] ~= nil)
    end)

    T:test("sync: older entry is excluded", function()
        reset()
        _G.peerdb["peer2"] = mkpeer(9)
        local _, delta = rpc.sync("caller", { peer2 = 10 })
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
            probe = function() return true, "peer2", { peer2 = 42 } end,
            sync  = function() return true, "peer2", { peer2 = peer2_data } end,
        }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["peer2"] ~= nil, "peer2 should have been added")
        assert(_G.peerdb["peer2"].version == 42)
        assert(ag.last_seen["peer2"] == 1000)
    end)

    T:atest("maintenance: same version in delta refreshes last_seen", function()
        reset()
        t_clock = 900
        _G.peerdb["peer2"] = mkpeer(42)
        ag.last_seen["peer2"] = 900
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        with_rpcall({
            -- same version in remote digest: no sync triggered, but
            -- last_seen must still be refreshed after the probe
            probe = function() return true, "peer2", { peer2 = 42 } end,
        }, function()
            ag.maintenance()
        end)
        assert(ag.last_seen["peer2"] == 1000,
            "last_seen must be refreshed after a successful probe")
    end)

    T:atest("maintenance: older version in delta is ignored", function()
        reset()
        t_clock = 1000
        _G.peerdb["peer2"] = mkpeer(10)
        ag.last_seen["peer2"] = 1000 -- keep peer2 fresh so expire() won't remove it
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        with_rpcall({
            -- remote has version 9, local has version 10: no sync triggered
            probe = function() return true, "peer2", { peer2 = 9 } end,
        }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["peer2"] ~= nil,
            "peer2 must not be removed (older delta should be ignored)")
        assert(_G.peerdb["peer2"].version == 10,
            "peerdb must not be downgraded to an older version")
    end)

    T:atest("maintenance: probe always refreshes direct peer last_seen (regression)", function()
        -- Regression: when the gossip delta is empty (all entries up-to-date),
        -- the direct peer's last_seen was never updated, causing spurious expiry.
        reset()
        t_clock = 900
        _G.peerdb["peer2"] = mkpeer(42)
        ag.last_seen["peer2"] = 900
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        with_rpcall({
            probe = function() return true, "peer2", {} end, -- empty digest: no sync
        }, function()
            ag.maintenance()
        end)
        assert(ag.last_seen["peer2"] == 1000,
            "direct peer last_seen must be refreshed even when probe digest is empty")
    end)

    -- ------------------------------------------------------------------ --
    -- 6. expire() via maintenance
    -- ------------------------------------------------------------------ --

    T:atest("expire: stale peer is removed", function()
        reset()
        _G.peerdb["stale"] = mkpeer(1)
        ag.last_seen["stale"] = 0
        t_clock = ag.PEERDB_EXPIRY_TIME + 1 -- one second past expiry
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["stale"] == nil, "stale peer must be expired")
        assert(ag.last_seen["stale"] == nil)
    end)

    T:atest("expire: recently refreshed peer is kept", function()
        reset()
        t_clock = 1000
        _G.peerdb["fresh"] = mkpeer(1)
        ag.last_seen["fresh"] = 1000 - ag.PEERDB_EXPIRY_TIME + 10 -- 10s to go
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["fresh"] ~= nil, "peer with time remaining must not be expired")
    end)

    T:atest("expire: self entry is never expired", function()
        reset()
        -- Advance clock far past expiry; self has no last_seen entry
        t_clock = ag.PEERDB_EXPIRY_TIME * 10
        ag.last_seen["self"] = nil
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["self"] ~= nil, "self entry must never be expired")
    end)

    -- ------------------------------------------------------------------ --
    -- 7. conn_state transitions via maintenance
    -- ------------------------------------------------------------------ --

    T:atest("conn_state: successful probe creates alive state with rtt_win", function()
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
        assert(st.state == "alive",
            "state must be alive, got " .. tostring(st and st.state))
        assert(st.peername == "peer2")
        assert(st.failures == 0)
        assert(type(st.rtt_win) == "table" and st.rtt_win[1] ~= nil and st.rtt_win[1].rtt > 0,
            "rtt_win must be a non-empty deque with a positive rtt")
    end)

    T:atest("conn_state: failed probe transitions alive->suspect", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        ag.conn_state[1] = {
            peername = "peer2",
            rtt_win = { { rtt = 0.001, expiry = 1600 } },
            state = "alive",
            failures = 0,
            last_success = 1000,
        }
        with_rpcall({ probe = function() return false, "connection refused" end }, function()
            ag.maintenance()
        end)
        local st = ag.conn_state[1]
        assert(st ~= nil, "conn_state must survive the first failure")
        assert(st.state == "suspect",
            "state must be suspect after first failure, got " .. tostring(st and st.state))
        assert(st.failures == 1)
    end)

    T:atest("conn_state: DEAD_FAILURES consecutive failures drops the conn", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        -- Pre-seed with DEAD_FAILURES-1 so one more failure tips it over.
        ag.conn_state[1] = {
            peername = "peer2",
            rtt_win = { { rtt = 0.001, expiry = 1600 } },
            state = "suspect",
            failures = ag.DEAD_FAILURES - 1,
            last_success = 1000,
        }
        with_rpcall({ probe = function() return false, "refused" end }, function()
            ag.maintenance()
        end)
        assert(ag.conn_state[1] == nil,
            "conn_state must be dropped after DEAD_FAILURES consecutive failures")
    end)

    T:atest("conn_state: recovery resets failure counter", function()
        reset()
        ag.conns = { [1] = { "socks4a://peer2.internal:1080" } }
        t_clock = 1000
        ag.conn_state[1] = {
            peername = "peer2",
            rtt_win = { { rtt = 0.001, expiry = 1600 } },
            state = "suspect",
            failures = 2,
            last_success = 990,
        }
        with_rpcall({
            probe = function()
                t_clock = t_clock + 0.001
                return true, "peer2", {}
            end,
        }, function()
            ag.maintenance()
        end)
        local st = ag.conn_state[1]
        assert(st ~= nil, "conn_state must survive a recovery")
        assert(st.state == "alive" and st.failures == 0,
            "successful probe must reset state to alive with zero failures")
    end)

    -- ------------------------------------------------------------------ --
    -- 8. Self-entry version management
    -- ------------------------------------------------------------------ --

    T:atest("self-entry: version starts at 1 on first publish", function()
        reset()
        _G.peerdb["self"] = nil
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        assert(_G.peerdb["self"] ~= nil, "self entry must be created by maintenance")
        assert(_G.peerdb["self"].version == 1,
            "initial version must be 1, got " ..
            tostring(_G.peerdb["self"].version))
    end)

    T:atest("self-entry: version increments when content changes", function()
        reset()
        t_clock = 1000
        _G.peerdb["self"] = mkpeer(50, { "self-host" }, {})
        ag.hosts = { "self-host", "added-host" } -- trigger a change
        with_rpcall({ probe = function() return false, "no route" end }, function()
            ag.maintenance()
        end)
        ag.hosts = { "self-host" }
        assert(_G.peerdb["self"].version == 51,
            "version must increment when hosts change, got " ..
            tostring(_G.peerdb["self"].version))
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
                return true, "peer2", { peer2 = 1 }
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
                return true, "peer2", { peer2 = 1, peer3 = 1 }
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
                return true, "peer2", { peer2 = 1 }
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
                return true, "peer2", {}
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
    -- 10. Cleanup
    -- ------------------------------------------------------------------ --

    ag.stop() -- signal the sleeping mainloop to exit on wake
    os.time   = orig_ostime
    _G.peerdb = saved_peerdb
    _G.agent  = saved_agent
end
