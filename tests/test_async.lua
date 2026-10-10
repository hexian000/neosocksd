-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ test_async.lua: tests for async/await primitives ]] --

return function(T)
    T:atest("await.execute returns ok on success", function()
        -- await.execute returns (ok, "exit"|"signal", code)
        local ok, kind, code = await.execute("true")
        assert(ok == true,  string.format("expected ok, got %s", tostring(ok)))
        assert(kind == "exit")
        assert(code == 0,   string.format("expected exit code 0, got %d", code))
    end)

    T:atest("await.execute returns nil on failure", function()
        local ok, kind, code = await.execute("false")
        assert(ok == nil,  string.format("expected nil, got %s", tostring(ok)))
        assert(kind == "exit")
        assert(code ~= 0,  string.format("expected non-zero, got %d", code))
    end)

    T:atest("await.sleep suspends for at least the requested duration", function()
        local t0 = neosocksd.now()
        await.sleep(0.05)
        local elapsed = neosocksd.now() - t0
        assert(elapsed >= 0.04, string.format(
            "sleep(0.05) returned too early: %.3fms", elapsed * 1e3))
    end)

    T:atest("await.callback wraps sync callback", function()
        local result = await.callback(function(cb, val)
            cb(val)
        end, "HELLO")
        assert(result == "HELLO", string.format(
            "expected %q, got %q", "HELLO", tostring(result)))
    end)

    T:atest("await.callback wraps async callback", function()
        local result = await.callback(function(cb, val)
            -- The callback is deferred to a new coroutine so that
            -- the outer coroutine actually yields before cb is called.
            async(function()
                await.sleep(0)
                cb(val)
            end)
        end, "DEFERRED")
        assert(result == "DEFERRED", string.format(
            "expected %q, got %q", "DEFERRED", tostring(result)))
    end)

    T:atest("await.callback preserves trailing nils", function()
        -- Regression: the synchronous fast path stored the callback's
        -- arguments in a plain table and unpacked it with #, so trailing nils
        -- were lost -- cb(nil) even returned no value at all.
        local n = select('#', await.callback(function(cb)
            cb(nil)
        end))
        assert(n == 1, string.format("expected 1 value, got %d", n))
        local a, b, c = await.callback(function(cb)
            cb("HELLO", nil, nil)
        end)
        assert(a == "HELLO" and b == nil and c == nil)
        n = select('#', await.callback(function(cb)
            cb("HELLO", nil, nil)
        end))
        assert(n == 3, string.format("expected 3 values, got %d", n))
        -- the deferred path resumes the coroutine directly and already kept
        -- the count; pin it so the two paths cannot drift apart
        n = select('#', await.callback(function(cb)
            async(function()
                await.sleep(0)
                cb("HELLO", nil, nil)
            end)
        end))
        assert(n == 3, string.format("expected 3 deferred values, got %d", n))
    end)

    T:atest("future:get preserves trailing nils", function()
        -- Regression: the result is table.pack'ed with its true count in .n,
        -- but was unpacked with #, which is undefined for a table with holes
        -- and demonstrably short when the last packed value is nil.
        local t = async(function()
            await.sleep(0)
            return nil, nil
        end)
        local r = table.pack(t:get())
        assert(r.n == 3, string.format("expected ok plus 2 values, got %d", r.n))
        assert(r[1] == true and r[2] == nil and r[3] == nil)
        -- an already-finished future takes the fast path in get()
        local n = select('#', t:get())
        assert(n == 3, string.format("expected 3 values on re-get, got %d", n))
    end)

    T:atest("async captures error in future", function()
        local t = async(function()
            await.sleep(0)
            error("EXPECTED_ERROR")
        end)
        local ok, err = t:get()
        assert(not ok, "expected future to carry an error")
        assert(err and err:find("EXPECTED_ERROR"),
            string.format("unexpected error message: %q", tostring(err)))
    end)

    T:atest("multiple waiters receive same future result", function()
        local t = async(function()
            await.sleep(0)
            error("FROM_PRODUCER")
        end)
        local w1 = async(function()
            local ok, err = t:get()
            assert(not ok)
            assert(err and err:find("FROM_PRODUCER"))
        end)
        local w2 = async(function()
            local ok, err = t:get()
            assert(not ok and err)
        end)
        local ok1, e1 = w1:get()
        assert(ok1, tostring(e1))
        local ok2, e2 = w2:get()
        assert(ok2, tostring(e2))
    end)

end
