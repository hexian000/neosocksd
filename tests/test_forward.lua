-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ test_forward.lua: end-to-end tests for await.forward() ]] --
-- Each request is routed through the local SOCKS proxy, exercising
-- ruleset.resolve() -> await.forward() -> relay.

return function(T, api_endpoint)
    -- route through our own SOCKS listener
    local socks_proxy = "socks4a://" .. neosocksd.config().listen

    T:atest("await.forward relays a request through the proxy", function()
        local target = { api_endpoint, socks_proxy }
        local ok, ret = await.rpcall(target, "echo", "via-forward")
        assert(ok, "rpcall through the proxy failed: " .. tostring(ret))
        assert(ret == "via-forward",
            string.format("expected 'via-forward', got %q", tostring(ret)))
    end)

    T:atest("await.forward relays repeatedly over fresh sessions", function()
        local target = { api_endpoint, socks_proxy }
        for i = 1, 4 do
            local ok, ret = await.rpcall(target, "echo", i)
            assert(ok, "rpcall through the proxy failed: " .. tostring(ret))
            assert(ret == i,
                string.format("expected %d, got %s", i, tostring(ret)))
        end
    end)

    T:atest("await.forward failover reaches a working upstream", function()
        -- routed (in tests/boot.lua) through a bad proxy, then direct
        local target = { "failover.test:80", socks_proxy }
        local ok, ret = await.rpcall(target, "echo", "failover-ok")
        assert(ok, "failover rpcall failed: " .. tostring(ret))
        assert(ret == "failover-ok",
            string.format("expected 'failover-ok', got %q", tostring(ret)))
    end)

    T:atest("await.forward failure is counted as a ruleset reject", function()
        -- falls through to route_default backends with no listener; the
        -- forward fails and the handler gives up, so the request is rejected
        -- by policy (a ruleset reject) and the rpcall errors
        local before = neosocksd.stats()
        local target = { "unreachable.invalid:80", socks_proxy }
        local ok = await.rpcall(target, "echo", "denied")
        assert(not ok,
            "expected the unreachable request to fail, but it succeeded")
        local after = neosocksd.stats()
        assert(after.num_reject_ruleset >= before.num_reject_ruleset + 1,
            "a failed forward must count as num_reject_ruleset")
        assert(after.num_reject_upstream == before.num_reject_upstream,
            "a failed forward must not count as num_reject_upstream")
    end)

    T:atest("policy reject after a failed forward is a ruleset reject", function()
        -- the handler forwards (fails), then returns nil; giving up without a
        -- successful forward always rejects by policy (a ruleset reject), never
        -- an upstream failure.
        local before = neosocksd.stats()
        local target = { "policyreject.test:80", socks_proxy }
        local ok = await.rpcall(target, "echo", "denied")
        assert(not ok, "expected the policy-rejected request to fail")
        local after = neosocksd.stats()
        assert(after.num_reject_ruleset >= before.num_reject_ruleset + 1,
            "a policy reject must count as num_reject_ruleset")
        assert(after.num_reject_upstream == before.num_reject_upstream,
            "a policy reject must not count as num_reject_upstream")
    end)
end
