local libruleset = require("libruleset")

-- [[ configurations ]] --
function _G.is_enabled()
    -- if false, new connections are rejected
    return true
end

-- 1. unordered hosts map
_G.hosts = {
    ["gateway.region1.lan"] = "192.168.32.1",
    ["host123.region1.lan"] = "192.168.32.123",
    ["gateway.region2.lan"] = "192.168.33.1",
    ["host123.region2.lan"] = "192.168.33.123",
    -- self-assignment
    ["neosocksd.lan"] = "127.0.1.1" -- see _G.redirect
}

-- 2. ordered redirect rules
-- in {matcher, action, optional log tag}
-- matching stops after a match is found
_G.redirect_name = {
    -- pass to region1 proxy
    [1] = {match.exact("region1.neosocksd.lan:80"), rule.redirect("192.168.32.1:1080", "neosocksd.lan:80")},
    -- jump to region2 through region1 proxy
    [2] = {match.exact("region2.neosocksd.lan:80"),
           rule.redirect("192.168.32.1:1080", "192.168.33.1:1080", "neosocksd.lan:80")},
    -- access mDNS sites directly, _G.route/_G.route6 are skipped
    [3] = {match.domain(".local"), rule.direct(), "local"},
    -- no default action
    [0] = nil
}

_G.redirect = {
    -- redirect API address, or loopback will be rejected
    [1] = {match.exact("127.0.1.1:80"), rule.redirect("127.0.1.1:9080")},
    -- no default action, go to _G.route
    [0] = nil
}

-- _G.redirect6 is not set

-- 3. ordered routes
_G.route = {
    -- reject loopback or link-local
    [1] = {inet.subnet("127.0.0.0/8"), rule.reject()},
    [2] = {inet.subnet("169.254.0.0/16"), rule.reject()},
    -- region1 proxy
    [3] = {inet.subnet("192.168.32.0/24"), rule.proxy("192.168.32.1:1080"), "region1"},
    -- jump to region2 through region1 proxy
    [4] = {inet.subnet("192.168.33.0/24"), rule.proxy("192.168.32.1:1080", "192.168.33.1:1080"), "region2"},
    -- access other lan addresses directly
    [5] = {inet.subnet("192.168.0.0/16"), rule.direct(), "lan"},
    -- dynamically loaded big IP ranges list
    [6] = {composite.maybe(_G, "countryip"), rule.proxy("proxy.lan:1080"), "countryip"},
    -- no default action, go to _G.route_default
    [0] = nil
}

_G.route6 = {
    -- reject loopback or link-local
    [1] = {inet6.subnet("::1/128"), rule.reject()},
    [2] = {inet6.subnet("fe80::/10"), rule.reject()},
    [3] = {inet6.subnet("::ffff:127.0.0.0/104"), rule.reject()},
    [4] = {inet6.subnet("::ffff:169.254.0.0/112"), rule.reject()},
    -- dynamically loaded big IP ranges list
    [5] = {composite.maybe(_G, "countryip6"), rule.proxy("proxy.lan:1080"), "countryip"},
    -- default action
    [0] = rule.direct()
}

-- 4. the global default applies to any unmatched requests
_G.server_list = {"127.0.0.1:1081", "127.0.0.2:1081"}
_G.server_index = 1
_G.route_default = rule.proxy(server_list[server_index])

function _G.change_route()
    server_index = server_index % #server_list + 1
    _G.route_default = rule.proxy(server_list[server_index])
    logf("change route: [%d] %q", server_index, server_list[server_index])
end

local function portal_test()
    -- if failed, change default route
    os.execute([[(
        if ! curl -m 15 -sx "socks5h://127.0.0.1:1080" "https://cp.cloudflare.com/generate_204"; then
            curl -sx "socks5h://127.0.0.1:1080" "http://neosocksd.lan/ruleset/invoke" \
                -d "change_route()"
        fi
    ) &]])
end

local ruleset = setmetatable({}, {
    __index = libruleset
})

function ruleset.tick(now)
    portal_test()
    return libruleset.tick(now)
end

function ruleset.stats(dt)
    local w = list:new()
    w:insertf("%-20s: [%d] %q", "Default Route", server_index, server_list[server_index])
    w:insert(libruleset.stats(dt))
    return w:concat("\n")
end

logf("ruleset loaded, interpreter: %s", _VERSION)
return ruleset
