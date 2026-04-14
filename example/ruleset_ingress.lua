_G.libruleset = require("libruleset")

local ruleset = {}

_G.secrets = {
    ["lamer"] = "secret",
}

local API_ENDPOINT = "api.neosocksd.internal:80"

_G.redirect_name = {
    { match.domain({ ".local", ".lan", ".internal" }), rule.reject() },

    { composite.maybe(_G, "biglist_name"),             rule.direct(), "chn" },
}

_G.redirect = {
}

_G.route = {
    -- reject non-global
    { inet.subnet("224.0.0.0/4"),     rule.reject() },
    { inet.subnet("0.0.0.0/8"),       rule.reject() },
    { inet.subnet("127.0.0.0/8"),     rule.reject() },
    { inet.subnet("10.0.0.0/8"),      rule.reject() },
    { inet.subnet("172.16.0.0/12"),   rule.reject() },
    { inet.subnet("169.254.0.0/16"),  rule.reject() },
    { inet.subnet("192.168.0.0/16"),  rule.reject() },
    { inet.subnet("192.0.0.0/24"),    rule.reject() },
    { inet.subnet("127.0.0.0/8"),     rule.reject() },
    { inet.subnet("169.254.0.0/16"),  rule.reject() },
    -- custom rules
    { composite.maybe(_G, "biglist"), rule.direct(), "chn" },
}

_G.route6 = {
    { composite.maybe(_G, "biglist6"), rule.direct(), "chn" },
    { match.any(),                     rule.direct() },
}

_G.route_default = { rule.proxy("socks4a://127.0.1.1:1081"), "default" }

local function update_biglist(last_updated)
    await.sleep(0)
    local target = { API_ENDPOINT, "socks4a://127.0.1.1:1081" }
    local ok, data = await.rpcall(target, "update", last_updated)
    if not ok then
        evlogf("ruleset update: %s", data)
        return
    end
    if not data then return end
    await.sleep(0)
    if data.biglists then
        _G.biglist = inet.subnet(data.biglists.cidr)
        _G.biglist6 = inet6.subnet(data.biglists.cidr6)
        _G.biglist_name = composite.anyof({
            match.domain(data.biglists.domain),
            match.host(data.biglists.host),
            match.regex(data.biglists.regex),
        })
    end
    evlogf("ruleset updated: %s", format_timestamp(data.timestamp))
    ruleset.last_updated = data.timestamp
end

function ruleset.tick()
    libruleset.tick()
    local last_updated = table.get(_G, "ruleset", "last_updated")
    if not last_updated or os.time() - last_updated > 24 * 3600 then
        async(update_biglist, last_updated)
    end
end

local function main(...)
    async(update_biglist, nil)
    neosocksd.setinterval(60)
    -- inherit undefined fields from libruleset
    return setmetatable(ruleset, {
        __index = function(_, k)
            return _G.libruleset[k]
        end
    })
end

evlogf("ruleset loaded, interpreter: %s", _VERSION)
return main(...)
