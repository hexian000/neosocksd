_G.libruleset = require("libruleset")

local backends = {
    ["10.0.0.1:30001"] = 100,
    ["10.0.0.2:30001"] = 100,
    ["10.0.0.3:30001"] = 100,
    ["10.0.0.4:30001"] = 100,
    ["10.0.0.5:30001"] = 50,
}

local function rebuild()
    local t = {}
    for s, w in pairs(backends) do
        table.insert(t, { w, rule.redirect(s) })
    end
    -- interleaved weighted round robin
    _G.route_default = { lb.iwrr(t) }
end
rebuild()

function rpc.set_weight(s, w)
    local old = backends[s]
    backends[s] = w
    rebuild()
    return old
end

function rpc.set_backends(t)
    local old = backends
    backends = t or backends
    rebuild()
    return old
end

logf("ruleset loaded, interpreter: %s", _VERSION)
return _G.libruleset
