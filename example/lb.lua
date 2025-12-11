-- [[ lb.lua: load balancer example ]] --
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
    _G.route_default = { lb.iwrr(t) }
end
rebuild()

function rpc.set_weight(s, w)
    logf("rpc.set_weight(%q, %q)", s, w)
    local old = backends[s]
    backends[s] = w
    rebuild()
    return old
end

function rpc.set_backends(t)
    logf("rpc.set_backends(%s)", marshal(t))
    local old = backends
    backends = t or backends
    rebuild()
    return old
end

local function main(...)
    neosocksd.setinterval(60.0)
    return _G.libruleset
end

evlogf("ruleset loaded, interpreter: %s", _VERSION)
return main(...)
