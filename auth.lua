_G.libruleset = require("libruleset")

_G.secrets = {
    ["lamer"] = "secret",
}

_G.route_default = { rule.proxy("socks4a://127.0.1.1:1081") }

local function main(...)
    pcall(collectgarbage, "generational")
    neosocksd.setinterval(60.0)
    return _G.libruleset
end

logf("ruleset loaded, interpreter: %s", _VERSION)
return main(...)
