_G.libruleset = require("libruleset")

_G.secrets = {
    ["lamer"] = "secret",
}

local function main(...)
    pcall(collectgarbage, "generational")
    neosocksd.setinterval(60.0)
    return _G.libruleset
end

logf("ruleset loaded, interpreter: %s", _VERSION)
return main(...)
