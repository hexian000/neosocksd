_G.libruleset = require("libruleset")

local ruleset = {}

_G.route_default = { lb.roundrobin({
    rule.redirect("10.0.0.1:30001"),
    rule.redirect("10.0.0.2:30001"),
    rule.redirect("10.0.0.3:30001"),
    rule.redirect("10.0.0.4:30001"),
    rule.redirect("10.0.0.5:30001"),
}) }

logf("ruleset loaded, interpreter: %s", _VERSION)
-- inherit undefined fields from libruleset
return setmetatable(ruleset, {
    __index = function(t, k)
        return _G.libruleset[k]
    end
})
