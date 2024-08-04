_G.libruleset = require("libruleset")

-- interleaved weighted round robin
_G.route_default = { lb.iwrr({
    { 100, rule.redirect("10.0.0.1:30001") },
    { 100, rule.redirect("10.0.0.2:30001") },
    { 100, rule.redirect("10.0.0.3:30001") },
    { 100, rule.redirect("10.0.0.4:30001") },
    { 50,  rule.redirect("10.0.0.5:30001") },
}) }

logf("ruleset loaded, interpreter: %s", _VERSION)
return _G.libruleset
