_G.libruleset = require("libruleset")

local ruleset = setmetatable({}, {
    __index = function(t, k)
        return _G.libruleset[k]
    end
})

local function check_update()
    os.execute([[ (
    HOSTNAME="$(cat /etc/hostname)"
    if curl -sLo /tmp/libruleset.lua "http://central.lan/neosocksd/${HOSTNAME}/libruleset.lua"; then
        curl -sX POST "http://127.0.1.1:9080/ruleset/update?module=libruleset" --data-binary @/tmp/libruleset.lua
        rm /tmp/libruleset.lua
    fi
    if curl -sLo /tmp/ruleset.lua "http://central.lan/neosocksd/${HOSTNAME}/ruleset.lua"; then
        curl -sX POST "http://127.0.1.1:9080/ruleset/update" --data-binary @/tmp/ruleset.lua
        rm /tmp/ruleset.lua
    fi
) & ]])
end

function ruleset.tick(now)
    queue_task(check_update)
    return libruleset.tick(now)
end
neosocksd.setinterval(60.0)

queue_task(check_update)
logf("ruleset stub loaded, interpreter: %s", _VERSION)
return ruleset
