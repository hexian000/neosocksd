-- neosocksd.lua: dummy lib for linter
error("dummy lib should not be loaded")

_G.NDEBUG = true
_G.marshal = function(...)
    return ""
end


local async = setmetatable({}, {
    __call = function(_, f, ...)
        return true, f(...)
    end,
})

function async.wait(t) return true end

_G.async = async


local await = {}

function await.resolve(s) return "" end

function await.invoke(code, addr, ...) return false, ... end

function await.sleep(n) end

function await.idle() end

_G.await = await


local neosocksd = {}

function neosocksd.resolve(s) return "" end

function neosocksd.parse_ipv4(s) return 0 end

function neosocksd.parse_ipv6(s) return 0, 0 end

function neosocksd.setinterval(n) end

function neosocksd.invoke(code, addr, ...) end

function neosocksd.stats() return {} end

function neosocksd.now() return 0 end

_G.neosocksd = neosocksd


local regex = {}

function regex:find(s, init)
    return 0, 0
end

function regex:match(s, init)
    return s
end

function regex:gmatch(s, init)
    return function()
        init = init + 1
        return self:match(s, init)
    end
end

local regex_mt = { __index = regex }
function regex.compile(pattern)
    return setmetatable({}, regex_mt)
end

_G.regex = regex


local zlib = {}

function zlib.compress(s) return "" end

function zlib.uncompress(z) return "" end

_G.zlib = zlib
