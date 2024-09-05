-- neosocksd.lua: dummy lib for linter
error("dummy lib should not be loaded")

_G.NDEBUG = true
_G.async = pcall
_G.marshal = function(...)
    return ""
end


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

local regex_mt = { __index = regex }
function regex.compile(pattern)
    return setmetatable({}, regex_mt)
end

_G.regex = regex


local zlib = {}

function zlib.compress(s) return "" end

function zlib.uncompress(z) return "" end

_G.zlib = zlib
