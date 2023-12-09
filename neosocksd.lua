-- neosocksd.lua: dummy lib

_G.NDEBUG = true
_G.async = pcall


local await = {}

function await.resolve(s) return s end

function await.rpcall(code, addr, ...) return false, "" end

function await.sleep(n) end

function await.idle() end

_G.await = await


local neosocksd = {}

function neosocksd.resolve(s) return s end

function neosocksd.parse_ipv4(s) return 0 end

function neosocksd.parse_ipv6(s) return 0, 0 end

function neosocksd.setinterval(n) end

function neosocksd.invoke(code, addr, ...) end

function neosocksd.stats() return {} end

function neosocksd.now() return 0 end

_G.neosocksd = neosocksd


local regex = {}

function regex.compile(pat)
    return setmetatable({}, regex)
end

function regex.find(s)
    return 0, 0
end

function regex.match(s)
    return s
end

_G.regex = regex


local zlib = {}

function zlib.compress(s) return s end

function zlib.uncompress(s) return s end

_G.zlib = zlib
