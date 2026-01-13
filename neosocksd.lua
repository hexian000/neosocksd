-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ neosocksd.lua: dummy lib for linter ]] --
error("dummy lib should not be loaded")

local function marshal(...)
    return ""
end
_G.marshal = marshal


local await = {}

function await.execute(command) return 0 end

function await.invoke(code, addr, ...) return false, ... end

function await.resolve(s) return "" end

function await.sleep(n) end

_G.await = await


local neosocksd = {}

function neosocksd.async(finish, func, ...) return coroutine.create(func), nil end

function neosocksd.config() return {} end

function neosocksd.invoke(code, addr, ...) end

function neosocksd.now() return 0 end

function neosocksd.parse_ipv4(s) return 0 end

function neosocksd.parse_ipv6(s) return 0, 0 end

function neosocksd.resolve(s) return "" end

function neosocksd.setinterval(n) end

function neosocksd.splithostport(s) return "", "" end

function neosocksd.stats() return {} end

function neosocksd.traceback(s) return debug.traceback(s) end

_G.neosocksd = neosocksd


local regex = {
    EXTENDED = 1,
    ICASE = (1 << 1),
    NEWLINE = (1 << 2),
    NOSUB = (1 << 3),
}

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
function regex.compile(pattern, cflags)
    return setmetatable({}, regex_mt)
end

_G.regex = regex


local time = {}

function time.monotonic() return -1 end

function time.process() return -1 end

function time.thread() return -1 end

function time.wall() return -1 end

function time.measure(f, ...) return -1, f(...) end

_G.time = time


local zlib = {}

function zlib.compress(s) return "" end

function zlib.uncompress(z) return "" end

_G.zlib = zlib
