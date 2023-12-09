-- neosocksd.lua: dummy lib

_G.NDEBUG = true
_G.neosocksd = {}
_G.regex = {}
_G.async = pcall
_G.await = {}

function neosocksd.resolve(s) return s end

function neosocksd.parse_ipv4(s) return 0 end

function neosocksd.parse_ipv6(s) return 0, 0 end

function neosocksd.setinterval(n) end

function neosocksd.invoke(code, addr, ...) end

function neosocksd.stats() return {} end

function neosocksd.now() return 0 end

function regex.compile(pat)
	return setmetatable({}, {
		["find"] = function(s)
			return 0, 0
		end,
		["match"] = function(s)
			return s
		end,
	})
end

function await.resolve(s) return s end

function await.rpcall(code, addr, ...) return false, "" end

function await.sleep(n) end

function await.idle() end
