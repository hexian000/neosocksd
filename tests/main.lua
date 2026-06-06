-- [[ tests/main.lua: config entry point ]] --
-- Usage: neosocksd -c tests/main.lua
local mode = ...
assert(mode == "config")
return {
	listen   = "127.0.1.1:31080",
	restapi  = "127.0.1.1:39080",
	traceback = true,
	ruleset  = "tests/ruleset.lua",
}
