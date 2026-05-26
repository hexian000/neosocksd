-- [[ tests/boot.lua: boot configuration for the integration test suite ]] --
-- Load with: neosocksd -c tests/boot.lua
return {
    listen   = "127.0.1.1:31080",
    restapi  = "127.0.1.1:39080",
    ruleset  = "tests/ruleset.lua",
    traceback = true,
}
