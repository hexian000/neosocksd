-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ testlib.lua: minimal test framework for neosocksd Lua tests ]] --

local M = {}
local M_mt = { __index = M }

function M.new(name)
    return setmetatable({ name = name, passed = 0, failed = 0 }, M_mt)
end

function M:test(name, fn)
    local ok, err = xpcall(fn, neosocksd.traceback)
    if ok then
        self.passed = self.passed + 1
        printf("[PASS] %s/%s", self.name, name)
    else
        self.failed = self.failed + 1
        printf("[FAIL] %s/%s\n%s", self.name, name, err)
    end
end

-- atest must be called from within an async context
function M:atest(name, fn)
    local t = async(fn)
    local ok, err = t:get()
    if ok then
        self.passed = self.passed + 1
        printf("[PASS] %s/%s", self.name, name)
    else
        self.failed = self.failed + 1
        printf("[FAIL] %s/%s\n%s", self.name, name, tostring(err))
    end
end

-- bench measures throughput; iters is the total number of operations fn performs
-- bench must be called from within an async context
function M:bench(name, iters, fn)
    local begin = neosocksd.now()
    fn()
    local cost = (neosocksd.now() - begin) / iters
    printf("[BENCH] %-32s %d ns/op, %.0f tps",
        name, math.ceil(cost * 1e+9), 1.0 / cost)
end

function M:sub(name)
    local parent = self
    return {
        name = name,
        test = function(self, tname, fn)
            local ok, err = xpcall(fn, neosocksd.traceback)
            if ok then
                parent.passed = parent.passed + 1
                printf("[PASS] %s/%s", self.name, tname)
            else
                parent.failed = parent.failed + 1
                printf("[FAIL] %s/%s\n%s", self.name, tname, err)
            end
        end,
        atest = function(self, tname, fn)
            local t = async(fn)
            local ok, err = t:get()
            if ok then
                parent.passed = parent.passed + 1
                printf("[PASS] %s/%s", self.name, tname)
            else
                parent.failed = parent.failed + 1
                printf("[FAIL] %s/%s\n%s", self.name, tname, tostring(err))
            end
        end,
    }
end

function M:report()
    printf("[%s] passed=%d, failed=%d", self.name, self.passed, self.failed)
    return self.failed == 0
end

return M
