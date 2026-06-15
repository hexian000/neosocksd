-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ testlib.lua: minimal test framework for neosocksd Lua tests ]] --

local M = {}
local M_mt = { __index = M }

function M.new(name)
    return setmetatable({ name = name, passed = 0, failed = 0, benches = {} }, M_mt)
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

-- bench registers a benchmark; iters is the total number of operations fn performs.
-- bench must be called from within an async context.
-- Benchmarks are deferred. They only run when all tests pass AND the BENCH
-- environment variable is set (e.g. BENCH=1 neosocksd -c tests/boot.lua).
function M:bench(name, iters, fn)
    table.insert(self.benches, { name = name, iters = iters, fn = fn })
end

-- runbenches executes all deferred benchmarks. Called by report() when
-- all tests have passed and the BENCH environment variable is set.
function M:runbenches()
    for _, b in ipairs(self.benches) do
        local begin = neosocksd.now()
        b.fn()
        local cost = (neosocksd.now() - begin) / b.iters
        printf("[BENCH] %-32s %d ns/op, %.0f tps",
            b.name, math.ceil(cost * 1e+9), 1.0 / cost)
    end
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
        bench = function(self, bname, iters, fn)
            table.insert(parent.benches, { name = string.format("%s/%s", self.name, bname), iters = iters, fn = fn })
        end,
    }
end

function M:report()
    if self.failed == 0 and #self.benches > 0 and os.getenv("BENCH") then
        printf("[%s] all tests passed, running %d benchmark(s)...", self.name, #self.benches)
        self:runbenches()
    end
    printf("[%s] passed=%d, failed=%d", self.name, self.passed, self.failed)
    return self.failed == 0
end

return M
