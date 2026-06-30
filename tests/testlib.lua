-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ testlib.lua: minimal test framework for neosocksd Lua tests ]] --
--
-- Mirrors the C testing_main() convention from contrib/csnippets/utils/testing.h:
-- two independent filters select which suite entries run. TESTING_FILTER selects
-- cases (with no value every case runs); TESTING_BENCH selects benchmarks (with
-- no value no benchmark runs). Matching cases run first, then matching benches
-- run last. Each filter is a POSIX extended regular expression matched as an
-- unanchored substring against the entry's "<suite>/<name>".
--
-- This embedding has no argv, so the filters come from the TESTING_FILTER and
-- TESTING_BENCH environment variables only (the same fallbacks testing_main uses
-- when --run / --bench are absent); an empty value means no filter. To run every
-- case and every benchmark, set both, e.g.
-- TESTING_FILTER=. TESTING_BENCH=. neosocksd -c tests/boot.lua.

local M = {}
local M_mt = { __index = M }

-- filter: compiled TESTING_FILTER (selects cases), or nil when absent.
-- benchfilter: compiled TESTING_BENCH (selects benches), or nil when absent.
local filter, benchfilter
do
    local pat = os.getenv("TESTING_FILTER")
    if pat and pat ~= "" then
        filter = regex.compile(pat)
    end
    pat = os.getenv("TESTING_BENCH")
    if pat and pat ~= "" then
        benchfilter = regex.compile(pat)
    end
end

-- selected reports whether the case `name` runs under TESTING_FILTER; an absent
-- filter selects everything.
local function selected(name)
    return not filter or filter:find(name) ~= nil
end

-- benchselected reports whether the benchmark `name` runs: benchmarks run only
-- when TESTING_BENCH is set, then only those it matches (see runbenches).
local function benchselected(name)
    return benchfilter ~= nil and benchfilter:find(name) ~= nil
end

-- record tallies an outcome on the counter-owning context `t` and prints it.
local function record(t, name, ok, err)
    if ok then
        t.passed = t.passed + 1
        printf("[PASS] %s", name)
    else
        t.failed = t.failed + 1
        printf("[FAIL] %s\n%s", name, tostring(err))
    end
end

-- runtest runs a synchronous case unless the filter excludes it.
local function runtest(t, name, fn)
    if not selected(name) then
        return
    end
    record(t, name, xpcall(fn, neosocksd.traceback))
end

-- runatest runs an async case (from within a fresh async context) unless the
-- filter excludes it.
local function runatest(t, name, fn)
    if not selected(name) then
        return
    end
    record(t, name, async(fn):get())
end

function M.new(name)
    return setmetatable({
        name = name,
        passed = 0,
        failed = 0,
        skipped = 0,
        benched = 0,
        benches = {},
    }, M_mt)
end

function M:test(name, fn)
    runtest(self, string.format("%s/%s", self.name, name), fn)
end

-- atest must be called from within an async context
function M:atest(name, fn)
    runatest(self, string.format("%s/%s", self.name, name), fn)
end

-- bench registers a benchmark; iters is the total number of operations fn
-- performs. bench must be called from within an async context.
-- Benchmarks are deferred and run last by report(), and only those selected by
-- TESTING_BENCH (benches never run without TESTING_BENCH set).
function M:bench(name, iters, fn)
    table.insert(self.benches, {
        name = string.format("%s/%s", self.name, name),
        iters = iters,
        fn = fn,
    })
end

-- runbenches executes the deferred benchmarks selected by TESTING_BENCH. Called
-- by report() only when TESTING_BENCH is set, mirroring testing_main (benches
-- run last and only when --bench / TESTING_BENCH is given).
function M:runbenches()
    for _, b in ipairs(self.benches) do
        if benchselected(b.name) then
            -- time.monotonic() reads the real clock; neosocksd.now() is the
            -- cached event-loop timestamp and only advances when the benchmark
            -- yields, so it underreports (zero) for purely synchronous,
            -- CPU-bound benchmarks.
            local begin = time.monotonic()
            b.fn()
            local cost = (time.monotonic() - begin) / b.iters
            printf("[BENCH] %-32s %d ns/op, %.0f tps",
                b.name, math.ceil(cost * 1e+9), 1.0 / cost)
            self.benched = self.benched + 1
        end
    end
end

function M:sub(name)
    local parent = self
    return {
        name = name,
        test = function(sub, tname, fn)
            runtest(parent, string.format("%s/%s", sub.name, tname), fn)
        end,
        atest = function(sub, tname, fn)
            runatest(parent, string.format("%s/%s", sub.name, tname), fn)
        end,
        bench = function(sub, bname, iters, fn)
            table.insert(parent.benches, {
                name = string.format("%s/%s", sub.name, bname),
                iters = iters,
                fn = fn,
            })
        end,
    }
end

function M:report()
    if benchfilter then
        self:runbenches()
    end
    if (filter or benchfilter) and self.passed + self.failed + self.skipped + self.benched == 0 then
        printf("[%s] no entries matched filter", self.name)
    end
    printf("[%s] passed=%d, failed=%d, skipped=%d, benched=%d",
        self.name, self.passed, self.failed, self.skipped, self.benched)
    return self.failed == 0
end

return M
