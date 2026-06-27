-- neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
-- This code is licensed under MIT license (see LICENSE for details)

-- [[ testlib.lua: minimal test framework for neosocksd Lua tests ]] --
--
-- Mirrors the C testing_main() convention from contrib/csnippets/utils/testing.h:
-- a filter selects which suite entries run. With no filter every case runs and
-- all benches are skipped; with a filter only matching cases run, then matching
-- benches run last. The filter is a POSIX extended regular expression matched as
-- an unanchored substring against the entry's "<suite>/<name>".
--
-- This embedding has no argv, so the filter comes from the TESTING_FILTER
-- environment variable only (the same fallback testing_main uses when --run is
-- absent); an empty value means no filter. To run every case and every
-- benchmark, set TESTING_FILTER=. (e.g. TESTING_FILTER=. neosocksd -c tests/boot.lua).

local M = {}
local M_mt = { __index = M }

-- filter: compiled TESTING_FILTER, or nil when no filter is active.
local filter
do
    local pat = os.getenv("TESTING_FILTER")
    if pat and pat ~= "" then
        filter = regex.compile(pat)
    end
end

-- selected reports whether the entry `name` runs under the current filter.
-- An absent filter selects everything (used for cases; benches additionally
-- require a filter to be present, see runbenches).
local function selected(name)
    return not filter or filter:find(name) ~= nil
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
-- the TESTING_FILTER (benches never run without a filter).
function M:bench(name, iters, fn)
    table.insert(self.benches, {
        name = string.format("%s/%s", self.name, name),
        iters = iters,
        fn = fn,
    })
end

-- runbenches executes the deferred benchmarks selected by the filter. Called by
-- report() only when a filter is active, mirroring testing_main (benches run
-- last and only under a filter).
function M:runbenches()
    for _, b in ipairs(self.benches) do
        if selected(b.name) then
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
    if filter then
        self:runbenches()
    end
    if filter and self.passed + self.failed + self.skipped + self.benched == 0 then
        printf("[%s] no entries matched filter", self.name)
    end
    printf("[%s] passed=%d, failed=%d, skipped=%d, benched=%d",
        self.name, self.passed, self.failed, self.skipped, self.benched)
    return self.failed == 0
end

return M
