#!/usr/bin/env lua
-- [[ gen_biglist.lua: handy script to generate "big" rule lists ]] --
-- usage: lua gen_biglist.lua "biglist.cidr" "biglist.ipv6" "domain-list.txt"

-- marshal plain data object as Lua code
function _G.marshal(...)
    local visited, cached = {}, setmetatable({}, { __mode = "kv" })
    local numtype = math.type
    local strbuild = table.concat
    local strformat = string.format
    local marshaler
    local function marshal_string(v)
        return strformat("%q", v)
    end
    local function marshal_number(v)
        if numtype(v) == "integer" then
            if v > 999999999999 or v == math.mininteger then
                return strformat("0x%x", v)
            end
            if v < -999999999999 then
                return strformat("-0x%x", -v)
            end
        end
        if v ~= v then return "0/0" end
        if v == math.huge then return "1/0" end
        if v == -math.huge then return "-1/0" end
        return tostring(v)
    end
    local function marshal_value(v)
        local m = marshaler[type(v)]
        if not m then
            error(type(v) .. " is not marshallable")
        end
        return m(v)
    end
    local function marshal_table(t)
        local str = cached[t]
        if str then
            return str
        end
        if visited[t] then
            error("circular referenced table is not marshallable")
        end
        visited[t] = true
        local mt = getmetatable(t)
        if mt and mt.__marshal then
            str = mt.__marshal(t)
            cached[t] = str
            return str
        end
        local w, n = {}, 0
        local max_index = 0
        for i, v in ipairs(t) do
            n = n + 1
            w[n] = marshal_value(v)
            max_index = i
        end
        for k, v in pairs(t) do
            if numtype(k) == "integer" and
                1 <= k and k <= max_index then
                -- already marshalled
            else
                local kstr = marshal_value(k)
                local vstr = marshal_value(v)
                n = n + 1
                w[n] = strformat("[%s]=%s", kstr, vstr)
            end
        end
        str = "{" .. strbuild(w, ",") .. "}"
        cached[t] = str
        return str
    end
    marshaler = {
        ["table"] = marshal_table,
        ["userdata"] = marshal_table,
        ["string"] = marshal_string,
        ["number"] = marshal_number,
        ["boolean"] = tostring,
        ["nil"] = type,
    }
    local n, w = select("#", ...), {}
    for i = 1, n do
        local v = select(i, ...)
        w[i] = marshal_value(v)
    end
    return strbuild(w, ",")
end

local function parse_cidr(filename)
    local t, n = {}, 0
    for line in io.lines(filename) do
        if line:find("/%d+$") then
            n = n + 1
            t[n] = line
        end
    end
    return t
end

local function parse_list(filename)
    local domain = {}
    local host = {}
    local regex = {}
    for line in io.lines(filename) do
        if line:find("^regexp:") then
            local s = line:match("^regexp:(.*)$")
            s = s:gsub("\\d", "[0-9]")
            table.insert(regex, s)
        elseif line:find("^full:") then
            local s = line:match("^full:(.*)$")
            table.insert(host, s)
        elseif line ~= "" then
            table.insert(domain, line)
        end
    end
    return domain, host, regex
end

function main(args)
    assert(args[1] and args[2] and args[3], "3 arguments required")
    local cidr = parse_cidr(args[1])
    local cidr6 = parse_cidr(args[2])
    local domain, host, regex = parse_list(args[3])
    local f = io.stdout
    f:write(string.format("_G.biglist_raw={ cidr=%s, cidr6=%s, domain=%s, host=%s, regex=%s }\n",
        marshal(cidr), marshal(cidr6), marshal(domain), marshal(host), marshal(regex)))
    f:close()
    return 0
end

os.exit(main({ ... }))
