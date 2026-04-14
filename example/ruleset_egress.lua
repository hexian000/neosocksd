_G.libruleset = require("libruleset")

local ruleset = {}

local API_ENDPOINT = "api.neosocksd.internal:80"
-- { url, local_filename } pairs; files are downloaded in order and parsed in place.
-- cidr: one IPv4 CIDR per line, e.g. "1.2.3.0/24"
-- cidr6: one IPv6 CIDR per line
-- list: domain-list format (bare domain / "full:" host / "regexp:" pattern)
local BIGLIST_SOURCES = {
    { "https://example.invalid/ipv4.cidr",   "ipv4.cidr"  }, -- IPv4 CIDR list
    { "https://example.invalid/ipv6.cidr",   "ipv6.cidr"  }, -- IPv6 CIDR list
    { "https://example.invalid/domains.txt", "domains.txt"}, -- domain list
}

_G.redirect_name = {
    { match.exact("server.internal:22"),                  rule.redirect("127.0.0.1:22"),   "srv-ssh" },
    { match.exact(API_ENDPOINT),                          rule.redirect("127.0.1.1:9080"), "srv-api" },
    { match.domain({ ".local", ".lan", ".internal" }),    rule.reject() },

    { match.exact("1dot1dot1dot1.cloudflare-dns.com:53"), rule.redirect("127.0.0.53:53"),  "dns" },
    { match.exact("dns.google:53"),                       rule.redirect("127.0.0.53:53"),  "dns" },
}

_G.redirect = {
    { match.exact("1.1.1.1:53"), rule.redirect("127.0.0.53:53"), "dns" },
    { match.exact("1.0.0.1:53"), rule.redirect("127.0.0.53:53"), "dns" },
    { match.exact("8.8.8.8:53"), rule.redirect("127.0.0.53:53"), "dns" },
    { match.exact("8.8.4.4:53"), rule.redirect("127.0.0.53:53"), "dns" },
}

_G.route = {
    -- reject non-global addresses
    { inet.subnet("224.0.0.0/4"),    rule.reject() },
    { inet.subnet("0.0.0.0/8"),      rule.reject() },
    { inet.subnet("127.0.0.0/8"),    rule.reject() },
    { inet.subnet("10.0.0.0/8"),     rule.reject() },
    { inet.subnet("172.16.0.0/12"),  rule.reject() },
    { inet.subnet("169.254.0.0/16"), rule.reject() },
    { inet.subnet("192.168.0.0/16"), rule.reject() },
    { inet.subnet("192.0.0.0/24"),   rule.reject() },
}

_G.route6 = {
    { match.any(), rule.reject() },
}

_G.route_default = { rule.direct(), "outbound" }

function rpc.update(timestamp)
    local data = ruleset.data
    if not data or not data.timestamp or timestamp == data.timestamp then
        return nil
    end
    return data
end

local function shell_quote(s)
    return string.format("'%s'", s:gsub("'", "'\\''"))
end

local function rename_file(oldname, newname)
    local ok, err = os.rename(oldname, newname)
    if ok then
        return true
    end
    evlogf("failed to rename %s to %s: %s", oldname, newname, err)
    return nil
end

local function download_file(url, filename)
    local tmpname = filename .. ".new"
    local command = string.format(
        "wget -O %s %s",
        shell_quote(tmpname),
        shell_quote(url))
    local ok, what, code = await.execute(command)
    if not ok then
        evlogf("failed to download %s: %s %d", filename, what, code)
        return nil
    end
    return rename_file(tmpname, filename)
end

local function parse_cidr(filename)
    local f, err = io.open(filename, "r")
    if not f then
        return nil, err
    end
    local entries = {}
    for line in f:lines() do
        if line:find("/%d+$") then
            entries[#entries + 1] = line
        end
    end
    f:close()
    return entries
end

local function parse_list(filename)
    local f, err = io.open(filename, "r")
    if not f then
        return nil, nil, nil, err
    end
    local domain = {}
    local host = {}
    local regex = {}
    for line in f:lines() do
        if line:find("^regexp:") then
            local s = line:match("^regexp:(.*)$")
            regex[#regex + 1] = s:gsub("\\d", "[0-9]")
        elseif line:find("^full:") then
            host[#host + 1] = line:match("^full:(.*)$")
        elseif line ~= "" then
            domain[#domain + 1] = line
        end
    end
    f:close()
    return domain, host, regex
end

local function load_biglists()
    local cidr, err = parse_cidr(BIGLIST_SOURCES[1][2])
    if not cidr then
        evlogf("failed to parse %s: %s", BIGLIST_SOURCES[1][2], err)
        return nil
    end
    local cidr6, err6 = parse_cidr(BIGLIST_SOURCES[2][2])
    if not cidr6 then
        evlogf("failed to parse %s: %s", BIGLIST_SOURCES[2][2], err6)
        return nil
    end
    local domain, host, regex, err_list = parse_list(BIGLIST_SOURCES[3][2])
    if not domain then
        evlogf("failed to parse %s: %s", BIGLIST_SOURCES[3][2], err_list)
        return nil
    end
    return {
        cidr = cidr,
        cidr6 = cidr6,
        domain = domain,
        host = host,
        regex = regex,
    }
end

local function update_biglists()
    for _, source in ipairs(BIGLIST_SOURCES) do
        if not download_file(source[1], source[2]) then
            return
        end
    end
    local biglists = load_biglists()
    if not biglists then
        return
    end
    local data = {
        biglists = biglists,
        timestamp = os.time(),
    }
    ruleset.data = data
    evlogf("ruleset updated: %s", format_timestamp(data.timestamp))
end

function ruleset.tick()
    libruleset.tick()
    local last_updated = table.get(_G, "ruleset", "data", "timestamp")
    if not last_updated or os.time() - last_updated > 7 * 24 * 3600 then
        async(update_biglists)
    end
end

local function main(...)
    async(update_biglists)
    neosocksd.setinterval(60.0)
    -- inherit undefined fields from libruleset
    return setmetatable(ruleset, {
        __index = function(_, k)
            return _G.libruleset[k]
        end
    })
end

evlogf("ruleset loaded, interpreter: %s", _VERSION)
return main(...)
