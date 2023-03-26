# neosocksd

A lightweight programmable SOCKS4 / SOCKS4A / SOCKS5 / HTTP proxy server that only supports TCP CONNECT requests.

## Features

- Plain old protocols with no built-in support for authentication or encryption.
- Lua scripts powered rule set.
- RESTful API for monitoring and hot reloading of rulesets.
- IPv6 supported (SOCKS4A / SOCKS5 / HTTP).
- Almost minimal resource usage, embedded system friendly.
- Compliant with: ISO C11, POSIX.1-2008.

## Basic Usage

```sh
./neosocksd -4 -l 0.0.0.0:1080  # Just an IPv4 SOCKS server
./neosocksd --http -l 0.0.0.0:8080  # HTTP CONNECT server
./neosocksd -l 0.0.0.0:80 -f 127.0.0.1:8080  # Non-forking TCP port forwarder
```

## Scripting Usage

Start the server with a Lua script named "ruleset.lua":

```sh
./neosocksd -4 -l 0.0.0.0:1080 --api 127.0.0.1:9080 -r ruleset.lua
```

The following code snippets show how to use rulesets to manipulate server behavior.

Full code example at [ruleset.lua](ruleset.lua)

```Lua
local hosts = {
    ["gateway.region1.lan"] = "192.168.32.1",
    ["host123.region1.lan"] = "192.168.32.123",
    ["gateway.region2.lan"] = "192.168.33.1",
    ["host123.region2.lan"] = "192.168.33.123"
}

local routes = {
    ["192.168.32."] = {"192.168.32.1:1080"},
    -- reach region2 via region1 gateway
    ["192.168.33."] = {"192.168.33.1:1080", "192.168.32.1:1080"}
}

--[[
    ruleset.resolve(domain) process a host name request
    	i.e. HTTP CONNECT / SOCKS5 with host name ("socks5h" in cURL) / SOCKS4A
    <domain>: full qualified domain name and port, like "www.example.org:80"
    return <addr>: replace the request
    return <addr>, <proxy>: forward the request through another neosocksd
    return <addr>, <proxyN>, ..., <proxy1>: forward the request through proxy chain
    return nil: reject the request
]]
function ruleset.resolve(domain)
    printf("ruleset.resolve: %q", domain)
    local host, port = splithostport(domain)
    host = string.lower(host)
    -- redirect API domain
    if host == "neosocksd.lan" then
        return "127.0.0.1:9080"
    end
    -- lookup in hosts table
    local entry = hosts[host]
    if entry then
        return ruleset.route(string.format("%s:%s", entry, port))
    end
    -- reject other localnet
    if endswith(host, ".lan") or endswith(host, ".local") then
        return nil
    end
    -- accept
    return domain
end

--[[
    ruleset.route(addr) process an IPv4 request
        i.e. SOCKS5 with IPv4 / SOCKS4
    <addr>: address and port, like "8.8.8.8:53"
    returns: same as ruleset.resolve(addr)
]]
function ruleset.route(addr)
    printf("ruleset.route: %q", addr)
    local host, port = splithostport(addr)
    -- reject loopback or link-local
    if startswith(host, "127.") or startswith(host, "169.254.") then
        return nil
    end
    -- lookup in route table
    for prefix, route in pairs(routes) do
        if startswith(host, prefix) then
            return addr, table.unpack(route)
        end
    end
    -- direct lan access
    if startswith(host, "192.168.") then
        return addr
    end
    -- default gateway
    return addr, "192.168.1.1:1080"
end

--[[
    ruleset.route6(addr) process an IPv6 request
        i.e. SOCKS5 with IPv6
    <addr>: address and port, like "[::1]:80"
    returns: same as ruleset.resolve(addr)
]]
function ruleset.route6(addr)
    printf("ruleset.route6: %q", addr)
    -- reject any ipv6
    return nil
end
```

Access RESTful API through the proxy (as defined in the ruleset above):

```sh
curl -x socks5h://127.0.0.1:1080 http://neosocksd.lan/stats
```

Update ruleset without restarting:

```sh
curl -X POST -vx socks5h://127.0.0.1:1080 \
    http://neosocksd.lan/ruleset?update \
    --data-binary @ruleset.lua
```
