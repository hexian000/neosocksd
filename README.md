# neosocksd

[![MIT License](https://img.shields.io/github/license/hexian000/neosocksd)](https://github.com/hexian000/neosocksd/blob/master/LICENSE)
[![Build](https://github.com/hexian000/neosocksd/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/neosocksd/actions/workflows/build.yml)
[![Lint](https://github.com/hexian000/neosocksd/actions/workflows/lint.yml/badge.svg)](https://github.com/hexian000/neosocksd/actions/workflows/lint.yml)
[![Release](https://img.shields.io/github/release/hexian000/neosocksd.svg?style=flat)](https://github.com/hexian000/neosocksd/releases)

A lightweight programmable SOCKS4 / SOCKS4A / SOCKS5 / HTTP proxy server that only supports TCP CONNECT requests.

## Features

- Plain old protocols with no built-in support for authentication or encryption.
- Top class processor/memory/storage/bandwidth efficiency.
- Lua scripts powered rule set.
- Routing connections by rule and even building an autonomous proxy mesh.
- Horizontally scalable.
- RESTful API for monitoring and updating rules online.
- IPv6 supported (SOCKS4A / SOCKS5 / HTTP).
- Minimized resource usage, embedded systems friendly.
- Compliant with: ISO C11, POSIX.1-2008.

## Basic Usage

```sh
./neosocksd -4 -l 0.0.0.0:1080  # Just an IPv4 SOCKS server
./neosocksd --http -l 0.0.0.0:8080  # HTTP CONNECT server
./neosocksd -l 0.0.0.0:80 -f 127.0.0.1:8080  # Non-forking TCP port forwarder
```

See ```./neosocksd -h``` for details.

## Scripting Usage

Start the server with a Lua script named "ruleset.lua":

```sh
./neosocksd -4 -l 0.0.0.0:1080 --api 127.0.0.1:9080 -r ruleset.lua
```

The following code snippets show how to use rulesets to manipulate server behavior.

Full code example at [ruleset.lua](ruleset.lua)

Syntax and standard libraries: [Lua 5.4 Reference Manual](https://www.lua.org/manual/5.4/manual.html)

```Lua
local hosts = {
    ["gateway.region1.lan"] = "192.168.32.1",
    ["host123.region1.lan"] = "192.168.32.123",
    ["gateway.region2.lan"] = "192.168.33.1",
    ["host123.region2.lan"] = "192.168.33.123"
}

local static_route = {
    -- bypass default gateway
    ["203.0.113.1"] = {}
}

local function route_default(addr)
    -- default gateway
    return addr, "192.168.1.1:1080"
end

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
    if not _G.is_enabled() then
        return nil
    end
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
    -- direct lan access
    if host:endswith(".lan") or host:endswith(".local") then
        return domain
    end
    -- accept
    return route_default(domain)
end

--[[
    ruleset.route(addr) process an IPv4 request
        i.e. SOCKS5 with IPv4 / SOCKS4
    <addr>: address and port, like "8.8.8.8:53"
    returns: same as ruleset.resolve(addr)
]]
function ruleset.route(addr)
    if not _G.is_enabled() then
        return nil
    end
    printf("ruleset.route: %q", addr)
    local host, port = splithostport(addr)
    -- static rule
    local exact_match = static_route[host]
    if exact_match then
        return addr, table.unpack(exact_match)
    end
    -- reject loopback or link-local
    if host:startswith("127.") or host:startswith("169.254.") then
        return nil
    end
    -- region1 gateway
    if addr:startswith("192.168.32.") then
        return addr, "192.168.32.1:1080"
    end
    -- jump to region2 via region1 gateway
    if addr:startswith("192.168.33.") then
        return addr, "192.168.33.1:1080", "192.168.32.1:1080"
    end
    -- direct lan access
    if host:startswith("192.168.") then
        return addr
    end
    -- accept
    return route_default(addr)
end

--[[
    ruleset.route6(addr) process an IPv6 request
        i.e. SOCKS5 with IPv6
    <addr>: address and port, like "[::1]:80"
    returns: same as ruleset.resolve(addr)
]]
function ruleset.route6(addr)
    if not _G.is_enabled() then
        return nil
    end
    printf("ruleset.route6: %q", addr)
    -- access any ipv6 directly
    return addr
end

--[[
    ruleset.tick(now)
    <now>: current timestamp in seconds
    returns: ignored
]]
function ruleset.tick(now)
    printf("ruleset.tick: %.03f", now)
end
-- neosocksd.setinterval(1.0)
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

## Build from source
### Dependencies

```sh
# Debian & Ubuntu
sudo apt install -y libev-dev liblua5.4-dev
```

### Build with CMake

```sh
git clone https://github.com/hexian000/neosocksd.git
mkdir "neosocksd-build"
cmake -DCMAKE_BUILD_TYPE="Release" \
    -S "neosocksd" \
    -B "neosocksd-build"
cmake --build "neosocksd-build" --parallel
```

See [m.sh](m.sh) for more information about cross compiling support.

## Credits

Thanks to:
- [libev](http://software.schmorp.de/pkg/libev.html)
- [lua](https://www.lua.org/)
