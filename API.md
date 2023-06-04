# neosocksd API Reference

Version: v1.0

## Index

- [RESTful API](#restful-api)
- [Ruleset Callbacks](#ruleset-callbacks)
- [Lua API](#lua-api)

## RESTful API

*The RESTful API server runs HTTP/1.0*

### Healthy Check

Check server liveness.

- **Path**: /healthy
- **Method**: Any
- **Status**: HTTP 200

### Server Statistics

Calculate server statistics since the last call.

- **Path**: /stats
- **Method**: GET
- **Status**: HTTP 200
- **Response**: Server statistics in plain text.

### Ruleset Invoke

Run the posted script.

- **Path**: /ruleset/invoke
- **Method**: POST
- **Content**: Lua script
- **Status**: HTTP 200, HTTP 405, HTTP 500

### Ruleset Update

Replace ruleset with the posted script.

- **Path**: /ruleset/update
- **Method**: POST
- **Content**: Lua ruleset script
- **Status**: HTTP 200, HTTP 405, HTTP 500

### Ruleset GC

Trigger a full GC.

- **Path**: /ruleset/gc
- **Method**: POST
- **Content**: None
- **Status**: HTTP 200, HTTP 405

## Ruleset Callbacks
### ruleset.resolve

**Synopsis**

```Lua
function ruleset.resolve(domain)
    return "www.example.org:80", "203.0.113.1:1080", ..., "[2001:DB8::1]:1080"
end
```

**Description**

Process a host name request. Specifically:
- Any HTTP CONNECT
- SOCKS5 with host name (a.k.a. "socks5h")
- Any SOCKS4A

**Params**

- `domain`: full qualified domain name and port, like `"www.example.org:80"`

**Returns**

- `addr`: replace the request
- `addr, proxy`: forward the request through another neosocksd
- `addr, proxyN, ..., proxy1`: forward the request through proxy chain
- `nil`: reject the request


### ruleset.route

**Synopsis**

```Lua
function ruleset.route(addr)
    return "www.example.org:80", "203.0.113.1:1080", ..., "[2001:DB8::1]:1080"
end
```

**Description**

Process an IPv4 request. Specifically:
- SOCKS5 with IPv4 address
- Any SOCKS4

**Params**

- `addr`: address and port, like `"203.0.113.1:80"`

**Returns**

See [ruleset.resolve](#rulesetresolve)


### ruleset.route6

**Synopsis**

```Lua
function ruleset.route6(addr)
    return "www.example.org:80", "203.0.113.1:1080", ..., "[2001:DB8::1]:1080"
end
```

**Description**

Process an IPv6 request. Specifically:

- SOCKS5 with IPv6 address

**Params**

- `addr`: address and port, like `"[2001:DB8::1]:80"`

**Returns**

See [ruleset.resolve](#rulesetresolve)


### ruleset.tick

**Synopsis**

```Lua
function ruleset.tick(now)
    -- ......
end
```

**Description**

Periodic timer callback.

**Params**

- `now`: current timestamp in seconds

**Returns**

Ignored


### ruleset.stats

**Synopsis**

```Lua
function ruleset.stats(dt)
    local w = {}
    table.insert(w, string.format("dt = %.03f", dt))
    return table.concat(w, "\n")
end
```

**Description**

Generate custom information to be provided in the API `/stats`. See also [stats](#server-statistics).

**Params**

- `dt`: seconds elapsed since last call

**Returns**

Custom information in a string.


## Lua API

### neosocksd.resolve

**Synopsis**

```Lua
local addr = neosocksd.resolve("www.example.com")
-- got addr like "203.0.113.1" or "2001:DB8::1"
```

**Description**

Resolves a host name locally and blocks until resolution succeeds or times out. IPv4/IPv6 preference depends on command line argument `-4`/`-6`.


### neosocksd.parse_ipv4

**Synopsis**

```Lua
local subnet = neosocksd.parse_ipv4("169.254.0.0")
local mask = 0xFFFF0000 -- 169.254.0.0/16
local ip = neosocksd.parse_ipv4("203.0.113.1")
if (ip & mask) == subnet then
    -- ......
end
```

**Description**

Parses an IPv4 address into integers.


### neosocksd.parse_ipv6

**Synopsis**

```Lua
-- with 64-bit Lua integers
local subnet1, subnet2 = neosocksd.parse_ipv6("FE80::")
local mask1 = 0xFFC0000000000000 -- fe80::/10
local ip1, ip2 = neosocksd.parse_ipv6("2001:DB8::1")
if (ip1 & mask1) == subnet1 then
    -- ......
end
```

**Description**

Parses an IPv6 address into integers.


### neosocksd.setinterval

**Synopsis**

```Lua
neosocksd.setinterval(1.5)
```

**Description**

Set tick interval in seconds, see also [ruleset.tick](#rulesettick).

The valid interval range is `[1e-3, 1e+9]`, use `setinterval(0)` to stop the timer tick.


### neosocksd.invoke

**Synopsis**

```Lua
neosocksd.invoke([[printf("test rpc")]], "neosocksd.lan:80", "127.0.0.1:1080")
```

**Description**

Run Lua code on another neosocksd. This function returns immediately. On failure, the invocation is lost.

NOTE: The code length limit for a single invocation is guaranteed to be at least 4 KiB.


### _G.NDEBUG

**Synopsis**

```Lua
printf("some debug log")
```

**Description**

Controls whether the default implementation of `printf` in `libruleset.lua` writes to standard output.

Defaults to false if the log level allows printing debug logs. The log level depends on command line argument `-s`/`-v`.
