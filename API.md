# neosocksd API Reference

## Index

- [RESTful API](#restful-api)
- [Ruleset Callbacks](#ruleset-callbacks)
- [Lua API](#lua-api)

## RESTful API

1. The RESTful API server runs `HTTP/1.1`.
2. The content length limit for a single request is at least 4 MiB.

### Healthy Check

Check server liveness.

- **Path**: `/healthy`
- **Method**: Any
- **Status**: HTTP 200

### Server Statistics

GET: Get the stateless server statistics.

POST: Calculate server statistics since the last request.

- **Path**: `/stats`
- **Method**: GET, POST
- **Status**: HTTP 200, HTTP 405
- **Response**: Server statistics in plain text.

### Ruleset Invoke

Run the posted script.

- **Path**: `/ruleset/invoke`
- **Method**: POST
- **Content**: Lua script
- **Status**: HTTP 200, HTTP 405, HTTP 500

### Ruleset Update

Load the posted script and use it as follows:

1. If module name is not specified, replace the ruleset.
2. If module name is specified, replace the named Lua module.
3. If the field `_G.name` refers to the named module, it will be updated too.

- **Path**: `/ruleset/update`
- **Query**: `?module=name` (optional)
- **Method**: POST
- **Content**: Lua ruleset script or Lua module script
- **Status**: HTTP 200, HTTP 405, HTTP 500

### Ruleset GC

Trigger the garbage collector to free some memory.

- **Path**: `/ruleset/gc`
- **Method**: POST
- **Content**: None
- **Status**: HTTP 200, HTTP 405


## Ruleset Callbacks
### ruleset.resolve

**Synopsis**

```Lua
function ruleset.resolve(domain)
    return "www.example.org:80", "http://203.0.113.1:8080", ..., "socks4a://[2001:DB8::1]:1080"
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
- `addr, proxy`: forward the request through another proxy
- `addr, proxyN, ..., proxy1`: forward the request through proxy chain
- `nil`: reject the request

The proxy addresses are specified in URI format, supported scheme:
- `socks4a://example.org:1080`: SOCKS4A server. The implementation is SOCKS4 compatible when requesting IPv4 address.
- `socks5://example.org:1080`: SOCKS5 server.
- `http://example.org:8080`: HTTP/1.1 CONNECT server.

*Notice: The port number can not be omitted.*


### ruleset.route

**Synopsis**

```Lua
function ruleset.route(addr)
    return "www.example.org:80", "http://203.0.113.1:8080", ..., "socks4a://[2001:DB8::1]:1080"
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
    return "www.example.org:80", "http://203.0.113.1:8080", ..., "socks4a://[2001:DB8::1]:1080"
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


### ruleset.idle

**Synopsis**

```Lua
function ruleset.idle()
    -- ......
    if not finished then
        -- pending requests get processed before next idle
        neosocksd.setidle()
    end
end
```

**Description**

`ruleset.idle()` is invoked when there is nothing better to do. This can be used to do some non-urgent cleanups in the background, for example.

**Params**

None

**Returns**

None


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
```

**Description**

(Deprecated) consider using [await.resolve](#awaitresolve) instead.

Resolves a host name locally and blocks the whole server until resolution is finished or times out.


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


### neosocksd.setidle

**Synopsis**

```Lua
neosocksd.setidle()
```

**Description**

Invoke the idle callback the next time the server is idle.

See [ruleset.idle](#rulesetidle).


### neosocksd.invoke

**Synopsis**

```Lua
-- neosocksd.invoke(code, host, proxyN, ..., proxy1)
neosocksd.invoke([[log("test rpc")]], "neosocksd.lan:80", "socks4a://127.0.0.1:1080")
```

**Description**

Run Lua code on another neosocksd. This function returns immediately. In case of failure, the invocation is lost.


### regex.compile

**Synopsis**

```Lua
local reg = regex.compile([[\.example\.(com|org)$]])
local s, e = reg:find(host)
if s then
    -- ......
end
local m = reg:match(host)
if m then
    -- ......
end
```

**Description**

Lua interface for [POSIX Extended Regular Expressions](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap09.html#tag_09_04).


### _G.NDEBUG

**Synopsis**

```Lua
logf("some debug log: %d", 123)
```

**Description**

True if the log level doesn't allow printing debug logs. The log level depends on command line argument `--loglevel`.

In the default implementation of `libruleset.lua`, this value controls whether `log`/`logf` writes to standard output.


### _G.async

**Synopsis**

```Lua
async(function()
    -- routine
end)
```

**Description**

Start an asynchronous routine. See [await.resolve](#awaitresolve) for full example.

*Notice: The await.\* functions should be called in asynchronous routines.*


### await.resolve

**Synopsis**

```Lua
async(function()
    local addr = await.resolve("www.example.com")
    if addr then
        -- ......
    end
end)
```

**Description**

Resolves a host name locally.

IPv4/IPv6 preference depends on command line argument `-4`/`-6`.

Tip: To reduce delays caused by name resolution. It's recommended to set up a local DNS cache, such as systemd-resolved or dnsmasq.


### await.pcall

**Synopsis**

```Lua
async(function()
    local ok, ret = await.pcall([[return 123]], "127.0.1.1:9080")
    if ok then
        -- ret: the string result "123"
        -- ......
    else
        -- ret: error message
    end
end)
```

**Description**

Run Lua code on another neosocksd and take one string back.
