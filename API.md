# neosocksd API Reference

Version: dev

- [RESTful API](#restful-api)
  - [/healthy](#healthy)
  - [/stats](#stats)
  - [/ruleset/invoke](#rulesetinvoke)
  - [/ruleset/rpcall](#rulesetrpcall)
  - [/ruleset/update](#rulesetupdate)
  - [/ruleset/gc](#rulesetgc)
- [Ruleset Callbacks](#ruleset-callbacks)
  - [ruleset.resolve](#rulesetresolve)
  - [ruleset.route](#rulesetroute)
  - [ruleset.route6](#rulesetroute6)
  - [ruleset.tick](#rulesettick)
  - [ruleset.stats](#rulesetstats)
- [Lua API](#lua-api)
  - [neosocksd.config](#neosocksdconfig)
  - [neosocksd.resolve](#neosocksdresolve)
  - [neosocksd.splithostport](#neosocksdsplithostport)
  - [neosocksd.parse\_ipv4](#neosocksdparse_ipv4)
  - [neosocksd.parse\_ipv6](#neosocksdparse_ipv6)
  - [neosocksd.setinterval](#neosocksdsetinterval)
  - [neosocksd.invoke](#neosocksdinvoke)
  - [neosocksd.stats](#neosocksdstats)
  - [neosocksd.now](#neosocksdnow)
  - [neosocksd.traceback](#neosocksdtraceback)
  - [regex.compile](#regexcompile)
  - [time.\*](#time)
  - [zlib.compress](#zlibcompress)
  - [\_G.marshal](#_gmarshal)
  - [\_G.async](#_gasync)
  - [await.execute](#awaitexecute)
  - [await.invoke](#awaitinvoke)
  - [await.resolve](#awaitresolve)
  - [await.sleep](#awaitsleep)


## RESTful API

1. The RESTful API server runs `HTTP/1.1`.
2. The content length limit for a single request is 4 MiB.

### /healthy

- **Method**: Any
- **Status**: HTTP 200

Check server liveness.

### /stats

- **Method**: GET, POST
- **Query**:
  - `nobanner`: omit the banner, default to 0.
  - `server`: show server statistics, default to 1.
  - `q`: argument for [ruleset.stats](#rulesetstats).
- **Status**: HTTP 200
- **Response**: Server statistics in `text/plain`.

GET: Get the stateless server statistics.

POST: Calculate server statistics since the last request.

### /ruleset/invoke

- **Method**: POST
- **Content**: Lua script
- **Status**: HTTP 200, HTTP 500

Run the POSTed script.

### /ruleset/rpcall

- **Method**: POST
- **Content**: `application/x-neosocksd-rpc`
- **Status**: HTTP 200, HTTP 500
- **Response**: Invocation results.

Internal API reserved for [await.invoke](#awaitinvoke).

### /ruleset/update

- **Method**: POST
- **Query**:
  - `module`: replace a loaded Lua module, like `libruleset`.
  - `chunkname`: chunk name for stack traceback, like `%40libruleset.lua`.
- **Content**: Lua ruleset script or Lua module script
- **Status**: HTTP 200, HTTP 500

Load the posted script and use it as follows:

1. If module name is not specified, replace the ruleset.
2. If module name is specified, replace the named Lua module.
3. If the field `_G.name` refers to the named module, update it.

### /ruleset/gc

- **Method**: POST
- **Content**: None
- **Status**: HTTP 200

Trigger the garbage collector to free some memory.


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

Periodic timer callback. See [neosocksd.setinterval](#neosocksdsetinterval).

**Params**

- `now`: current timestamp in seconds

**Returns**

Ignored


### ruleset.stats

**Synopsis**

```Lua
function ruleset.stats(dt, q)
    local w = {}
    table.insert(w, string.format("dt = %.03f, q = %q", dt, q))
    return table.concat(w, "\n")
end
```

**Description**

Generate custom information to be provided in the API `/stats`. See also [stats](#stats).

**Params**

- `dt`: seconds elapsed since last call

**Returns**

Custom information in a string.


## Lua API

### neosocksd.config

**Synopsis**

```Lua
_G.config = neosocksd.config()
if config.loglevel >= 6 then
    print("...")
end
```

**Description**

Returns a table of server configurations.


### neosocksd.resolve

**Synopsis**

```Lua
local addr = neosocksd.resolve("www.example.com")
```

**Description**

(Deprecated) consider using [await.resolve](#awaitresolve) instead.

Resolves a host name locally and blocks the whole server until resolution is finished or times out.


### neosocksd.splithostport

**Synopsis**

```Lua
local host, port = neosocksd.splithostport("example.com:80")
```

**Description**

Split address string into host and port. Raises an error on failure.


### neosocksd.parse_ipv4

**Synopsis**

```Lua
local subnet = neosocksd.parse_ipv4("169.254.0.0")
local mask = 0xFFFF0000 -- 169.254.0.0/16
local ip = neosocksd.parse_ipv4("203.0.113.1")
if ip and (ip & mask) == subnet then
    -- ......
end
```

**Description**

Parses an IPv4 address into integers. Returns nil on failure.


### neosocksd.parse_ipv6

**Synopsis**

```Lua
-- with 64-bit Lua integers
local subnet1, subnet2 = neosocksd.parse_ipv6("FE80::")
local mask1 = 0xFFC0000000000000 -- fe80::/10
local ip1, ip2 = neosocksd.parse_ipv6("2001:DB8::1")
if ip1 and (ip1 & mask1) == subnet1 then
    -- ......
end
```

**Description**

Parses an IPv6 address into integers. Returns nil on failure.


### neosocksd.setinterval

**Synopsis**

```Lua
neosocksd.setinterval(1.5)
```

**Description**

Set the interval to call [ruleset.tick](#rulesettick) in seconds.

The valid interval range is `[1e-3, 1e+9]`, use `setinterval(0)` to stop the timer tick.


### neosocksd.invoke

**Synopsis**

```Lua
-- neosocksd.invoke(code, host, proxyN, ..., proxy1)
neosocksd.invoke([[log("test rpc")]], "api.neosocksd.internal:80", "socks4a://127.0.0.1:1080")
```

**Description**

Run Lua code on another neosocksd. This function returns immediately. In case of failure, the invocation is lost.

Tip: Please refer to `neosocksd.sendmsg` in `libruleset.lua`.


### neosocksd.stats

**Synopsis**

```Lua
local t = neosocksd.stats()
```

**Description**

Return a table of raw statistics. If called during the initial loading phase, unavailable data will be set to zero.


### neosocksd.now

**Synopsis**

```Lua
local now = neosocksd.now()
```

**Description**

Formally, get the timestamp of the latest event in seconds.

- Any ruleset callback must be invoked by an event.
- Any asynchronous routine must be resumed by an event.


### neosocksd.traceback

**Synopsis**

```Lua
local ok, result = xpcall(f, neosocksd.traceback, ...)
```

**Description**

In supported builds, log both Lua and C traceback.


### regex.compile

**Synopsis**

```Lua
local reg = regex.compile([[\.example\.(com|org)$]])
local s, e = reg:find(host)
if s then
    -- ......
end
local m, sub1 = reg:match(host)
if m then
    -- ......
end
for m, sub1 in reg:gmatch(s) do
    -- ......
end
```

**Description**

Lua interface for [POSIX Extended Regular Expressions](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap09.html#tag_09_04).


### time.\*

**Synopsis**

```Lua
local t0 = time.monotonic() -- CLOCK_MONOTONIC
local t1 = time.process()   -- CLOCK_PROCESS_CPUTIME_ID
local t2 = time.thread()    -- CLOCK_THREAD_CPUTIME_ID
local t3 = time.wall()      -- CLOCK_REALTIME
-- measure function time with monotonic clock
local t, ... = time.measure(f, ...)
```

**Description**

Lua interface for POSIX function [clock_gettime()](https://pubs.opengroup.org/onlinepubs/9699919799/functions/clock_gettime.html).


### zlib.compress

**Synopsis**

```Lua
local z = zlib.compress(s)
local s1 = zlib.uncompress(z)
assert(s == s1)
```

**Description**

Data compression interface for zlib format (as declared in RFC 1950 and RFC 1951).

Tip: [neosocksd.invoke](#neosocksdinvoke) and [await.invoke](#awaitinvoke) will compress the data internally.


### _G.marshal

**Synopsis**

```Lua
local s = marshal("a", {"b", ["c"] = "d"})
log(s) -- "a",{"b",["c"]="d"}
```

**Description**

Marshal all parameters in Lua syntax.

To be symmetric, there is also `_G.unmarshal(s)` in `libruleset.lua`.


### _G.async

**Synopsis**

```Lua
async(function(...)
    -- routine
end, ...)
```

**Description**

Start an asynchronous routine. Asynchronous routines are supported by Lua coroutines. Therefore, they run concurrently, but not in parallel. See [await.resolve](#awaitresolve) for a full example.

This function is implemented in `libruleset.lua`.

*Notice: The await.\* functions should only be called in asynchronous routines.*


### await.execute

**Synopsis**

```Lua
async(function()
    local status = await.execute("curl -sX POST http://example.com/v1/api")
    if status ~= 0 then
        -- ......
    end
end)
```

**Description**

Execute a shell command asynchronously.


### await.invoke

**Synopsis**

```Lua
async(function(addr)
    local begin = neosocksd.now()
    local ok, result = await.invoke([[await.idle(); return "ok"]], addr)
    if not ok then
        -- on failure, the result is string
        error("invocation failed: " .. result)
    end
    -- on success, the result is function
    ok, result = result()
    if not ok then
        error("remote error: " .. result)
    end
    assert(result == "ok")
    local rtt = neosocksd.now() - begin
    logf("ping %s: %dms", addr, math.ceil(rtt * 1e+3))
end, "127.0.1.1:9080")
```

**Description**

Run Lua code on another neosocksd and return the result. On another neosocksd, the code runs in asynchronous routine. Therefore, you can call `await.*` functions in the code. `await.invoke` is likely to be less efficient than `neosocksd.invoke`.

Tip: Please refer to `await.rpcall` in `libruleset.lua`.


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

Resolves a host name asynchronously. If asynchronous name resolution is not supported, `await.resolve` behaves the same as `neosocksd.resolve`.

IPv4/IPv6 preference depends on command line argument `-4`/`-6`.

Tip: To reduce delays caused by name resolution. It's recommended to set up a local DNS cache, such as systemd-resolved or dnsmasq.


### await.sleep

**Synopsis**

```Lua
async(function()
    await.sleep(1.5)
end)
```

**Description**

Pause an asynchronous routine for at least specified interval in seconds.

The interval must be in the range `[0, 1e+9]`.
