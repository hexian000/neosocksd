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
  - [neosocksd.async](#neosocksdasync)
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

1. The REST API uses `HTTP/1.1`.
2. The maximum request body size is 4 MiB.
3. Requests and responses support `deflate` compression when the appropriate headers are present (`Content-Encoding` for requests, `Accept-Encoding` for responses).

### /healthy

- **Method**: Any
- **Status**: HTTP 200

Health check.

### /stats

- **Method**: GET, POST
- **Query**:
  - `nobanner`: omit the banner. Default: 0.
  - `server`: include server statistics. Default: 1.
  - `q`: argument passed to [ruleset.stats](#rulesetstats).
- **Status**: HTTP 200
- **Response**: Server statistics (`text/plain`).

GET: Returns stateless server statistics.

POST: Returns server statistics accumulated since the previous request.

### /ruleset/invoke

- **Method**: POST
- **Content**: Lua script
- **Status**: HTTP 200, HTTP 500

Executes the provided script.

### /ruleset/rpcall

- **Method**: POST
- **Content**: `application/x-neosocksd-rpc; version=<n>`
- **Status**: HTTP 200, HTTP 500
- **Response Content-Type**: `application/x-neosocksd-rpc; version=<n>`
- **Response**: Invocation results. The response may be `deflate`-compressed if the request includes `Accept-Encoding: deflate`.

Reserved for internal use by [await.invoke](#awaitinvoke).

### /ruleset/update

- **Method**: POST
- **Query**:
  - `module`: replace a loaded Lua module (e.g., `libruleset`).
  - `chunkname`: chunk name for stack tracebacks (e.g., `%40libruleset.lua`).
- **Content**: Lua ruleset script or Lua module script
- **Status**: HTTP 200, HTTP 500

Loads the posted script and applies it as follows:

1. If `module` is not specified, replace the active ruleset.
2. If `module` is specified, replace the named Lua module.
3. If the `_G.module` refers to the named module, update it.

### /ruleset/gc

- **Method**: POST
- **Content**: None
- **Status**: HTTP 200
- **Response**: Text report including reclaimed bytes/objects, current ruleset memory usage, and elapsed time.

Triggers garbage collection.


## Ruleset Callbacks
### ruleset.resolve

**Synopsis**

```Lua
function ruleset.resolve(domain)
    return "www.example.org:80", "http://203.0.113.1:8080", ..., "socks4a://[2001:DB8::1]:1080"
end
```

**Description**

Handles a hostname request. Specifically:
- Any HTTP CONNECT request
- SOCKS5 with a hostname (a.k.a. "socks5h")
- Any SOCKS4A request

*This callback is called from an asynchronous routine.*

**Params**

- `domain`: fully qualified domain name and port (e.g., `"www.example.org:80"`)

**Returns**

- `addr`: replaces the request
- `addr, proxy`: forwards the request through another proxy
- `addr, proxyN, ..., proxy1`: forwards the request through a proxy chain
- `nil`: rejects the request

Proxy addresses are specified in URI format. Supported schemes:
- `socks4a://example.org:1080`: SOCKS4A server. The implementation is SOCKS4‑compatible when requesting an IPv4 address.
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

Handles an IPv4 request. Specifically:
- SOCKS5 with an IPv4 address
- Any SOCKS4 request

*This callback is called from an asynchronous routine.*

**Params**

- `addr`: address and port (e.g., `"203.0.113.1:80"`)

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

Handles an IPv6 request. Specifically:

- SOCKS5 with an IPv6 address

*This callback is called from an asynchronous routine.*

**Params**

- `addr`: address and port (e.g., `"[2001:DB8::1]:80"`)

**Returns**

See [ruleset.resolve](#rulesetresolve)


### ruleset.tick

**Synopsis**

```Lua
function ruleset.tick()
    -- ......
end
```

**Description**

Periodic timer callback. See [neosocksd.setinterval](#neosocksdsetinterval).

*This callback is NOT called from an asynchronous routine.*


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

Generates custom information for the `/stats` API. See also [stats](#stats).

*This callback is NOT called from an asynchronous routine.*

**Params**

- `dt`: seconds elapsed since the last call

**Returns**

Custom information as a string.


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

Returns a table of server configuration values.


### neosocksd.resolve

**Synopsis**

```Lua
local addr = neosocksd.resolve("www.example.com")
```

**Description**

Deprecated. Consider using [await.resolve](#awaitresolve) instead.

Resolves a hostname locally and blocks the entire server until completion or timeout.


### neosocksd.splithostport

**Synopsis**

```Lua
local host, port = neosocksd.splithostport("example.com:80")
```

**Description**

Splits an address string into host and port. Raises an error on failure.


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

Parses an IPv4 address into an integer. Returns nil on failure.


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

Parses an IPv6 address into two integers. Returns nil on failure.


### neosocksd.setinterval

**Synopsis**

```Lua
neosocksd.setinterval(1.5)
```

**Description**

Sets the interval to call [ruleset.tick](#rulesettick), in seconds.

Valid range: `[1e-3, 1e+9]`. Use `setinterval(0)` to stop the timer tick.


### neosocksd.async

**Synopsis**

```Lua
local co, err = neosocksd.async(finish, func, ...)
-- works like: finish(pcall(func, ...))
-- func is yieldable, but finish is NOT
```

**Description**

Low-level API for starting an asynchronous routine. Asynchronous routines use Lua coroutines; they run concurrently, but not in parallel. User scripts typically do not call this directly; see [_G.async](#_gasync).

*Shares the coroutine pool with request handlers for better performance.*


### neosocksd.invoke

**Synopsis**

```Lua
-- neosocksd.invoke(code, host, proxyN, ..., proxy1)
neosocksd.invoke([[log("test rpc")]], "api.neosocksd.internal:80", "socks4a://127.0.0.1:1080")
```

**Description**

Runs Lua code on another neosocksd. Returns immediately. On failure, the invocation is dropped.

Note: See `neosocksd.sendmsg` in `libruleset.lua`.


### neosocksd.stats

**Synopsis**

```Lua
local t = neosocksd.stats()
```

**Description**

Returns a table of raw statistics. During the initial loading phase, unavailable fields are set to zero.


### neosocksd.now

**Synopsis**

```Lua
local now = neosocksd.now()
```

**Description**

Returns the timestamp of the latest event in seconds.

- Any ruleset callback must be invoked by an event.
- Any asynchronous routine must be resumed by an event.


### neosocksd.traceback

**Synopsis**

```Lua
local ok, result = xpcall(f, neosocksd.traceback, ...)
```

**Description**

In supported builds, logs both Lua and C tracebacks.


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

Lua interface for the POSIX function [clock_gettime()](https://pubs.opengroup.org/onlinepubs/9699919799/functions/clock_gettime.html).


### zlib.compress

**Synopsis**

```Lua
local z = zlib.compress(s)
local s1 = zlib.uncompress(z)
assert(s == s1)
```

**Description**

Data compression interface for the zlib format (RFC 1950 and RFC 1951).

Note: [`neosocksd.invoke`](#neosocksdinvoke) and [`await.invoke`](#awaitinvoke) already compress payloads internally.


### _G.marshal

**Synopsis**

```Lua
local s = marshal("a", {"b", ["c"] = "d"})
log(s) -- "a",{"b",["c"]="d"}
```

**Description**

Serializes all parameters into Lua syntax.

The complementary `_G.unmarshal(s)` is defined in `libruleset.lua`.


### _G.async

**Synopsis**

```Lua
async(function(...)
    -- routine0
    local future1 = async(function(...)
        -- routine1
        return "result1"
    end, ...)
    local future2 = async(function(...)
        -- routine2
        return "result2"
    end, ...)
    local ok1, r1 = future1:get()
    local ok2, r2 = future2:get()
end, ...)
```

**Description**

Starts an asynchronous routine and runs it until the first await or completion. See [await.resolve](#awaitresolve) for a full example. Although possible, using `coroutine.*` directly to manipulate asynchronous routines is not recommended.

This function is implemented in `libruleset.lua`.

*Notice: The await.\* functions should only be called in asynchronous routines.*


### await.execute

**Synopsis**

```Lua
async(function()
    local ok, what, stat = await.execute("curl -sX POST http://example.com/api/v1")
    if not ok then
        -- ......
    end
end)
```

**Description**

Executes a shell command asynchronously. Returns three values, similar to `os.execute`.

Requires `/bin/sh`.


### await.invoke

**Synopsis**

```Lua
async(function(addr)
    local begin = neosocksd.now()
    local ok, result = await.invoke([[await.sleep(1); return "ok"]], addr)
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

Low-level API for running Lua code on another neosocksd and returning the result. On the remote neosocksd, the code runs in an asynchronous routine, so you can call `await.*` functions in the remote code. `await.invoke` is typically less efficient than `neosocksd.invoke`.

Note: See `await.rpcall` in `libruleset.lua`.


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

Resolves a hostname asynchronously. If asynchronous name resolution is not supported, `await.resolve` behaves the same as `neosocksd.resolve`.

IPv4/IPv6 preference depends on the `-4`/`-6` command-line flag.

Tip: To reduce delays caused by name resolution, set up a local DNS cache (e.g., systemd-resolved or dnsmasq).


### await.sleep

**Synopsis**

```Lua
async(function()
    await.sleep(1.5)
end)
```

**Description**

Pauses an asynchronous routine for at least the specified interval, in seconds.

The interval must be in the range `[0, 1e+9]`.
