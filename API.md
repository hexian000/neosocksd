# neosocksd API Reference

Version: dev

- [RESTful API](#restful-api)
  - [/healthy](#healthy)
  - [/stats](#stats)
  - [/ruleset/invoke](#rulesetinvoke)
  - [/ruleset/rpcall](#rulesetrpcall)
  - [/ruleset/update](#rulesetupdate)
  - [/ruleset/gc](#rulesetgc)
  - [/metrics](#metrics)
- [Ruleset Callbacks](#ruleset-callbacks)
  - [ruleset.resolve](#rulesetresolve)
  - [ruleset.route](#rulesetroute)
  - [ruleset.route6](#rulesetroute6)
  - [ruleset.tick](#rulesettick)
  - [ruleset.stats](#rulesetstats)
  - [ruleset.metrics](#rulesetmetrics)
  - [ruleset.healthy](#rulesethealthy)
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
  - [zlib.gzip](#zlibgzip)
  - [\_G.marshal](#_gmarshal)
  - [\_G.async](#_gasync)
  - [await.execute](#awaitexecute)
  - [await.forward](#awaitforward)
  - [await.invoke](#awaitinvoke)
  - [await.resolve](#awaitresolve)
  - [await.sleep](#awaitsleep)


## RESTful API

1. The RESTful API uses `HTTP/1.1`.
2. The maximum request body size is 4 MiB.
3. Requests and responses support `deflate` compression when the appropriate headers are present (`Content-Encoding` on request bodies, `Accept-Encoding` on response bodies).

> **Security:** This API has no built-in authentication. [/ruleset/invoke](#rulesetinvoke)
> and [/ruleset/update](#rulesetupdate) execute or replace arbitrary Lua code,
> so anyone able to reach this API can control ruleset behavior and thus
> outbound traffic. Bind `--api` to loopback or a trusted, firewalled network —
> never expose it to an untrusted network.

### /healthy

- **Method**: Any
- **Status**: HTTP 200 (healthy), HTTP 503 (unhealthy)
- **Response**: When unhealthy, the reason reported by [ruleset.healthy](#rulesethealthy) (`text/plain`).

Health check. If the [ruleset.healthy](#rulesethealthy) callback is defined and returns a
non-empty string, the endpoint responds with HTTP 503 and that string as the body. Otherwise
it responds with HTTP 200 and an empty body.

### /stats

- **Method**: GET, POST
- **Query**:
  - `nobanner`: omit the banner. Default: 0.
  - `server`: include server statistics. Default: 1.
  - `runtime`: include ruleset VM memory statistics. Default: 0.
  - `q` (POST only): passed to [ruleset.stats](#rulesetstats) as the second argument. Default: nil.
- **Status**: HTTP 200
- **Response**: Server statistics (`text/plain`).

GET: Returns stateless server statistics.

POST: Returns server statistics accumulated since the previous request. Also invokes [ruleset.stats](#rulesetstats) if a ruleset is active.

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
3. Replacing a module always refreshes `package.loaded[modname]` (set to the module's return value, or `true` if it returns nothing). The global `_G[modname]` is updated to the new module only if it currently aliases the previously loaded module; otherwise it is left unchanged.

### /ruleset/gc

- **Method**: POST
- **Content**: None
- **Status**: HTTP 200
- **Response**: Text report including reclaimed bytes/objects, current ruleset memory usage, and elapsed time.

Triggers garbage collection.

### /metrics

- **Method**: GET
- **Status**: HTTP 200, HTTP 405 (method not allowed)
- **Response Content-Type**: `text/plain; version=0.0.4; charset=utf-8`
- **Response**: Built-in server metrics, optionally followed by custom output from [ruleset.metrics](#rulesetmetrics). The response is `deflate`-compressed if the request includes `Accept-Encoding: deflate`.

Exposes built-in server metrics in [Prometheus text exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/).


## Ruleset Callbacks

### ruleset.resolve

**Synopsis**

```Lua
function ruleset.resolve(domain, username, password)
    return "www.example.org:80", "http://203.0.113.1:8080", ..., "socks4a://[2001:DB8::1]:1080"
end
```

**Description**

Handles a hostname request. Specifically:
- Any HTTP CONNECT request
- SOCKS5 with a hostname (a.k.a. socks5h)
- Any SOCKS4A request

*This callback is called from an asynchronous routine.*

**Params**

- `domain`: fully qualified domain name and port (e.g., `"www.example.org:80"`)
- `username`, `password`: credentials supplied with the proxy request, or `nil`
  when none were provided. The source is the SOCKS4 user ID (`password` is then
  always `nil`), the SOCKS5 username/password authentication method, or the HTTP
  `Proxy-Authorization: Basic` header.

**Returns**

- `addr`: replaces the request
- `addr, proxy`: forwards the request through another proxy
- `addr, proxyN, ..., proxy1`: forwards the request through a proxy chain
- `nil`: rejects the request

Proxy addresses are specified in URI format. Supported schemes:
- `socks4a://example.org:1080`: SOCKS4A server. The implementation is SOCKS4-compatible when requesting an IPv4 address.
- `socks5://example.org:1080`: SOCKS5 server.
- `http://example.org:8080`: HTTP/1.1 CONNECT server.

**Active forwarding**

Returning a decision (above) lets the server perform the dial. Alternatively,
the callback may forward the request itself with [await.forward](#awaitforward)
and learn whether the connection succeeded — enabling failover and retries:

```Lua
function ruleset.route(addr)
    return await.forward(addr, "socks5://gateway.lan:1080")
end
```

Both styles are supported. The bundled `libruleset.lua` uses active forwarding
internally while keeping the return-value style for its `rule.*` actions.


### ruleset.route

**Synopsis**

```Lua
function ruleset.route(addr, username, password)
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
- `username`, `password`: see [ruleset.resolve](#rulesetresolve)

**Returns**

See [ruleset.resolve](#rulesetresolve)


### ruleset.route6

**Synopsis**

```Lua
function ruleset.route6(addr, username, password)
    return "www.example.org:80", "http://203.0.113.1:8080", ..., "socks4a://[2001:DB8::1]:1080"
end
```

**Description**

Handles an IPv6 request. Specifically:

- SOCKS5 with an IPv6 address

*This callback is called from an asynchronous routine.*

**Params**

- `addr`: address and port (e.g., `"[2001:DB8::1]:80"`)
- `username`, `password`: see [ruleset.resolve](#rulesetresolve)

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

**Returns**

None.


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

- `dt`: seconds elapsed since the previous POST `/stats` request.
- `q`: the `q` query parameter from the POST `/stats` request, or `nil` if absent.

**Returns**

Custom information as a string. Newlines are preserved in the response body.


### ruleset.metrics

**Synopsis**

```Lua
function ruleset.metrics()
    return "# HELP my_counter An example counter.\n"
        .. "# TYPE my_counter counter\n"
        .. string.format("my_counter %d\n", _G.my_value or 0)
end
```

**Description**

Appends custom text to the `/metrics` API response. This callback is optional; if it is not defined, the `/metrics` output is unchanged.

The returned string is appended verbatim after all built-in Prometheus metrics, so it must conform to the [Prometheus text exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/).

*This callback is NOT called from an asynchronous routine.*

**Returns**

A string in Prometheus text format to append to the `/metrics` response.


### ruleset.healthy

**Synopsis**

```Lua
function ruleset.healthy()
    if not database_connected() then
        return "database unreachable"
    end
    -- return nil or "" when healthy
end
```

**Description**

Reports service health for the [/healthy](#healthy) API. This callback is optional; if it is not defined, the service is always considered healthy.

Return a non-empty string to mark the service unhealthy; the string becomes the `/healthy` error message (HTTP 503 response body). Return `nil` or an empty string to indicate health (HTTP 200). If the callback itself raises an error, the service is considered unhealthy and the error message is reported.

*This callback is NOT called from an asynchronous routine.*

**Returns**

- `nil` or `""`: healthy
- a non-empty string: unhealthy; the string is the reported reason


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

Returns a table reflecting the effective server configuration. Fields mirror the
corresponding command-line options.

**Returns**

Fields marked † are present only when the corresponding build feature is enabled.

Addresses (string, or `nil` if unset):

- `listen`, `forward`, `proxy`, `restapi`, `http_listen`
- `ruleset`†, `nameserver`†, `netdev`†, `user_name`

Numbers:

- `loglevel`: log verbosity level.
- `resolve_pf`: preferred address family for name resolution (a `PF_*` value; `0` means no preference).
- `timeout`: connection timeout in seconds.
- `memlimit`†: soft limit on total Lua object size, in MiB.

Booleans:

- `auth_required`, `tcp_nodelay`, `tcp_keepalive`, `socks5_bind`, `socks5_udp`,
  `daemonize`, `block_loopback`, `block_multicast`, `block_local`, `block_global`
- `pipe`†, `reuseport`†, `tcp_fastopen`†, `tcp_fastopen_connect`†, `transparent`†, `traceback`†

Tuning (integer):

- `tcp_sndbuf`, `tcp_rcvbuf`: socket buffer sizes in bytes (`0` means system default).
- `max_sessions`: session count limit (`0` means unlimited).
- `startup_limit_start`, `startup_limit_rate`, `startup_limit_full`: accept rate-limiting parameters.


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

Parses an IPv6 address into two integers (or four, on Lua builds with 32-bit
integers). Returns nil on failure.


### neosocksd.setinterval

**Synopsis**

```Lua
neosocksd.setinterval(1.5)
```

**Description**

Sets the interval to call [ruleset.tick](#rulesettick), in seconds.

Behavior by input value:

- positive normal number: start periodic tick with that interval.
- negative normal number: invoke [ruleset.tick](#rulesettick) whenever the event loop is idle.
- non-normal number (`0`, `NaN`, `+Inf`, `-Inf`, subnormal): stop ticking.


### neosocksd.async

**Synopsis**

```Lua
local co, err = neosocksd.async(finish, func, ...)
-- works like: finish(pcall(func, ...))
-- func may yield; finish must not.
```

**Description**

Low-level API for starting an asynchronous routine. Asynchronous routines use Lua coroutines; they run concurrently, but not in parallel. User scripts typically do not call this directly; see [_G.async](#_gasync).

*Shares the coroutine pool with request handlers for better performance.*


### neosocksd.invoke

**Synopsis**

```Lua
-- neosocksd.invoke(code, addr, proxyN, ..., proxy1)
neosocksd.invoke([[log("test rpc")]], "api.neosocksd.internal:80", "socks4a://127.0.0.1:1080")
```

**Description**

Runs Lua code on another neosocksd. Returns immediately, and drops the invocation on failure.

Note: See `neosocksd.sendmsg` in `libruleset.lua`.


### neosocksd.stats

**Synopsis**

```Lua
local t = neosocksd.stats()
```

**Description**

Returns a table of raw statistics. During the initial loading phase, unavailable fields are set to zero.

**Returns**

General:

- `uptime`: nanoseconds elapsed since the server started.
- `lasterror`: the most recent uncaught error message from a ruleset routine, or `nil`.

Proxy sessions:

- `num_halfopen`: connections still in handshake (not yet relaying).
- `num_sessions`: active relay sessions.
- `num_sessions_peak`: peak concurrent sessions.

Proxy requests:

- `num_request`: total proxy requests processed.
- `num_success`: successful proxy requests.
- `num_reject_ruleset`: requests rejected by the ruleset.
- `num_reject_timeout`: requests that timed out before becoming ready.
- `num_reject_upstream`: requests that failed while dialing upstream.

Traffic:

- `byt_up`: bytes uploaded.
- `byt_down`: bytes downloaded.

Listeners:

- `num_accept`: connections accepted.
- `num_serve`: connections handed to a protocol handler.

API server:

- `num_api_request`: RESTful API requests received.
- `num_api_success`: successful RESTful API requests.

Name resolution:

- `num_dns_query`: name resolution queries issued.
- `num_dns_success`: successful name resolutions.

Ruleset VM:

- `bytes_allocated`: bytes currently allocated by the ruleset Lua VM.
- `num_object`: live Lua objects.
- `num_thread_active`: asynchronous routines currently in flight.
- `num_thread_peak`: peak concurrent asynchronous routines.


### neosocksd.now

**Synopsis**

```Lua
local now = neosocksd.now()
```

**Description**

Returns the timestamp of the latest event in seconds.

**Notes**

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
-- the default flags are regex.EXTENDED | regex.NEWLINE
local reg = regex.compile([[\.example\.(com|org)$]], regex.EXTENDED | regex.ICASE)
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

Lua interface for [POSIX Regular Expressions](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap09.html#tag_09).

`regex.compile(pattern [, cflags])` compiles `pattern` into a reusable object and raises an error if the pattern is invalid. `cflags` defaults to `regex.EXTENDED | regex.NEWLINE`.

**Flags**

Compilation flags, combined with bitwise or:

- `regex.EXTENDED`: use Extended Regular Expression syntax.
- `regex.ICASE`: case-insensitive matching.
- `regex.NEWLINE`: make `.` and bracket expressions stop at newlines, and anchor `^`/`$` to line boundaries.
- `regex.NOSUB`: report only whether a match exists; subexpressions are not captured.

**Methods**

On a compiled pattern `reg`:

- `reg:find(s [, init])`: returns the start and end positions (1-based, inclusive) of the first match, or no values if there is no match.
- `reg:match(s [, init])`: returns the whole match followed by any captured subexpressions (`nil` for groups that did not participate), or no values if there is no match.
- `reg:gmatch(s [, init])`: returns an iterator that yields successive matches as `reg:match` would.

`init` is an optional 1-based start offset (negative counts from the end of `s`); it defaults to the start of `s`. Each method is also callable in function form, e.g. `regex.find(reg, s [, init])`.


### time.\*

**Synopsis**

```Lua
local t0 = time.monotonic() -- CLOCK_MONOTONIC
local t1 = time.process()   -- CLOCK_PROCESS_CPUTIME_ID
local t2 = time.thread()    -- CLOCK_THREAD_CPUTIME_ID
local t3 = time.unix()      -- CLOCK_REALTIME
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


### zlib.gzip

**Synopsis**

```Lua
local z = zlib.gzip(s)
local s1 = zlib.gunzip(z)
assert(s == s1)
```

**Description**

Data compression interface for the gzip format (RFC 1952).


### _G.marshal

**Synopsis**

```Lua
local s = marshal("a", {"b", ["c"] = "d"})
log(s) -- "a",{"b",["c"]="d",}
```

**Description**

Serializes all parameters into Lua syntax. Multiple parameters are separated by
commas. Tables are emitted in constructor form with a trailing separator after
every element (e.g., `marshal({1, 2, 3})` yields `{1,2,3,}`); the result is still
valid Lua and round-trips through `load`.

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


### await.forward

**Synopsis**

```Lua
function ruleset.route(addr)
    -- try a proxy, fall back to a direct connection
    if await.forward(addr, "socks5://backup.lan:1080") then
        return -- connected; the session now relays
    end
    return await.forward(addr) -- direct
end
```

**Description**

Actively forwards the current request to `addr`, optionally through a proxy
chain, and reports whether the upstream connection succeeded. This inverts the
classic return-value contract (see [ruleset.route](#rulesetroute)): instead of
returning a routing decision for the server to dial, the ruleset drives the
dial itself and observes the outcome, which makes failover, retries, and
per-route success metrics possible.

The arguments match the return values of [ruleset.resolve](#rulesetresolve):

```Lua
await.forward(addr)                       -- direct connection
await.forward(addr, proxy)                -- through one proxy
await.forward(addr, proxyN, ..., proxy1)  -- through a proxy chain
await.forward(nil)                        -- reject (nothing is dialed)
```

**Returns**

- `true`: the upstream is connected. The server takes over and relays the
  session; the routine should stop forwarding and return.
- `false, err`: the dial failed (`err` is a description). The request is **not**
  consumed, so the routine may call `await.forward` again to try an alternative.
- `nil`: the address was `nil`; the request is rejected.

**Notes**

- `await.forward` must be called from a ruleset request handler
  ([ruleset.resolve](#rulesetresolve), [ruleset.route](#rulesetroute), or
  [ruleset.route6](#rulesetroute6)); calling it elsewhere raises an error.
- Once a forward succeeds, the request is committed; a further `await.forward`
  in the same routine raises an error.
- The request is forwarded only when the handler returns a valid decision
  (an `addr`, optionally followed by a proxy chain). Otherwise the handler has
  given up — returning `nil`, `false`, nothing, or an address that fails to
  parse — and the request is rejected by policy. A failed `await.forward`
  reports its error only to the routine through the returned `err`; it does not
  affect how the rejection is reported.
- The shipped `libruleset.lua` already forwards through this function. Its
  `rule.*` actions still return routing decisions; the `ruleset.resolve`,
  `ruleset.route`, and `ruleset.route6` callbacks wrap the pure decision
  pipeline (exposed as `ruleset.decide.*`) with `await.forward`. The
  `ruleset.failover(addr, chains)` helper forwards through the first reachable
  chain.


### await.invoke

**Synopsis**

```Lua
async(function(addr)
    local begin = neosocksd.now()
    local ok, result = await.invoke([[await.sleep(1); return "ok"]], addr)
    if not ok then
        -- on failure, the result is a string
        error("invocation failed: " .. result)
    end
    -- on success, the result is a function
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

Resolves a hostname asynchronously using the server's configured name resolver.

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
