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
2. The maximum request body size is 4 MiB; a larger `Content-Length` is answered with HTTP 413.
3. A request body may be compressed with `Content-Encoding: deflate` or `Content-Encoding: gzip`; any other coding, or more than one, is rejected with HTTP 415 while the header is being parsed, whatever the endpoint. Only the endpoints that read a body decode it.
4. Response compression is a property of the endpoint, not a general negotiation: [/stats](#stats) and [/metrics](#metrics) `deflate` their body whenever `Accept-Encoding` accepts it, [/ruleset/rpcall](#rulesetrpcall) does so only once the body reaches 256 bytes, and every other endpoint answers uncompressed whatever `Accept-Encoding` says.
5. A boolean query parameter needs an explicit value: `1`, `y`, `yes`, `on`, `t` or `true` enable it, and anything else — including the bare key, as in `?nobanner` — leaves it disabled.
6. Besides the statuses listed for each endpoint, the shared request checks answer:
   - HTTP 404 for a path segment past the endpoint;
   - HTTP 405, carrying an `Allow` header, for a method the endpoint does not implement;
   - HTTP 501 for a chunked request body;
   - HTTP 411 when an endpoint that reads a body is given no `Content-Length`;
   - HTTP 400 for a malformed query string, at the two endpoints that take query parameters ([/stats](#stats) and [/ruleset/update](#rulesetupdate)).

   On a server started without a ruleset, every `/ruleset/*` endpoint answers HTTP 500 with `ruleset is not enabled on the server`.

> **Security:** This API has no built-in authentication. [/ruleset/invoke](#rulesetinvoke)
> and [/ruleset/update](#rulesetupdate) execute or replace arbitrary Lua code,
> so anyone able to reach this API can control ruleset behavior and thus
> outbound traffic. Bind `--api` to loopback or a trusted, firewalled network —
> never expose it to an untrusted network.

### /healthy

- **Method**: GET
- **Status**: HTTP 200 (healthy), HTTP 503 (unhealthy), HTTP 405 (method not allowed)
- **Response**: When unhealthy, the reason reported by [ruleset.healthy](#rulesethealthy) (`text/plain`).

Health check. If the [ruleset.healthy](#rulesethealthy) callback is defined and returns a
non-empty string, the endpoint responds with HTTP 503 and that string as the body. Otherwise
it responds with HTTP 200 and an empty body.

### /stats

- **Method**: GET, POST
- **Query**:
  - `nobanner`: omit the banner. Default: 0.
  - `server`: include server statistics. Default: 1.
  - `runtime`: append the ruleset VM report — allocation, thread counts and event-latency percentiles, the same `Ruleset ...` lines [/ruleset/gc](#rulesetgc) prints. Default: 0. It is written as part of the server statistics, so it also needs `server`: `?runtime=1&server=0` prints nothing.
  - `q` (POST only): passed to [ruleset.stats](#rulesetstats) as the second argument. Default: nil.
- **Status**: HTTP 200, HTTP 400 (malformed query)
- **Response**: Server statistics (`text/plain`), `deflate`-compressed when the request accepts it.

GET: Returns stateless server statistics.

POST: Returns server statistics accumulated since the previous POST request, and invokes [ruleset.stats](#rulesetstats) if a ruleset is active. The accumulation window is a single process-wide value that every client and connection shares and each POST consumes; see the `dt` parameter of [ruleset.stats](#rulesetstats).

### /ruleset/invoke

- **Method**: POST
- **Content**: Lua script
- **Status**: HTTP 200, HTTP 500 (the script failed to load or raised)
- **Response**: Empty. This endpoint ignores `Accept-Encoding`.

Executes the provided script.

The script runs with a sandboxed `_ENV`: a fresh empty table whose `__index` is
the ruleset's real global table. Reads therefore reach every global the ruleset
defines, but a bare global assignment (`counter = 1`) lands in that throw-away
table and is lost when the script returns — assign through `_G`
(`_G.counter = 1`) to keep a value. [/ruleset/rpcall](#rulesetrpcall),
[neosocksd.invoke](#neosocksdinvoke) and [await.invoke](#awaitinvoke) load code
the same way. A ruleset or module script does not:
[/ruleset/update](#rulesetupdate), `-r` and `-c` run with the real globals.

### /ruleset/rpcall

- **Method**: POST
- **Content**: `application/x-neosocksd-rpc; version=<n>`
- **Status**: HTTP 200, HTTP 400 (incompatible `Content-Type`), HTTP 500
- **Response Content-Type**: `application/x-neosocksd-rpc; version=<n>`
- **Response**: Invocation results. `deflate`-compressed when the request includes `Accept-Encoding: deflate` **and** the result reaches 256 bytes; shorter results are sent uncompressed.

Reserved for internal use by [await.invoke](#awaitinvoke). The posted chunk runs in the same sandboxed environment as [/ruleset/invoke](#rulesetinvoke).

### /ruleset/update

- **Method**: POST
- **Query**:
  - `module`: replace a loaded Lua module (e.g., `libruleset`).
  - `chunkname`: chunk name for stack tracebacks (e.g., `%40libruleset.lua`).
- **Content**: Lua ruleset script or Lua module script
- **Status**: HTTP 200, HTTP 400 (malformed query), HTTP 500 (the script failed to load, raised, or did not return a table)
- **Response**: The time the load took (`text/plain`). This endpoint ignores `Accept-Encoding`.

Loads the posted script and applies it as follows:

1. If `module` is not specified, or is exactly `ruleset`, replace the active ruleset: the script is called with the argument `"ruleset"` and must return a table, just as a `-r` file is (see [Ruleset Callbacks](#ruleset-callbacks)). So `module=ruleset` names the active ruleset, not a module called `ruleset`, and leaves `package.loaded` untouched.
2. For any other `module`, replace the named Lua module: the script is called with the module name, following the usual Lua module protocol.
3. Replacing a module always refreshes `package.loaded[modname]` (set to the module's return value, or `true` if it returns nothing). The global `_G[modname]` is updated to the new module only if it currently aliases the previously loaded module; otherwise it is left unchanged.

### /ruleset/gc

- **Method**: POST
- **Content**: None
- **Status**: HTTP 200, HTTP 500
- **Response**: Text report including reclaimed bytes/objects, current ruleset memory usage, and elapsed time. This endpoint ignores `Accept-Encoding`.

Triggers garbage collection.

### /metrics

- **Method**: GET
- **Status**: HTTP 200, HTTP 405 (method not allowed)
- **Response Content-Type**: `text/plain; version=0.0.4; charset=utf-8`
- **Response**: Built-in server metrics, optionally followed by custom output from [ruleset.metrics](#rulesetmetrics). The response is `deflate`-compressed if the request includes `Accept-Encoding: deflate`.

Exposes built-in server metrics in [Prometheus text exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/).


## Ruleset Callbacks

A ruleset is a table a Lua script returns; the server looks the callbacks below
up on the global `ruleset`. The script is called with one argument, a string
naming what is being loaded, and returning a table is mandatory in both modes:

- `-r <file>` and [/ruleset/update](#rulesetupdate) pass `"ruleset"`, and the
  returned table becomes the global `ruleset`.
- `-c <file>` passes `"config"`, and the returned table is the configuration;
  its `ruleset` field, when present, must itself be a table and becomes the
  global `ruleset`.

Installing `_G.ruleset` from inside the script does not substitute for the
return value: a script that returns nothing is rejected with
`ruleset: expected table, got nil` (`config: expected table, got nil` for a
`-c` file), and the server exits with `unable to load ruleset`
(`unable to load config`).

```Lua
local mode = ... -- "ruleset", or "config" for a `-c` file
local ruleset = {}

function ruleset.route(addr, username, password)
    return addr
end

return ruleset
```

Every callback is optional; one the table does not define is simply not called.
The synopses below write `function ruleset.<name>(...)` for brevity: `ruleset`
there is the table the script returns, not a global the script may assume
already exists.

> **Security:** `libruleset.lua` returns a table that already defines
> `resolve`, `route`, `route6`, `tick` and `stats`. Its `resolve`, `route` and
> `route6` are the wrappers that check the proxy credentials — against
> `_G.secrets`, or a `ruleset.authenticate(addr, username, password)` hook when
> the ruleset defines one — and that maintain `_G.num_requests` and
> `_G.num_authorized`. Defining one of those three yourself takes the wrapper
> out of the path, whether you assign to libruleset's table or shadow it on a
> table of your own: under `--auth-required` (or `auth_required` in a `-c`
> configuration) the server still demands credentials from every client, but
> nothing verifies them any more, so every username and password is accepted
> and the request counters stop advancing.
>
> Steer the decision through libruleset's rule tables (`_G.redirect_name`,
> `_G.route`, `_G.route6`, `_G.route_default`, ...), or supply
> `ruleset.authenticate` to plug in your own check. If the callback itself must
> be yours, give it the full `(addr, username, password)` signature and check
> the credentials in it — as a standalone ruleset, one that does not load
> libruleset, must do in any case.

### ruleset.resolve

**Synopsis**

```Lua
function ruleset.resolve(addr, username, password)
    return "www.example.org:80", "http://203.0.113.1:8080", ..., "socks4a://[2001:DB8::1]:1080"
end
```

**Description**

Handles a request whose destination the protocol did not type. Specifically:

- Any HTTP `CONNECT` proxy request, whether its target names a host or an IP
  literal
- SOCKS5 with a domain name (a.k.a. socks5h)
- Any SOCKS4A request
- Port forwarding (`-f`) when the forwarding target is a name

*This callback is called from an asynchronous routine.*

**Params**

- `addr`: the requested host and port (e.g., `"www.example.org:80"`). The host is
  the one the client named, so it is **not** necessarily a domain name: an HTTP
  `CONNECT` target and a SOCKS domain name may both carry an IP literal, and
  such a request arrives here — [ruleset.route](#rulesetroute) and
  [ruleset.route6](#rulesetroute6) are reached only when the protocol itself
  typed the address. Test the host with
  [neosocksd.parse\_ipv4](#neosocksdparse_ipv4) /
  [neosocksd.parse\_ipv6](#neosocksdparse_ipv6) when the decision depends on the
  distinction; `libruleset.lua` does exactly that, and hands a literal to its own
  `route`/`route6` pipeline. An IPv6 literal is bracketed only if the client
  wrote it bracketed: `CONNECT [2001:db8::1]:443` arrives as
  `"[2001:db8::1]:443"`, while a SOCKS domain name holding the bare literal
  arrives as `"2001:db8::1:443"`, which is no longer a parsable `host:port`
  authority.
- `username`, `password`: credentials supplied with the proxy request, or `nil`
  when none were provided. The source is the SOCKS4 user ID (`password` is then
  always `nil`), the SOCKS5 username/password authentication method, or the HTTP
  `Proxy-Authorization: Basic` header. Credentials reach the callback as the
  exact bytes received, NUL bytes included, so they must be compared as Lua
  strings rather than by any C-string rule. RFC 7617 §2 forbids control
  characters in the user-id and the password, so an HTTP `Basic` header whose
  decoded credentials carry a NUL byte is treated as absent. A port-forwarding
  (`-f`) or transparent-proxy (`--tproxy`) session runs no proxy protocol at
  all, so both are always `nil` there.

**Returns**

- `addr`: replaces the request
- `addr, proxy`: forwards the request through another proxy
- `addr, proxyN, ..., proxy1`: forwards the request through a proxy chain
- `nil`: rejects the request

Proxy addresses are specified in URI format. Supported schemes:
- `socks4a://example.org:1080`: SOCKS4A server. The implementation is SOCKS4-compatible when requesting an IPv4 address.
- `socks5://example.org:1080`: SOCKS5 server.
- `http://example.org:8080`: HTTP/1.1 CONNECT server.

**Base proxy chain**

A routing decision here does not replace the command-line `-x`/`--proxy` chain —
it extends it. neosocksd always dials the `-x` chain first, then any proxies
returned by the ruleset, then the target. So the `-x` hops sit nearest neosocksd
while the returned `proxy1, ..., proxyN` are appended toward the target (`proxy1`
is the hop right after the `-x` chain); even a bare `addr` with no proxies still
routes through the `-x` chain. When `-x` is unset, the returned chain is the whole
path. The same extension applies to any proxy chain given to
[neosocksd.invoke](#neosocksdinvoke), [await.forward](#awaitforward), and
[await.invoke](#awaitinvoke).

**Active forwarding**

Returning a decision (above) lets the server perform the dial. Alternatively,
the callback may forward the request itself with [await.forward](#awaitforward)
and learn whether the connection succeeded — enabling failover and retries:

```Lua
function ruleset.resolve(addr, username, password)
    return await.forward(addr, "socks5://gateway.lan:1080")
end
```

Both styles are supported. The bundled `libruleset.lua` uses active forwarding
internally while keeping the return-value style for its `rule.*` actions: the
`ruleset.resolve`, `ruleset.route` and `ruleset.route6` it installs wrap the
pure decision pipeline (exposed as `ruleset.decide.*`) in `await.forward`, and
`ruleset.failover(addr, chains)` forwards through the first reachable chain.
Defining one of those three yourself replaces that wrapper, credential check
included — see the security note at the top of this section.


### ruleset.route

**Synopsis**

```Lua
function ruleset.route(addr, username, password)
    return "www.example.org:80", "http://203.0.113.1:8080", ..., "socks4a://[2001:DB8::1]:1080"
end
```

**Description**

Handles a request the protocol typed as an IPv4 address. Specifically:

- SOCKS5 with an IPv4 address
- Any SOCKS4 request (a SOCKS4A request names a host, and goes to
  [ruleset.resolve](#rulesetresolve))
- Port forwarding (`-f`) and transparent proxying (`--tproxy`) when the
  destination is an IPv4 address

*This callback is called from an asynchronous routine.*

**Params**

- `addr`: address and port (e.g., `"203.0.113.1:80"`). Always an address
  literal, rendered by the server from the parsed address rather than echoed
  from the request. An IPv4 address the client sent as text — an HTTP `CONNECT`
  target, or a SOCKS domain name — is not typed by the protocol and reaches
  [ruleset.resolve](#rulesetresolve) instead.
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

Handles a request the protocol typed as an IPv6 address. Specifically:

- SOCKS5 with an IPv6 address
- Port forwarding (`-f`) and transparent proxying (`--tproxy`) when the
  destination is an IPv6 address

*This callback is called from an asynchronous routine.*

**Params**

- `addr`: address and port, the address always bracketed (e.g.,
  `"[2001:db8::1]:80"`). Always an address literal, rendered by the server from
  the parsed address rather than echoed from the request. An IPv6 address the
  client sent as text — an HTTP `CONNECT` target, or a SOCKS domain name — is
  not typed by the protocol and reaches [ruleset.resolve](#rulesetresolve)
  instead.
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

- `dt`: seconds elapsed since the previous POST `/stats` request. The window is
  a single process-wide value: the first POST after startup reports the server
  uptime rather than an interval, and every POST — from any client, over any
  connection — consumes and restarts it, so concurrent pollers shorten each
  other's `dt`.
- `q`: the `q` query parameter from the POST `/stats` request, or `nil` if
  absent. A bare `?q` carrying no value also reads as `nil`.

**Returns**

Custom information as a string. Newlines are preserved in the response body.

The result is taken with Lua's string conversion, so a number is accepted and
converted. Any other non-string result — a table, or a callback that returns
nothing — is discarded, and the text of the error the ruleset last recorded
(see `lasterror` in [neosocksd.stats](#neosocksdstats)) goes into the `/stats`
body in its place: `(nil)` when none has been recorded yet, the message itself
when the error was a string, and otherwise the error object rendered the way
Lua's `tostring` renders it — through its `__tostring` metamethod if it has
one, else as `table: 0x...` and the like. When that rendering fails (the
`__tostring` raises or returns neither a string nor a number), the text is
`(unprintable <type>: <address>)`, or `(unprintable error object)` when even
that cannot be built.

`libruleset.lua` defines `ruleset.stats` itself (the recent-events list and the
request-rate chart). Defining your own replaces it; call `libruleset.stats(dt)`
from yours to keep that output.


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

A string in Prometheus text format to append to the `/metrics` response. A
number is converted; any other non-string result, and a callback that raises,
appends nothing and leaves the built-in metrics unchanged.


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

The result is taken with Lua's string conversion:

- `nil`, `""`, or no return value at all: healthy.
- a non-empty string: unhealthy; the string is the reported reason.
- a number: converted to its decimal text, which is never empty, so **every**
  number — `0` included — reports unhealthy with that text as the reason.
- `true`, `false`, a table, or any other value: not convertible to a string,
  and therefore read as healthy. Never report health with a boolean.


## Lua API

### neosocksd.config

**Synopsis**

```Lua
-- read the field where it is used, not once at load time
if neosocksd.config().loglevel >= 6 then
    print("...")
end
```

**Description**

Returns a table reflecting the effective server configuration. Fields mirror the
corresponding command-line options.

Every call builds a new table from the configuration in effect at that moment.
The result is a snapshot, not a view: it never reflects a later change.

**Notes**

- The configuration is not fixed for the life of the process. A boot
  configuration (`-c`) is applied only after the chunk that returns it has
  finished, so a call made while that chunk runs — including one from a module
  it `require`s — still reports the configuration that preceded it, and `SIGHUP`
  reloads that file into the running configuration again. A table captured at
  load time therefore answers with the pre-configuration values for the life of
  the process; read each field at the point of use instead.
- A `SIGHUP` reload is refused as a whole, keeping the running configuration and
  ruleset, when the file would fail the checks made at startup, would require
  authentication with no ruleset installed, or changes a field the server
  applies only at startup: `listen`, `http_listen`, `restapi`, `transparent`,
  `reuseport`, `tcp_fastopen`, `workers`, and whether `forward` is set (its
  destination may change). Changing one of those takes a restart.
- `libruleset.lua` publishes `_G.config`, a read-only view over this function:
  every field read calls it, and `pairs` iterates a fresh snapshot. A ruleset
  that loads `libruleset` can read `config.<field>` at the point of use rather
  than calling this function itself. Writing to a field of the view raises an
  error, and a ruleset must not assign a table to `_G.config`: that replaces the
  view with a snapshot for every reader reaching it through the global.
  `libruleset` keeps its own reference to the view, so its reads stay live
  either way.

**Returns**

Fields marked † are present only when the corresponding build feature is enabled.

Strings (or `nil` if unset):

- `listen`, `forward`, `proxy`, `restapi`, `http_listen`
- `ruleset`, `nameserver`†, `netdev`†, `user_name`

Numbers:

- `loglevel`: log verbosity level.
- `resolve_pf`: preferred address family for name resolution (a `PF_*` value; `0` means no preference).
- `timeout`: connection timeout in seconds. This is the only float in the table; every other number is a Lua integer.
- `memlimit`: soft limit on total Lua object size, in MiB.

Booleans:

- `auth_required`, `tcp_nodelay`, `tcp_keepalive`, `socks5_bind`, `socks5_udp`,
  `daemonize`, `block_loopback`, `block_multicast`, `block_local`, `block_global`
- `pipe`†, `reuseport`†, `tcp_fastopen`†, `tcp_fastopen_connect`†, `transparent`†, `traceback`

Tuning (integer):

- `tcp_sndbuf`, `tcp_rcvbuf`: socket buffer sizes in bytes (`0` means system default).
- `tcp_keepidle`†, `tcp_keepintvl`†, `tcp_keepcnt`†: keepalive idle time and probe
  interval in seconds, and the failed probe count (`0` means system default). Only
  meaningful when `tcp_keepalive` is set.
- `max_sessions`: session count limit (`0` means unlimited).
- `startup_limit_start`, `startup_limit_rate`, `startup_limit_full`: accept rate-limiting parameters.
- `workers`†: number of dedicated I/O worker threads (present only in threaded builds).


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

Parses an IPv4 address into an integer.

On failure — an unparsable address, or an argument that is not a string — it
returns **no values** rather than `nil`. `local ip = neosocksd.parse_ipv4(s)`
still reads as `nil`, but `select('#', ...)` and `table.pack` see zero results.


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
integers).

On failure — an unparsable address, or an argument that is not a string — it
returns **no values** rather than `nil`, exactly as
[neosocksd.parse\_ipv4](#neosocksdparse_ipv4) does.


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

The code is posted to the remote server's [/ruleset/invoke](#rulesetinvoke) and
runs in the sandboxed environment described there: a bare global assignment in
it is discarded, so write `_G.name = value`.

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

- `uptime`: nanoseconds elapsed since the server started. This field is a float; every other number in the table is a Lua integer.
- `lasterror`: the error the ruleset last recorded, or `nil` if none has been. Recorded are the errors raised synchronously — while loading a ruleset, module or configuration, by a [/ruleset/invoke](#rulesetinvoke) script, by the [ruleset.tick](#rulesettick), [ruleset.stats](#rulesetstats), [ruleset.metrics](#rulesetmetrics) and [ruleset.healthy](#rulesethealthy) callbacks, or while starting an asynchronous routine — and an error raised by the `finish` function of [neosocksd.async](#neosocksdasync). An error raised inside an asynchronous routine is passed to its `finish` instead: one raised by a request handler ([ruleset.resolve](#rulesetresolve), [ruleset.route](#rulesetroute), [ruleset.route6](#rulesetroute6)) or a [/ruleset/rpcall](#rulesetrpcall) chunk is written to the error log and never recorded here. The value is usually a string even when a table was raised: the first time neosocksd reports a recorded error that is not a string — in a log line (when that log level is enabled), the [ruleset.stats](#rulesetstats) fallback, the [/healthy](#healthy) reason, or a `/ruleset/*` error response — it replaces the object here with its rendering, described under [ruleset.stats](#rulesetstats). So after `error({ code = 42 })` in `ruleset.tick` this field normally holds the string `table: 0x...`; only an error nothing has rendered yet is still the raised object. Under `--traceback` the stored value is the traceback string the error handler built.

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

- The value is a float, never a Lua integer.
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
for m, sub1 in reg:gmatch(host) do
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
- `regex.NOSUB`: accepted and ignored. `find`, `match` and `gmatch` all report match offsets, which this flag would leave unset.

**Methods**

On a compiled pattern `reg`:

- `reg:find(s [, init])`: returns the start and end positions (1-based, inclusive) of the first match, or no values if there is no match.
- `reg:match(s [, init])`: returns the whole match followed by any captured subexpressions (`nil` for groups that did not participate), or no values if there is no match.
- `reg:gmatch(s [, init])`: returns an iterator that yields successive matches as `reg:match` would.

`init` is an optional 1-based start offset (negative counts from the end of `s`); it defaults to the start of `s`. Each method is also callable in function form, e.g. `regex.find(reg, s [, init])`.

Starting past the beginning of `s` does not by itself make that offset a line start, so `^` does not match there; under `regex.NEWLINE` it still matches after any newline, whether that newline lies inside the searched region or immediately before its start. The same applies between `gmatch` iterations, so an anchored pattern yields one match per line rather than one per position — including when the pattern consumes its own line terminator.


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

Note: [`neosocksd.invoke`](#neosocksdinvoke) and [`await.invoke`](#awaitinvoke) compress their payload internally, but only once it reaches 256 bytes; a shorter payload is sent uncompressed.


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

Requires a system shell: `_PATH_BSHELL` where `<paths.h>` provides it (e.g.
`/system/bin/sh` on Android), otherwise `/bin/sh`.


### await.forward

**Synopsis**

```Lua
function ruleset.route(addr, username, password)
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
- `false, err`: no session was established (`err` is a description). When the
  dial itself failed or timed out, the request is **not** consumed, so the
  routine may call `await.forward` again to try an alternative. The exception is
  `err == "request cancelled"`: the client session was torn down while the dial
  was in flight, so the request is already gone and a further `await.forward`
  raises `await.forward: the request is not forwardable` instead of dialing.
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
- Those three callbacks are also where `libruleset.lua` checks the proxy
  credentials. A ruleset that loads `libruleset` and defines one of them to
  forward differently loses that check — see the security note under
  [Ruleset Callbacks](#ruleset-callbacks) before writing one.


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

The code is posted to the remote server's [/ruleset/rpcall](#rulesetrpcall) and
runs in the sandboxed environment described under
[/ruleset/invoke](#rulesetinvoke): a bare global assignment in it is discarded,
so write `_G.name = value`.

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

IPv4/IPv6 preference depends on the `-4`/`-6` command-line flag. A name
resolving to several addresses yields the first of them: the rest are dialed as
fallbacks by the proxy itself and are not surfaced here.

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
