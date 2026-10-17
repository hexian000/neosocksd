# neosocksd

[![MIT License](https://img.shields.io/github/license/hexian000/neosocksd)](https://github.com/hexian000/neosocksd/blob/master/LICENSE)
[![Build](https://github.com/hexian000/neosocksd/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/neosocksd/actions/workflows/build.yml)
[![Downloads](https://img.shields.io/github/downloads/hexian000/neosocksd/total.svg)](https://github.com/hexian000/neosocksd/releases)
[![Release](https://img.shields.io/github/release/hexian000/neosocksd.svg?style=flat)](https://github.com/hexian000/neosocksd/releases)

A fast, lightweight SOCKS/HTTP proxy server written in C, with an optional Lua ruleset engine for per-connection routing, load balancing and live reconfiguration. Ships with `agent.lua`, a module for building an autonomous overlay network across multiple LANs.

Status: **Stable**

- [Features](#features)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Protocol Modes](#protocol-modes)
  - [Proxy Chains](#proxy-chains)
  - [Lua Ruleset](#lua-ruleset)
  - [RESTful API](#restful-api)
  - [Deployment Notes](#deployment-notes)
- [Distributed Virtual Network](#distributed-virtual-network)
- [Installation](#installation)
  - [Runtime Dependencies](#runtime-dependencies)
  - [Building from Source](#building-from-source)
  - [Build Options](#build-options)
  - [Testing](#testing)
- [Credits](#credits)


## Features

- **Protocols**: [SOCKS4](https://www.openssh.com/txt/socks4.protocol)/[SOCKS4A](https://www.openssh.com/txt/socks4a.protocol), SOCKS5 ([RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928), with [RFC 1929](https://datatracker.ietf.org/doc/html/rfc1929) auth), HTTP/1.1 `CONNECT` ([RFC 9110 §9.3.6](https://datatracker.ietf.org/doc/html/rfc9110#section-9.3.6)), plain TCP port forwarding, and Linux transparent proxying ([TPROXY](https://docs.kernel.org/networking/tproxy.html)).
- **Fast and small**: 10+ Gbps per x86 core on Linux with `--pipe` (measured in 2024); <800 KiB executable on most platforms\*.
- **Lua ruleset**: resolve, route, authenticate and load-balance every connection in Lua, with built-in async I/O and RPC helpers.
- **RESTful API**: live stats, Prometheus metrics, and hot-reloading of the ruleset and Lua modules without a restart.
- **Proxy chains**: forward outbound connections through a chain of SOCKS4A/SOCKS5/HTTP upstreams.
- **IPv6**: supported in both forwarding and resolving; a name resolving to IPv4 and IPv6 addresses is dialed with Happy Eyeballs ([RFC 8305](https://datatracker.ietf.org/doc/html/rfc8305)).
- **Portable**: ISO C11 and POSIX.1-2008; cross-compiles for Android (NDK) and Windows (MSYS2), see [m.sh](m.sh).
- **Legacy SOCKS5 commands**, off by default and available in plain proxy mode only (not with `-r`/`-x`): BIND (`--enable-socks5-bind`) and UDP ASSOCIATE (`--enable-socks5-udp`).
- **No built-in encryption** — pair with external tools for transport security. Authentication is basic (plaintext credentials) only.

*\* Dynamically linked build; statically linked executables are larger. See [Runtime Dependencies](#runtime-dependencies).*


## Quick Start

Download a `-static` build from [Releases](https://github.com/hexian000/neosocksd/releases) (no dependencies) or [build from source](#building-from-source), then:

```sh
./neosocksd -l 0.0.0.0:1080                       # SOCKS 4/4a/5 server
./neosocksd -l 0.0.0.0:1080 --http 0.0.0.0:8080   # plus an HTTP proxy
curl -x socks5h://127.0.0.1:1080 https://example.com/   # try it
```

`./neosocksd --help` lists every option.


## Usage

### Protocol Modes

```sh
./neosocksd -l 0.0.0.0:1080                       # SOCKS server
./neosocksd -4 -l 0.0.0.0:1080                    # Resolve names as IPv4 only
./neosocksd -l 0.0.0.0:1080 -i eth0               # Bind outbound to eth0
./neosocksd -l 0.0.0.0:1080 --http 0.0.0.0:8080   # SOCKS and HTTP server
./neosocksd -l 0.0.0.0:1080 --enable-socks5-bind --enable-socks5-udp   # Allow SOCKS5 BIND and UDP ASSOCIATE
./neosocksd -l 0.0.0.0:80 -f 127.0.0.1:8080       # Forward port 80 to 8080

# Transparent proxy (requires root)
sudo ./neosocksd --tproxy -l 0.0.0.0:50080 --api 127.0.1.1:9080 \
    -r ruleset_simple.lua --max-startups 60:30:100 --max-sessions 0 -u nobody: -d

# Hardened load balancer (requires root)
sudo ./neosocksd --pipe -d -u nobody: --max-sessions 10000 --max-startups 60:30:100 \
    -t 15 -l :80 -f : -r lb.lua --api 127.0.1.1:9080
```

- `--tproxy` takes each destination from the intercepted socket, so it is always an address literal: only `ruleset.route` (IPv4) and `ruleset.route6` (IPv6) are consulted, never `ruleset.resolve`, and no credentials are passed. With no ruleset loaded, the connection goes to its original destination.
- `-f <address>` forwards every accepted connection to one fixed destination. A bare `:` names no destination, leaving the choice to the ruleset per connection — that turns forward mode into a load balancer, so it needs `-r` (or `-c`).
- `--pipe` moves payload with `splice(2)` instead of copying it through userspace, at the cost of two extra file descriptors per session.

### Proxy Chains

Forward through an upstream chain, optionally exposing a different inbound protocol:

```sh
./neosocksd -l 0.0.0.0:12345 -f 192.168.2.2:12345 \
    -x "socks5://user:pass@192.168.1.1:1080,http://192.168.2.1:8080"

./neosocksd -l 127.0.0.1:1080 --http 0.0.0.0:8080 -x socks4a://203.0.113.1:1080
```

### Lua Ruleset

A ruleset is a Lua script that implements callbacks such as `ruleset.resolve` and `ruleset.route`, returning where each connection should go: a direct destination, a proxy chain, or a rejection. See [API.md](API.md) for the callbacks and the Lua API, and the [Lua 5.5 Manual](https://www.lua.org/manual/5.5/manual.html) for the language.

Binary releases include `neosocksd.noarch.tar.gz` with `libruleset.lua`, `agent.lua`, the `example/` scripts, and `neosocksd.lua` — a stub that declares the built-in API for editors and linters and is never loaded at runtime. Deploy `neosocksd` alongside `libruleset.lua`.

```sh
# Simple rule table
./neosocksd -d -l [::]:1080 --api 127.0.1.1:9080 -r ruleset_simple.lua

# Full ruleset with tracing
./neosocksd -l 0.0.0.0:1080 --api 127.0.1.1:9080 \
    -r ruleset.lua --traceback --loglevel 6

# Gzip-compressed Lua files
./neosocksd -l 0.0.0.0:1080 -r ruleset.lua.gz

# One file does both: configure the server and set up the ruleset
./neosocksd -c config.lua
```

`-r ruleset.lua` loads a standalone ruleset. `-c config.lua` loads a boot config instead: the script returns a table of server options and may also install the ruleset, by setting `_G.ruleset` or providing a `ruleset` field. The two options are mutually exclusive.

The ruleset routes each request, then actively forwards it with `await.forward` and learns whether the upstream connected — see [await.forward](API.md#awaitforward) for failover and retries.

Provided scripts:

| Script                                                     | Description                                                                               |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| [libruleset.lua](libruleset.lua)                           | Ruleset framework and RPC utilities                                                       |
| [agent.lua](agent.lua)                                     | RPC-based peer discovery and relay                                                        |
| [example/ruleset_simple.lua](example/ruleset_simple.lua)   | Minimal ruleset with domain and IP rule tables                                            |
| [example/ruleset.lua](example/ruleset.lua)                 | Full ruleset: `agent.lua` integration, schedule-based logic, RPC; doubles as `-c` config  |
| [example/ruleset_egress.lua](example/ruleset_egress.lua)   | Egress: blocks private addresses, maintains external IP/domain biglist, direct outbound   |
| [example/ruleset_ingress.lua](example/ruleset_ingress.lua) | Ingress: client auth, biglist routing, upstream proxy fallback, RPC biglist sync          |
| [example/lb.lua](example/lb.lua)                           | IWRR (interleaved weighted round robin) load balancer with runtime weight updates via RPC |
| [example/config.lua](example/config.lua)                   | Comprehensive boot configuration for `-c`: server options and optional ruleset            |

### RESTful API

`--api <address>` serves a plain HTTP/1.1 API for monitoring and live control:

```sh
# Stateless snapshot; POST also invokes the ruleset's stats function if defined
watch curl -s http://127.0.1.1:9080/stats
watch curl -sX POST http://127.0.1.1:9080/stats

# Prometheus metrics
curl -s http://127.0.1.1:9080/metrics

# Replace the active ruleset
curl "http://127.0.1.1:9080/ruleset/update?chunkname=%40ruleset.lua" \
    --data-binary @ruleset.lua

# Replace a module
curl "http://127.0.1.1:9080/ruleset/update?module=libruleset&chunkname=%40libruleset.lua" \
    --data-binary @libruleset.lua

# Execute arbitrary code, plain or gzip-compressed
curl "http://127.0.1.1:9080/ruleset/invoke" -d "_G.some_switch = true"
curl "http://127.0.1.1:9080/ruleset/invoke" \
    -H "Content-Encoding: gzip" --data-binary @biglist.lua.gz
```

> **Security note:** The API has no built-in authentication — anyone who can
> reach it can execute arbitrary Lua code via `/ruleset/invoke` or hot-swap the
> running ruleset via `/ruleset/update`. Bind it to loopback or a trusted,
> firewalled network only; never expose `--api` to an untrusted network.

See [API.md](API.md#restful-api) for every endpoint.

### Deployment Notes

A single instance is the normal deployment: one core with `--pipe` relays more
than most links carry. The notes below cover two specific situations.

- **Scaling out.** The accept loop, both handshakes, the ruleset and outbound
  dialing run on one thread; only relayed payload is offloaded. In a build with
  `-DENABLE_THREADS=ON`, `--workers <n>` (default `1`, at most `1024`) relays
  payload on `n` dedicated I/O threads. To put the control path on more cores,
  run several independent instances; on Linux 3.9+, `--reuseport` lets them
  share one listening port and the kernel spreads connections across them.
  Instances share nothing — each has its own Lua state, limits and counters,
  and `--api` reaches whichever one the kernel picks — so give each its own
  `--api` address and update or scrape them individually.
- **Low-power hosts.** An idle neosocksd performs no periodic work: an
  established relay carries no timer, and with no ruleset tick armed the event
  loop blocks indefinitely. What still wakes it is configured by you: a
  `neosocksd.setinterval(n)` tick (every shipped example ruleset arms one at
  60 s; leave it out if your ruleset has no periodic work), `agent.lua`'s peer
  probes, and TCP keepalive on idle connections (tune `tcp_keepidle`,
  `tcp_keepintvl` and `tcp_keepcnt` in the boot config, or set
  `tcp_keepalive = false`). The default single-threaded build is the right one
  here; at runtime, omit `--api` unless you use it and pass `-4` where IPv6 is
  not needed so each name costs one DNS round trip instead of two.


## Distributed Virtual Network

With `agent.lua` loaded, peers discover each other via RPC and relay traffic for one another, so each node's local SOCKS/HTTP endpoint reaches the resources of every other LAN.

Set up on each node:

1. Start neosocksd with the API enabled.
2. Load `libruleset.lua` and `agent.lua` (see [example/ruleset.lua](example/ruleset.lua)).

The agent maintains peer state and relay paths from there. Peer discovery needs
the API reachable between nodes, so it cannot stay on loopback: give it a VPN or
private LAN link between the nodes (see the [security note](#restful-api)).


## Installation

### Runtime Dependencies

**Statically linked setup**: Download a `-static` build from the [Releases](https://github.com/hexian000/neosocksd/releases) section — no additional runtime dependencies are needed. Such a build cannot be relied on to `require` a binary Lua module (a C `?.so` on `package.cpath`): on musl the static libc's `dlopen` is a stub that always fails, and on glibc it succeeds only by mapping the dynamic loader and a second `libc.so.6` into the process — restoring the very dependency a static build exists to avoid. Pure Lua modules, the ruleset and everything it hot-reloads included, are unaffected.

**Dynamically linked setup**: Install the following runtime dependencies.

```sh
# Debian / Ubuntu
sudo apt install libev4 libc-ares2
# Alpine Linux
apk add libev c-ares
# OpenWrt
opkg install libev libcares
```

*Note: Lua is always linked statically.*

### Building from Source

| Name   | Version   | Required | Feature                      |
| ------ | --------- | -------- | ---------------------------- |
| libev  | >= 4.31   | yes      |                              |
| Lua    | >= 5.3    | no       | ruleset                      |
| c-ares | >= 1.16.0 | no       | asynchronous name resolution |

```sh
# Debian / Ubuntu
sudo apt install libev-dev liblua5.4-dev libc-ares-dev
# Alpine Linux
apk add libev-dev lua5.4-dev c-ares-dev
```

```sh
git clone https://github.com/hexian000/neosocksd.git
mkdir -p neosocksd-build && cd neosocksd-build
cmake -DCMAKE_BUILD_TYPE="Release" \
    ../neosocksd
cmake --build . --parallel
```

The binary lands in `bin/neosocksd`. Lua 5.3, 5.4 and 5.5 are all supported;
without Lua, configure with `-DENABLE_RULESET=OFF` to build a plain proxy.
Without c-ares, name resolution falls back to a blocking resolver.

[m.sh](m.sh) wraps the common in-tree configurations: `./m.sh` for an
incremental build, `./m.sh r` for a release build with tests, `./m.sh d` for a
debug build with sanitizers, and `./m.sh x` / `./m.sh ndk` / `./m.sh msys2` for
cross-compiling.

### Build Options

| CMake option         | Default | Effect                                               |
| -------------------- | ------- | ---------------------------------------------------- |
| `ENABLE_RULESET`     | ON      | Lua ruleset scripting (requires Lua)                 |
| `ENABLE_THREADS`     | OFF     | I/O worker threads, enables `--workers`              |
| `BUILD_STATIC`       | OFF     | Build a fully static executable, no Lua C modules    |
| `LINK_STATIC_LIBS`   | OFF     | Link dependencies statically, libc dynamically       |
| `BUILD_PIE`          | OFF     | Build a position-independent executable              |
| `ENABLE_MIMALLOC`    | OFF     | Use mimalloc as the allocator                        |
| `ENABLE_ALLOC_CACHE` | OFF     | Cache Lua VM allocations                             |
| `ENABLE_SYSTEMD`     | OFF     | systemd integration                                  |
| `FORCE_POSIX`        | OFF     | Core built on POSIX.1 APIs only, no Linux extras     |
| `ENABLE_SANITIZERS`  | OFF     | Address, leak and undefined-behavior sanitizers      |

### Testing

```sh
# Unit tests, from the build directory
ctest --output-on-failure

# End-to-end smoke test: drives the built binary over real sockets and
# exercises SOCKS/HTTP, the API, rulesets, hot reload, chains and forwarding
python3 scripts/smoke_test.py --build /path/to/build
```

The smoke test needs only the Python standard library and no network access.
Run `python3 scripts/format.py .` (or `./m.sh fmt`) before committing.


## Credits

Thanks to:
- [libev](http://software.schmorp.de/pkg/libev.html)
- [Lua](https://www.lua.org/)
- [c-ares](https://c-ares.org/)
- [miniz](https://github.com/richgel999/miniz)
