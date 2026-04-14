# neosocksd

[![MIT License](https://img.shields.io/github/license/hexian000/neosocksd)](https://github.com/hexian000/neosocksd/blob/master/LICENSE)
[![Build](https://github.com/hexian000/neosocksd/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/neosocksd/actions/workflows/build.yml)
[![Downloads](https://img.shields.io/github/downloads/hexian000/neosocksd/total.svg)](https://github.com/hexian000/neosocksd/releases)
[![Release](https://img.shields.io/github/release/hexian000/neosocksd.svg?style=flat)](https://github.com/hexian000/neosocksd/releases)

neosocksd is a fast, lightweight TCP proxy server written in C with a Lua-powered routing engine. It also ships with `agent.lua`, an optional Lua module that builds an autonomous overlay network across multiple LANs for seamless cross-network access through a single local proxy.

Status: **Stable**

- [At a Glance](#at-a-glance)
  - [Basic Proxy](#basic-proxy)
  - [Lua Ruleset](#lua-ruleset)
  - [Distributed Virtual Network](#distributed-virtual-network)
- [Features](#features)
- [More Usage Patterns](#more-usage-patterns)
- [Observability](#observability)
- [Runtime Dependencies](#runtime-dependencies)
- [Building from Source](#building-from-source)
  - [Dependencies](#dependencies)
  - [Building with CMake](#building-with-cmake)
- [Credits](#credits)


## At a Glance

The project is best understood through three progressive use cases:

1. **Basic Proxy**: start a high-performance SOCKS/HTTP/TPROXY service.
2. **Lua Ruleset**: program traffic decisions and hot-update logic at runtime.
3. **Distributed Virtual Network**: use `agent.lua` to connect multiple LANs into one autonomous overlay.

If you are new to neosocksd, follow the sections below in order.


### Basic Proxy

Run neosocksd as a fast TCP forwarding proxy (no built-in encryption):

```sh
./neosocksd -l 0.0.0.0:1080               # SOCKS server
./neosocksd -4 -l 0.0.0.0:1080            # Prefer IPv4 in DNS resolution
./neosocksd -4 -l 0.0.0.0:1080 -i eth0    # Bind outbound connections to eth0
./neosocksd --http -l 0.0.0.0:8080        # HTTP CONNECT server
```

Forward connections through an upstream proxy chain:

```sh
./neosocksd -l 0.0.0.0:12345 -f 192.168.2.2:12345 \
    -x "socks5://user:pass@192.168.1.1:1080,http://192.168.2.1:8080"
```

Convert an incoming proxy protocol to a different outbound protocol (e.g., SOCKS4A):

```sh
./neosocksd -l 127.0.0.1:1080 -x socks4a://203.0.113.1:1080
./neosocksd --http -l 127.0.0.1:8080 -x socks4a://203.0.113.1:1080
```

For full flags and protocol options, run `./neosocksd --help`.


### Lua Ruleset

When static forwarding is not enough, enable the Lua control plane.

Deploy `neosocksd` alongside `libruleset.lua`; binary releases include `neosocksd.noarch.tar.gz` with all Lua scripts.

Start with `example/ruleset_simple.lua` if you only need a rule table. For advanced logic and RPC integration, use `example/ruleset.lua` and `libruleset.lua`.

Start a ruleset-powered server:

```sh
./neosocksd -d -l [::]:1080 --api 127.0.1.1:9080 -r ruleset_simple.lua
./neosocksd -l 0.0.0.0:1080 --api 127.0.1.1:9080 \
    -r ruleset.lua --traceback --loglevel 6
```

Hot-update rules without restarting the service:

```sh
# Update main ruleset chunk
curl "http://127.0.1.1:9080/ruleset/update?chunkname=%40ruleset.lua" \
    --data-binary @ruleset.lua

# Update a module
curl "http://127.0.1.1:9080/ruleset/update?module=libruleset&chunkname=%40libruleset.lua" \
    --data-binary @libruleset.lua

# Invoke arbitrary script/code
curl "http://127.0.1.1:9080/ruleset/invoke" -d "_G.some_switch = true"
```

Key scripts and references:

- [agent.lua](agent.lua): RPC-based peer discovery and relay.
- [libruleset.lua](libruleset.lua): ruleset framework and RPC utilities.
- [example/ruleset_simple.lua](example/ruleset_simple.lua): minimal ruleset with domain and IP rule tables; the recommended starting point.
- [example/ruleset.lua](example/ruleset.lua): full-featured ruleset integrating `agent.lua`, schedule-based enable/disable logic, and RPC support.
- [example/ruleset_egress.lua](example/ruleset_egress.lua): egress-side ruleset that blocks private addresses, downloads and maintains an external IP/domain biglist, and routes all remaining traffic directly outbound.
- [example/ruleset_ingress.lua](example/ruleset_ingress.lua): ingress-side ruleset that authenticates clients, routes biglist-matched traffic directly, and forwards everything else through an upstream (egress) proxy; syncs the biglist from the egress peer via RPC.
- [example/lb.lua](example/lb.lua): weighted load balancer using IWRR across multiple backends, with RPC endpoints to update weights at runtime.
- [neosocksd API Reference](https://github.com/hexian000/neosocksd/wiki/API-Reference)
- [Lua 5.4 Reference Manual (external)](https://www.lua.org/manual/5.4/manual.html)


### Distributed Virtual Network

`agent.lua` is a self-contained Lua module for building an autonomous virtual network across multiple LANs:

- peers discover each other through RPC,
- traffic is relayed across nodes,
- remote resources become reachable through a unified local proxy interface.

This is ideal for cross-network access while keeping the deployment lightweight and fully programmable.

Typical workflow:

1. Run neosocksd with the API enabled on each site.
2. Load `libruleset.lua` and `agent.lua`.
3. The agent automatically maintains peer state and relay paths.
4. Access remote targets through the local SOCKS/HTTP endpoint as though they were on the local network.



## Features

- Programmable TCP forwarding proxy — no built-in encryption.
- Supported protocols: SOCKS4, SOCKS4A, SOCKS5 (CONNECT only), HTTP (CONNECT only), and transparent proxy (Linux).
- High performance: 10+ Gbps per x86 core on Linux (with `--pipe`, 2024).
- Lightweight: ~500 KiB executable on most platforms\*.
- Versatile: Lua scripting on the control plane.
- Programmable: rich RPC facilities for scripting; see [Lua Ruleset](#lua-ruleset).
- Hot-reloadable: RESTful API for live monitoring and updating Lua modules without restarts.
- Modern: full IPv6 support and horizontal scalability.
- Standards-compliant: ISO C11 and POSIX.1-2008; additional features may be available on certain platforms.

*\* Some required libraries are dynamically linked, see runtime dependencies below. Statically linked executable can be larger due to these libraries.*

neosocksd supports only basic authentication (plaintext username and password) and does not provide built-in encryption. For transport security, pair it with other tools.


## More Usage Patterns

```sh
# Start a hardened load balancer in the background
sudo ./neosocksd --pipe -d -u nobody: --max-sessions 10000 --max-startups 60:30:100 \
    --bidir-timeout -t 15 -l :80 -f : -r lb.lua --api 127.0.1.1:9080

# Start a transparent proxy that routes TCP traffic according to the ruleset
sudo ./neosocksd --tproxy -l 0.0.0.0:50080 --api 127.0.1.1:9080 -r tproxy.lua \
    --max-startups 60:30:100 --max-sessions 0 -u nobody: -d
```

You can also push gzip-compressed script payloads through the API:

```sh
# Load a gzip-compressed data chunk
curl "http://127.0.1.1:9080/ruleset/invoke" \
    -H "Content-Encoding: gzip" --data-binary @biglist.lua.gz
```


## Observability

Use the built-in RESTful API to monitor service status and runtime metrics.

```sh
# Stateless
watch curl -s http://127.0.1.1:9080/stats
# Stateful: calls the ruleset stats function if available
watch curl -sX POST http://127.0.1.1:9080/stats
```

See [neosocksd API Reference](https://github.com/hexian000/neosocksd/wiki/API-Reference#restful-api) for more details.


## Runtime Dependencies

**Statically-linked setup**: Download a `-static` build from the [Releases](https://github.com/hexian000/neosocksd/releases) section — no additional runtime dependencies are needed.

**Dynamically-linked setup**: Install the following runtime dependencies.

```sh
# Debian / Ubuntu
sudo apt install libev4 libc-ares2
# Alpine Linux
apk add libev c-ares
# OpenWrt
opkg install libev libcares
```

*Note: Lua is always linked statically.*


## Building from Source
### Dependencies

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

### Building with CMake

```sh
git clone https://github.com/hexian000/neosocksd.git
mkdir -p neosocksd-build && cd neosocksd-build
cmake -DCMAKE_BUILD_TYPE="Release" \
    ../neosocksd
cmake --build . --parallel
```

See [m.sh](m.sh) for cross-compilation support.


## Credits

Thanks to:
- [libev](http://software.schmorp.de/pkg/libev.html)
- [Lua](https://www.lua.org/)
- [c-ares](https://c-ares.org/)
- [miniz](https://github.com/richgel999/miniz)
