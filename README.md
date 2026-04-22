# neosocksd

[![MIT License](https://img.shields.io/github/license/hexian000/neosocksd)](https://github.com/hexian000/neosocksd/blob/master/LICENSE)
[![Build](https://github.com/hexian000/neosocksd/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/neosocksd/actions/workflows/build.yml)
[![Downloads](https://img.shields.io/github/downloads/hexian000/neosocksd/total.svg)](https://github.com/hexian000/neosocksd/releases)
[![Release](https://img.shields.io/github/release/hexian000/neosocksd.svg?style=flat)](https://github.com/hexian000/neosocksd/releases)

A fast, lightweight TCP proxy server written in C with a Lua-powered routing engine. Ships with `agent.lua`, an optional module for building an autonomous overlay network across multiple LANs.

Status: **Stable**

- [Features](#features)
- [Usage](#usage)
  - [Protocol Modes](#protocol-modes)
  - [Proxy Chains](#proxy-chains)
  - [Lua Ruleset](#lua-ruleset)
  - [Observability](#observability)
- [Distributed Virtual Network](#distributed-virtual-network)
- [Installation](#installation)
  - [Runtime Dependencies](#runtime-dependencies)
  - [Building from Source](#building-from-source)
    - [Dependencies](#dependencies)
    - [Building with CMake](#building-with-cmake)
- [Credits](#credits)


## Features

- Protocols: SOCKS4, SOCKS4A, SOCKS5 (CONNECT), HTTP CONNECT, transparent proxy (Linux).
- 10+ Gbps per x86 core on Linux (with `--pipe`, 2024); ~500 KiB executable on most platforms\*.
- Lua scripting on the control plane with rich RPC facilities.
- RESTful API for live monitoring and hot-reloading Lua modules without restarts.
- Full IPv6 support; horizontal scalability.
- Standards-compliant: ISO C11 and POSIX.1-2008.
- No built-in encryption — pair with other tools for transport security. Basic authentication only (plaintext).

*\* Dynamically linked builds depend on libev and c-ares; see [Runtime Dependencies](#runtime-dependencies). Statically linked executables can be larger.*


## Usage

### Protocol Modes

```sh
./neosocksd -l 0.0.0.0:1080               # SOCKS server
./neosocksd -4 -l 0.0.0.0:1080            # Prefer IPv4 in DNS resolution
./neosocksd -4 -l 0.0.0.0:1080 -i eth0    # Bind outbound to eth0
./neosocksd -l 0.0.0.0:1080 --http 0.0.0.0:8080 # SOCKS and HTTP server

# Transparent proxy (requires root)
sudo ./neosocksd --tproxy -l 0.0.0.0:50080 --api 127.0.1.1:9080 -r tproxy.lua \
    --max-startups 60:30:100 --max-sessions 0 -u nobody: -d

# Hardened load balancer (requires root)
sudo ./neosocksd --pipe -d -u nobody: --max-sessions 10000 --max-startups 60:30:100 \
    --bidir-timeout -t 15 -l :80 -f : -r lb.lua --api 127.0.1.1:9080
```

For all flags and options, run `./neosocksd --help`.

### Proxy Chains

Forward through an upstream chain and expose a different inbound protocol:

```sh
./neosocksd -l 0.0.0.0:12345 -f 192.168.2.2:12345 \
    -x "socks5://user:pass@192.168.1.1:1080,http://192.168.2.1:8080"

./neosocksd -l 127.0.0.1:1080 --http 0.0.0.0:8080 -x socks4a://203.0.113.1:1080
```

### Lua Ruleset

Binary releases include `neosocksd.noarch.tar.gz` with all Lua scripts. Deploy `neosocksd` alongside `libruleset.lua`.

```sh
# Simple rule table
./neosocksd -d -l [::]:1080 --api 127.0.1.1:9080 -r ruleset_simple.lua

# Full ruleset with tracing
./neosocksd -l 0.0.0.0:1080 --api 127.0.1.1:9080 \
    -r ruleset.lua --traceback --loglevel 6
```

Hot-reload without restart:

```sh
# Replace the main ruleset chunk
curl "http://127.0.1.1:9080/ruleset/update?chunkname=%40ruleset.lua" \
    --data-binary @ruleset.lua

# Replace a module
curl "http://127.0.1.1:9080/ruleset/update?module=libruleset&chunkname=%40libruleset.lua" \
    --data-binary @libruleset.lua

# Eval arbitrary code
curl "http://127.0.1.1:9080/ruleset/invoke" -d "_G.some_switch = true"

# Push a gzip-compressed chunk
curl "http://127.0.1.1:9080/ruleset/invoke" \
    -H "Content-Encoding: gzip" --data-binary @biglist.lua.gz
```

Provided scripts:

| Script                                                     | Description                                                                             |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| [libruleset.lua](libruleset.lua)                           | Ruleset framework and RPC utilities                                                     |
| [agent.lua](agent.lua)                                     | RPC-based peer discovery and relay                                                      |
| [example/ruleset_simple.lua](example/ruleset_simple.lua)   | Minimal ruleset with domain and IP rule tables                                          |
| [example/ruleset.lua](example/ruleset.lua)                 | Full ruleset: `agent.lua` integration, schedule-based logic, RPC                        |
| [example/ruleset_egress.lua](example/ruleset_egress.lua)   | Egress: blocks private addresses, maintains external IP/domain biglist, direct outbound |
| [example/ruleset_ingress.lua](example/ruleset_ingress.lua) | Ingress: client auth, biglist routing, upstream proxy fallback, RPC biglist sync        |
| [example/lb.lua](example/lb.lua)                           | IWRR weighted load balancer with runtime weight updates via RPC                         |

References: [neosocksd API Reference](https://github.com/hexian000/neosocksd/wiki/API-Reference) · [Lua 5.4 Manual](https://www.lua.org/manual/5.4/manual.html)

### Observability

```sh
# Stateless snapshot
watch curl -s http://127.0.1.1:9080/stats

# Stateful: invokes the ruleset stats function if defined
watch curl -sX POST http://127.0.1.1:9080/stats
```

See [neosocksd API Reference](https://github.com/hexian000/neosocksd/wiki/API-Reference#restful-api) for the full API.


## Distributed Virtual Network

`agent.lua` builds an autonomous overlay across multiple LANs: peers discover each other via RPC, traffic is relayed across nodes, and remote resources are reachable through the local proxy endpoint.

Setup on each site:

1. Start neosocksd with the API enabled.
2. Load `libruleset.lua` and `agent.lua`.
3. The agent maintains peer state and relay paths automatically.
4. Access remote targets through the local SOCKS/HTTP endpoint.


## Installation

### Runtime Dependencies

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


### Building from Source

#### Dependencies

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

#### Building with CMake

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
