# neosocksd

[![MIT License](https://img.shields.io/github/license/hexian000/neosocksd)](https://github.com/hexian000/neosocksd/blob/master/LICENSE)
[![Build](https://github.com/hexian000/neosocksd/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/neosocksd/actions/workflows/build.yml)
[![Downloads](https://img.shields.io/github/downloads/hexian000/neosocksd/total.svg)](https://github.com/hexian000/neosocksd/releases)
[![Release](https://img.shields.io/github/release/hexian000/neosocksd.svg?style=flat)](https://github.com/hexian000/neosocksd/releases)

neosocksd is a fast and lightweight proxy server written in C, featuring a Lua-powered rules engine. As an imaginative example, it provides an out-of-the-box agent module (in Lua) for establishing an autonomous virtual network that interconnects multiple LANs, allowing seamless cross-network access through a unified proxy.

Status: **Stable**

- [Features](#features)
- [Usage](#usage)
  - [Command-line arguments](#command-line-arguments)
  - [Scripting](#scripting)
- [Observability](#observability)
- [Runtime Dependencies](#runtime-dependencies)
- [Building from Source](#building-from-source)
  - [Dependencies](#dependencies)
  - [Building with CMake](#building-with-cmake)
- [Credits](#credits)


## Features

- This is a TCP forward proxy.
- Supported protocols: SOCKS4, SOCKS4A, SOCKS5 (CONNECT only), HTTP (CONNECT only), and transparent proxy (Linux).
- High performance: transfer 10+ Gbps per x86 core on Linux (with `--pipe`, 2024).
- Lightweight: ~500 KiB executable on most platforms\*.
- Versatile: Lua scripting on the control plane.
- Programmable: rich RPC facilities for scripting; see [Scripting](#scripting).
- Hot-reloadable: RESTful API for monitoring and updating Lua modules.
- Modern: full IPv6 support and horizontal scalability.
- Standards-compliant: ISO C11 and POSIX.1-2008. Additional features may be available on certain platforms.

*\* Some required libraries are dynamically linked, see runtime dependencies below. Statically linked executable can be larger due to these libraries.*

neosocksd supports only basic authentication (plain-text username and password) and does not provide built-in encryption. For transport security, pair it with tools such as [tlswrapper](https://github.com/hexian000/tlswrapper) or [kcptun-libev](https://github.com/hexian000/kcptun-libev).


## Usage
### Command-line arguments

```sh
./neosocksd -l 0.0.0.0:1080               # Just a SOCKS server
./neosocksd -4 -l 0.0.0.0:1080            # Prefer IPv4 in name resolution
./neosocksd -4 -l 0.0.0.0:1080 -i eth0    # And bind outbound connections to eth0
./neosocksd --http -l 0.0.0.0:8080        # HTTP CONNECT server

# Forward connection over proxy chain
./neosocksd -l 0.0.0.0:12345 -f 192.168.2.2:12345 -x "socks5://user:pass@192.168.1.1:1080,http://192.168.2.1:8080"

# Convert proxy protocol to SOCKS4A
./neosocksd -l 127.0.0.1:1080 -x socks4a://203.0.113.1:1080
./neosocksd --http -l 127.0.0.1:8080 -x socks4a://203.0.113.1:1080

# Start a hardened load balancer in the background
sudo ./neosocksd --pipe -d -u nobody: --max-sessions 10000 --max-startups 60:30:100 \
    --proto-timeout -t 15 -l :80 -f : -r lb.lua --api 127.0.1.1:9080

# Start a ruleset powered SOCKS4 / SOCKS4A / SOCKS5 server
./neosocksd -d -l [::]:1080 --api 127.0.1.1:9080 -r ruleset_simple.lua
```

See `./neosocksd --help` for the full list of options.

### Scripting

First, deploy `neosocksd` alongside `libruleset.lua`. (For binary releases, see `neosocksd.noarch.tar.gz`.)

If a proxy rule table is sufficient, see the well-documented [ruleset_simple.lua](example/ruleset_simple.lua).

More examples are available in the [`example`](example) directory.

Other resources:

- [agent.lua](agent.lua) implements RPC-based peer discovery and connection relaying.
- [libruleset.lua](libruleset.lua) provides the ruleset framework and RPC utilities.
- [neosocksd API Reference](https://github.com/hexian000/neosocksd/wiki/API-Reference)
- [Lua 5.4 Reference Manual (external)](https://www.lua.org/manual/5.4/manual.html)

Start the server with the Lua scripts from the current directory:

```sh
# Print ruleset logs and error tracebacks
./neosocksd -l 0.0.0.0:1080 --api 127.0.1.1:9080 -r ruleset.lua --traceback --loglevel 6

# Start a transparent proxy that routes TCP traffic according to the ruleset
sudo ./neosocksd --tproxy -l 0.0.0.0:50080 --api 127.0.1.1:9080 -r tproxy.lua \
    --max-startups 60:30:100 --max-sessions 0 -u nobody: -d
```

Update the ruleset without service interruption:

```sh
# Update the ruleset. Optionally specify a chunk name to appear in stack tracebacks
curl "http://127.0.1.1:9080/ruleset/update?chunkname=%40ruleset.lua" \
    --data-binary @ruleset.lua

# Update a library module
curl "http://127.0.1.1:9080/ruleset/update?module=libruleset&chunkname=%40libruleset.lua" \
    --data-binary @libruleset.lua

# Load a gzip-compressed data chunk
curl "http://127.0.1.1:9080/ruleset/invoke" \
    -H "Content-Encoding: gzip" --data-binary @biglist.lua.gz

# Execute an arbitrary script on the server
curl "http://127.0.1.1:9080/ruleset/invoke" -d "_G.some_switch = true"
curl "http://127.0.1.1:9080/ruleset/invoke" --data-binary @patch.lua
```


## Observability

The built-in RESTful API can be used to monitor service status.

```sh
# Stateless
watch curl -s http://127.0.1.1:9080/stats
# Stateful: calls the ruleset stats function if available
watch curl -sX POST http://127.0.1.1:9080/stats
```

See [neosocksd API Reference](https://github.com/hexian000/neosocksd/wiki/API-Reference#restful-api) for more details.


## Runtime Dependencies

**Statically-linked setup**: Download a `-static` build from the [Releases](https://github.com/hexian000/neosocksd/releases) section — no additional runtime dependencies are needed.

**Dynamically-linked setup**: The following dependencies should be installed.

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
