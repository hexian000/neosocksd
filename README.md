# neosocksd

[![MIT License](https://img.shields.io/github/license/hexian000/neosocksd)](https://github.com/hexian000/neosocksd/blob/master/LICENSE)
[![Build](https://github.com/hexian000/neosocksd/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/neosocksd/actions/workflows/build.yml)
[![Downloads](https://img.shields.io/github/downloads/hexian000/neosocksd/total.svg)](https://github.com/hexian000/neosocksd/releases)
[![Release](https://img.shields.io/github/release/hexian000/neosocksd.svg?style=flat)](https://github.com/hexian000/neosocksd/releases)

A lightweight unencrypted proxy server that can run Lua script as rule set.

- [Introduction](#introduction)
- [Features](#features)
- [Usage](#usage)
  - [Command Line Arguments](#command-line-arguments)
  - [Scripting](#scripting)
- [Observability](#observability)
- [Runtime Dependencies](#runtime-dependencies)
- [Building from Source](#building-from-source)
  - [Dependencies](#dependencies)
  - [Building with CMake](#building-with-cmake)
- [Credits](#credits)


## Introduction

neosocksd is an unencrypted proxy server that allows highly customized rule sets in Lua.

If a proxy rule table is all you need, see the self explaining [ruleset_simple.lua](ruleset_simple.lua).

For advanced scripting usage, see [scripting](#scripting).


## Features

- Supported protocols: SOCKS4, SOCKS4A, SOCKS5 (TCP only), HTTP CONNECT, transparent proxy (Linux).
- High performance: transfer over 10 Gbps per x86 core on Linux. (with `--pipe`, 2024)
- Basic security: supports username/password authentication.
- Flexible: Lua scripts powered rule set.
- Versatile: [working demo](agent.lua) of autonomous peer discovery and connection relay. 
- Hot reloadable: RESTful API for monitoring and updating Lua modules.
- Morden: Full IPv6 support. Horizontally scalable.
- Tiny: embedded systems friendly.
- Conforming to: ISO C11, POSIX.1-2008.


## Usage
### Command Line Arguments

```sh
./neosocksd -l 0.0.0.0:1080               # Just a SOCKS server
./neosocksd -4 -l 0.0.0.0:1080            # Prefer IPv4 in name resolution
./neosocksd -4 -l 0.0.0.0:1080 -i eth0    # And bind outbound connections to eth0
./neosocksd --http -l 0.0.0.0:8080        # HTTP CONNECT server

# Forward connection over proxy chain
# Tip: forwarding in SOCKS5 needs 1 more roundtrip than SOCKS4A/HTTP, so is usually not a good idea.
./neosocksd -l 0.0.0.0:12345 -f 192.168.2.2:12345 -x "socks4a://192.168.1.1:1080,http://192.168.2.1:8080"

# Convert proxy protocol to SOCKS4A
./neosocksd -l 127.0.0.1:1080 -x socks4a://203.0.113.1:1080 -d
./neosocksd --http -l 127.0.0.1:8080 -x socks4a://203.0.113.1:1080 -d

# Start a hardened load balancer in the background
sudo ./neosocksd --pipe -d -u nobody: --max-sessions 10000 \
    --max-startups 60:30:100 -l :80 -t 15 --proto-timeout \
    -f 10.0.0.1:30001 --api 127.0.1.1:9080 -r lb.lua

# Start a rule set powered SOCKS4 / SOCKS4A / SOCKS5 server
./neosocksd -l [::]:1080 --api 127.0.1.1:9080 -r ruleset_simple.lua -d
```

See `./neosocksd -h` for more details.

### Scripting

First, deploy neosocksd with `ruleset.lua` and `libruleset.lua`. (For binary releases, check `neosocksd.noarch.tar.gz`)

- [ruleset.lua](ruleset.lua) is a fancy demo script.
- [libruleset.lua](libruleset.lua) provides rule table facilities.
- [agent.lua](agent.lua) implements autonomous peer discovery and connection relay.
- Developer manual: [neosocksd API Reference](https://github.com/hexian000/neosocksd/wiki/API-Reference), [Lua 5.4 Reference Manual (external)](https://www.lua.org/manual/5.4/manual.html)

Use the following command to start the server with the Lua scripts in current directory:

```sh
# Print rule set logs and error traceback
./neosocksd -l 0.0.0.0:1080 --api 127.0.1.1:9080 -r ruleset.lua --traceback --loglevel 6

# Start a transparent proxy to route TCP traffic by ruleset
sudo ./neosocksd --tproxy -l 0.0.0.0:50080 --api 127.0.1.1:9080 -r tproxy.lua \
    --max-startups 60:30:100 --max-sessions 0 -u nobody: -d
```

Use the following command to update rule set on remote instance without restarting:

```sh
# Reload rule set
curl -v http://127.0.1.1:9080/ruleset/update \
    --data-binary @ruleset.lua

# Reload Lua module
curl -v http://127.0.1.1:9080/ruleset/update?module=libruleset \
    --data-binary @libruleset.lua

# Run any script on the server
curl -v http://127.0.1.1:9080/ruleset/invoke \
    -d "_G.some_switch = true"
curl -v http://127.0.1.1:9080/ruleset/invoke \
    --data-binary @patch.lua
```


## Observability

The builtin RESTful API server can be used for monitoring service status.

```sh
# stateless
watch curl -s http://127.0.1.1:9080/stats
# stateful, will call rule set stats function if available
watch curl -sX POST http://127.0.1.1:9080/stats
```

See [neosocksd API Reference](https://github.com/hexian000/neosocksd/wiki/API-Reference#restful-api) for more details.


## Runtime Dependencies

If you downloaded a *-static build in the [Releases](https://github.com/hexian000/neosocksd/releases) section, you don't have to install the dependencies below.

```sh
# Debian & Ubuntu
sudo apt install libev4 libc-ares2
# Alpine Linux
apk add libev c-ares
# OpenWRT
opkg install libev libcares
```

*Lua is statically linked by default.*


## Building from Source
### Dependencies

| Name   | Version   | Required | Feature                    |
| ------ | --------- | -------- | -------------------------- |
| libev  | >= 4.31   | yes      |                            |
| Lua    | >= 5.3    | no       | rule set                   |
| c-ares | >= 1.16.0 | no       | asynchronous name resolves |

```sh
# Debian & Ubuntu
sudo apt install libev-dev liblua5.4-dev libc-ares-dev
# Alpine Linux
apk add libev-dev lua5.4-dev c-ares-dev
```

### Building with CMake

```sh
git clone https://github.com/hexian000/neosocksd.git
mkdir "neosocksd-build"
cmake -DCMAKE_BUILD_TYPE="Release" \
    -S "neosocksd" \
    -B "neosocksd-build"
cmake --build "neosocksd-build" --parallel
```

See [m.sh](m.sh) for more information about cross compiling support.


## Credits

Thanks to:
- [libev](http://software.schmorp.de/pkg/libev.html)
- [Lua](https://www.lua.org/)
- [c-ares](https://c-ares.org/)
- [miniz](https://github.com/richgel999/miniz)
