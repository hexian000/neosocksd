# neosocksd

[![MIT License](https://img.shields.io/github/license/hexian000/neosocksd)](https://github.com/hexian000/neosocksd/blob/master/LICENSE)
[![Build](https://github.com/hexian000/neosocksd/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/neosocksd/actions/workflows/build.yml)
[![Lint](https://github.com/hexian000/neosocksd/actions/workflows/lint.yml/badge.svg)](https://github.com/hexian000/neosocksd/actions/workflows/lint.yml)
[![Release](https://img.shields.io/github/release/hexian000/neosocksd.svg?style=flat)](https://github.com/hexian000/neosocksd/releases)

A lightweight SOCKS4 / SOCKS4A / SOCKS5 / HTTP proxy server that can run Lua script as ruleset.

- [Features](#features)
- [Usage](#usage)
	- [Basic Usage](#basic-usage)
	- [Scripting Usage](#scripting-usage)
- [Runtime Dependencies](#runtime-dependencies)
- [Building from Source](#building-from-source)
	- [Dependencies](#dependencies)
	- [Building with CMake](#building-with-cmake)
- [Credits](#credits)

## Features

- Plain old protocols with no built-in support for authentication or encryption.
- Only TCP CONNECT requests are supported.
- Top class processor efficiency, minimized memory usage and code size.
- Lua scripts powered rule set.
- Routing connections by rule and even building an autonomous proxy mesh.
- Horizontally scalable.
- RESTful API for monitoring and updating rules online.
- IPv6 supported (SOCKS4A / SOCKS5 / HTTP).
- Embedded systems friendly.
- Conforming to: ISO C11, POSIX.1-2008.

## Usage
### Basic Usage

```sh
./neosocksd -l 0.0.0.0:1080               # Just a SOCKS server
./neosocksd -4 -l 0.0.0.0:1080            # Prefer IPv4 in name resolution
./neosocksd -4 -l 0.0.0.0:1080 -i eth0    # And bind outbound connections to eth0
./neosocksd --http -l 0.0.0.0:8080        # HTTP CONNECT server

# Forward connection over proxy chain
# Tip: forwarding in SOCKS5 requires 1 more roundtrip than SOCKS4A/HTTP, so is generally not a good idea.
./neosocksd -l 192.168.1.2:12345 -f "192.168.2.2:12345,socks4a://192.168.2.1:1080,http://192.168.1.1:8080"

# Start a hardened non-forking TCP port forwarder in the background
sudo ./neosocksd -d -u nobody -l 0.0.0.0:80 -f 127.0.0.1:8080 -t 15 \
    --proto-timeout --max-startups 60:30:100 --max-sessions 10000
```

See `./neosocksd -h` for details.

### Scripting Usage

First, deploy neosocksd with `ruleset.lua` and `libruleset.lua`. (For binary releases, check `neosocksd.noarch.tar.gz`)

Depending on how complex your customizations are, check out:

- Level 1: Rule set configuration example at [ruleset.lua](ruleset.lua)
- Level 2: Rule set library code in [libruleset.lua](libruleset.lua)
- Level 3: Reference manual for enthusiasts and professionals: [neosocksd API Reference](https://github.com/hexian000/neosocksd/wiki/API-Reference), [Lua 5.4 Reference Manual (external)](https://www.lua.org/manual/5.4/manual.html)

Use the following command to start the server with the Lua scripts in current directory:

```sh
# Start a ruleset powered SOCKS4 / SOCKS4A / SOCKS5 server
./neosocksd -l [::]:1080 --api 127.0.1.1:9080 -r ruleset.lua -d

# For debugging ruleset script
./neosocksd -l 0.0.0.0:1080 --api 127.0.1.1:9080 -r ruleset.lua --traceback -v

# Start a transparent proxy to route TCP traffic by ruleset
sudo ./neosocksd --tproxy -l 0.0.0.0:50080 --api 127.0.1.1:9080 -r tproxy.lua \
    --max-startups 60:30:100 --max-sessions 0 -u nobody -d
```

Check server statistics via RESTful API:

```sh
curl -sX POST http://127.0.1.1:9080/stats
```

Load ruleset on remote instance without restarting:

```sh
curl -vx socks5h://192.168.1.1:1080 \
    http://neosocksd.lan/ruleset/update \
    --data-binary @ruleset.lua
```

The host name `neosocksd.lan` is defined in [ruleset.lua](ruleset.lua):


## Runtime Dependencies

If you downloaded a *-static build in the [Releases](https://github.com/hexian000/neosocksd/releases) section, you don't have to install the dependencies below.

```sh
# Debian & Ubuntu
sudo apt install libev4 libc-ares2
# OpenWRT
opkg install libev libcares
```

*Lua is always statically linked.*

## Building from Source
### Dependencies

| Name   | Version   | Required | Feature                    |
| ------ | --------- | -------- | -------------------------- |
| c-ares | >= 1.16.0 | no       | asynchronous name resolves |
| libev  | >= 4.31   | yes      |                            |
| Lua    | >= 5.3    | yes      | ruleset                    |

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
- [c-ares](https://c-ares.org/)
- [libev](http://software.schmorp.de/pkg/libev.html)
- [Lua](https://www.lua.org/)
