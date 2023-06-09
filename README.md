# neosocksd

[![MIT License](https://img.shields.io/github/license/hexian000/neosocksd)](https://github.com/hexian000/neosocksd/blob/master/LICENSE)
[![Build](https://github.com/hexian000/neosocksd/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/neosocksd/actions/workflows/build.yml)
[![Lint](https://github.com/hexian000/neosocksd/actions/workflows/lint.yml/badge.svg)](https://github.com/hexian000/neosocksd/actions/workflows/lint.yml)
[![Release](https://img.shields.io/github/release/hexian000/neosocksd.svg?style=flat)](https://github.com/hexian000/neosocksd/releases)

A lightweight programmable SOCKS4 / SOCKS4A / SOCKS5 / HTTP proxy server that only supports TCP CONNECT requests.

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
- Top class processor/memory/storage/bandwidth efficiency.
- Lua scripts powered rule set.
- Routing connections by rule and even building an autonomous proxy mesh.
- Horizontally scalable.
- RESTful API for monitoring and updating rules online.
- IPv6 supported (SOCKS4A / SOCKS5 / HTTP).
- Minimized resource usage, embedded systems friendly.
- Conforming to: ISO C11, POSIX.1-2008.

## Usage
### Basic Usage

```sh
./neosocksd -l 0.0.0.0:1080               # Just a SOCKS server
./neosocksd -4 -l 0.0.0.0:1080            # Prefer IPv4 in name resolution
./neosocksd -4 -l 0.0.0.0:1080 -i eth0    # And restrict client access to eth0 only
./neosocksd --http -l 0.0.0.0:8080        # HTTP CONNECT server

# Start a non-forking TCP port forwarder in the background
sudo ./neosocksd -l 0.0.0.0:80 -f 127.0.0.1:8080 -u nobody -d
```

See `./neosocksd -h` for details.

### Scripting Usage

First, deploy neosocksd with `ruleset.lua` and `libruleset.lua`. (For binary releases, check `neosocksd.noarch.tar.gz`)

Use the following command to start the server with the Lua scripts in current directory:

```sh
./neosocksd -l 0.0.0.0:1080 --api 127.0.1.1:9080 -r ruleset.lua -v
```

Depending on how complex your customizations are, check out:

- Level 1: Rule set configuration example at [ruleset.lua](ruleset.lua)
- Level 2: Rule set library code in [libruleset.lua](libruleset.lua)
- Level 3: Reference manual for enthusiasts and professionals: [neosocksd API Reference](https://github.com/hexian000/neosocksd/wiki/API-Reference), [Lua 5.4 Reference Manual (external)](https://www.lua.org/manual/5.4/manual.html)

```sh
curl -0sX POST http://127.0.1.1:9080/stats
```

Update ruleset on remote instance without restarting:

```sh
curl -0vx socks5h://192.168.1.1:1080 \
    http://neosocksd.lan/ruleset/update \
    --data-binary @ruleset.lua
```

The host name `neosocksd.lan` is defined in [ruleset.lua](ruleset.lua):

[neox.sh](neox.sh) is a curl wrapper script for simplified shell operating.

*Note: Since the HTTP/1.0 API server has a fixed buffer size of 8 KiB, you will not be able to load large scripts with this command. Consider sharded updates for large script projects.*

## Runtime Dependencies

If you downloaded a *-static build in the [Releases](https://github.com/hexian000/neosocksd/releases) section, you don't have to install the dependencies below.

```sh
# Debian & Ubuntu
sudo apt install -y libev4
# OpenWRT
opkg install libev
```

*Lua is always statically linked.*

## Building from Source
### Dependencies

```sh
# Debian & Ubuntu
sudo apt install -y libev-dev liblua5.4-dev
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
