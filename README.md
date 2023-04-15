# neosocksd

[![MIT License](https://img.shields.io/github/license/hexian000/neosocksd)](https://github.com/hexian000/neosocksd/blob/master/LICENSE)
[![Build](https://github.com/hexian000/neosocksd/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/neosocksd/actions/workflows/build.yml)
[![Lint](https://github.com/hexian000/neosocksd/actions/workflows/lint.yml/badge.svg)](https://github.com/hexian000/neosocksd/actions/workflows/lint.yml)
[![Release](https://img.shields.io/github/release/hexian000/neosocksd.svg?style=flat)](https://github.com/hexian000/neosocksd/releases)

A lightweight programmable SOCKS4 / SOCKS4A / SOCKS5 / HTTP proxy server that only supports TCP CONNECT requests.

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

## Basic Usage

```sh
./neosocksd -l 0.0.0.0:1080               # Just an SOCKS server
./neosocksd -4 -l 0.0.0.0:1080            # Prefer IPv4 in name resolution
./neosocksd -4 -l 0.0.0.0:1080 -i eth0    # And restrict access to eth0 only

./neosocksd --http -l 0.0.0.0:8080           # HTTP CONNECT server
./neosocksd -l 0.0.0.0:80 -f 127.0.0.1:8080  # Non-forking TCP port forwarder
```

See `./neosocksd -h` for details.

## Scripting Usage

Start the server with a Lua script named "ruleset.lua":

```sh
./neosocksd -4 -l 0.0.0.0:1080 --api 127.0.1.1:9080 -r ruleset.lua
```

- Full code example at [ruleset.lua](ruleset.lua)
- Lua syntax and standard libraries reference: [Lua 5.4 Reference Manual](https://www.lua.org/manual/5.4/manual.html)
- API reference: [neosocksd API Reference](API.md)

Access RESTful API through the proxy as defined in [ruleset.lua](ruleset.lua):

```sh
curl -x socks5h://127.0.0.1:1080 http://neosocksd.lan/stats
```

Update ruleset without restarting:

```sh
curl -0vx socks5h://127.0.0.1:1080 \
    http://neosocksd.lan/ruleset/update \
    --data-binary @ruleset.lua
```

## Build from source
### Dependencies

```sh
# Debian & Ubuntu
sudo apt install -y libev-dev liblua5.4-dev
```

### Build with CMake

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
- [lua](https://www.lua.org/)
