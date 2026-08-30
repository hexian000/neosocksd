# neosocksd

[![MIT License](https://img.shields.io/github/license/hexian000/neosocksd)](https://github.com/hexian000/neosocksd/blob/master/LICENSE)
[![Build](https://github.com/hexian000/neosocksd/actions/workflows/build.yml/badge.svg)](https://github.com/hexian000/neosocksd/actions/workflows/build.yml)
[![Downloads](https://img.shields.io/github/downloads/hexian000/neosocksd/total.svg)](https://github.com/hexian000/neosocksd/releases)
[![Release](https://img.shields.io/github/release/hexian000/neosocksd.svg?style=flat)](https://github.com/hexian000/neosocksd/releases)

A fast, lightweight proxy server written in C with a Lua-powered routing engine. Ships with `agent.lua`, an optional module for building an autonomous overlay network across multiple LANs.

Status: **Stable**

- [Features](#features)
- [Usage](#usage)
  - [Protocol Modes](#protocol-modes)
  - [Proxy Chains](#proxy-chains)
  - [Lua Ruleset](#lua-ruleset)
  - [Observability](#observability)
- [Distributed Virtual Network](#distributed-virtual-network)
- [Horizontal Scaling](#horizontal-scaling)
- [Battery-Powered Deployment](#battery-powered-deployment)
- [Installation](#installation)
  - [Runtime Dependencies](#runtime-dependencies)
  - [Building from Source](#building-from-source)
    - [Dependencies](#dependencies)
    - [Building with CMake](#building-with-cmake)
- [Credits](#credits)


## Features

- Protocols: [SOCKS4](https://www.openssh.com/txt/socks4.protocol)/[SOCKS4A](https://www.openssh.com/txt/socks4a.protocol) (Ying-Da Lee / NEC), SOCKS5 ([RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928), with [RFC 1929](https://datatracker.ietf.org/doc/html/rfc1929) auth), HTTP/1.1 proxy — `CONNECT` tunneling ([RFC 9110 §9.3.6](https://datatracker.ietf.org/doc/html/rfc9110#section-9.3.6)).
- Optional legacy compatibility: The following SOCKS5 commands are off by default and work only in plain proxy mode (not through chains or rulesets): BIND (`--enable-socks5-bind`, relays an inbound connection from the target back to the client); UDP ASSOCIATE (`--enable-socks5-udp`, relays UDP datagrams).
- Transparent proxy: Linux [TPROXY](https://docs.kernel.org/networking/tproxy.html).
- 10+ Gbps per x86 core on Linux with `--pipe` (measured in 2024).
- <800 KiB executable on most platforms\*. See [Runtime Dependencies](#runtime-dependencies).
- Lua scripting on the control plane with extensive RPC support.
- RESTful API for live monitoring and hot-reloading Lua modules without restarts.
- Full IPv6 support; [horizontal scalability](#horizontal-scaling) via multiple `--reuseport` instances.
- Standards-compliant: ISO C11 and POSIX.1-2008.
- No built-in encryption — pair with external tools for transport security. Supports basic authentication (plaintext credentials) only.

*\* Dynamically linked builds depend on libev and c-ares; see [Runtime Dependencies](#runtime-dependencies). Statically linked executables may be larger due to bundled dependencies.*


## Usage

### Protocol Modes

```sh
./neosocksd -l 0.0.0.0:1080  # SOCKS server
./neosocksd -4 -l 0.0.0.0:1080  # Prefer IPv4 in DNS resolution
./neosocksd -4 -l 0.0.0.0:1080 -i eth0  # Bind outbound to eth0
./neosocksd -l 0.0.0.0:1080 --http 0.0.0.0:8080  # SOCKS and HTTP server
./neosocksd -l 0.0.0.0:1080 --enable-socks5-bind --enable-socks5-udp  # Allow SOCKS5 BIND and UDP ASSOCIATE

# Transparent proxy (requires root)
sudo ./neosocksd --tproxy -l 0.0.0.0:50080 --api 127.0.1.1:9080 -r tproxy.lua \
    --max-startups 60:30:100 --max-sessions 0 -u nobody: -d

# Hardened load balancer (requires root)
sudo ./neosocksd --pipe -d -u nobody: --max-sessions 10000 --max-startups 60:30:100 \
    -t 15 -l :80 -f : -r lb.lua --api 127.0.1.1:9080
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

Binary releases include `neosocksd.noarch.tar.gz` with `libruleset.lua`, `agent.lua`, and the `example/` scripts. Deploy `neosocksd` alongside `libruleset.lua`.

```sh
# Simple rule table
./neosocksd -d -l [::]:1080 --api 127.0.1.1:9080 -r ruleset_simple.lua

# Full ruleset with tracing
./neosocksd -l 0.0.0.0:1080 --api 127.0.1.1:9080 \
    -r ruleset.lua --traceback --loglevel 6

# Gzip-compressed Lua files
./neosocksd -l 0.0.0.0:1080 -r ruleset.lua.gz
./neosocksd -c config.lua.gz
```

`-c config.lua` loads a boot config that configures the server and can also
install the ruleset — the config script returns a table of server options and
either sets `_G.ruleset` or provides a `ruleset` field. Use `-r ruleset.lua`
for a standalone ruleset file. The two options are mutually exclusive.

```sh
# One file does both: configure the server and set up the ruleset
./neosocksd -c config.lua
```

The ruleset routes each request, then actively forwards it with `await.forward`
and learns whether the upstream connected — see
[await.forward](https://github.com/hexian000/neosocksd/wiki/API-Reference#awaitforward)
for failover and retries.

Hot-reload without restart:

```sh
# Replace the active ruleset
curl "http://127.0.1.1:9080/ruleset/update?chunkname=%40ruleset.lua" \
    --data-binary @ruleset.lua

# Replace a module
curl "http://127.0.1.1:9080/ruleset/update?module=libruleset&chunkname=%40libruleset.lua" \
    --data-binary @libruleset.lua

# Execute arbitrary code
curl "http://127.0.1.1:9080/ruleset/invoke" -d "_G.some_switch = true"

# Push a gzip-compressed chunk
curl "http://127.0.1.1:9080/ruleset/invoke" \
    -H "Content-Encoding: gzip" --data-binary @biglist.lua.gz
```

> **Security note:** The RESTful API (`--api`) has no built-in authentication —
> anyone who can reach it can execute arbitrary Lua code via `/ruleset/invoke`
> or hot-swap the running ruleset via `/ruleset/update`. Bind it to loopback
> or a trusted, firewalled network only; never expose `--api` to an
> untrusted network.

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

Set up on each node:

1. Start neosocksd with the API enabled.
2. Load `libruleset.lua` and `agent.lua`.
3. The agent maintains peer state and relay paths automatically.
4. Access remote targets through the local SOCKS/HTTP endpoint.

The API must be reachable between nodes for peer discovery to work — see the
[security note](#lua-ruleset) above. Restrict it to a trusted network (e.g. a
VPN or private LAN link between nodes), not the public internet.


## Horizontal Scaling

Within one process, the accept loop, both proxy handshakes, `ruleset.route` and
outbound dialing all run on a single thread; only relayed payload is offloaded.
To put the control path on more cores, or to spread load across machines, run
**several independent instances**. On Linux, `--reuseport` lets them share one
listening port and the kernel load-balances new connections across them:

```sh
# Four instances sharing 0.0.0.0:1080, each with its own API address.
# The kernel spreads incoming connections across them.
for i in 1 2 3 4; do
    ./neosocksd --reuseport -l 0.0.0.0:1080 -r ruleset.lua \
        --api "127.0.0.$i:9080" -d
done
```

The same fleet as a systemd template unit, started with
`systemctl enable --now neosocksd@{1..4}`:

```ini
# /etc/systemd/system/neosocksd@.service
[Service]
# %i is the instance number: each binds a distinct loopback API address.
ExecStart=/usr/bin/neosocksd --reuseport -l 0.0.0.0:1080 -r /etc/neosocksd/ruleset.lua --api 127.0.0.%i:9080
DynamicUser=yes
Restart=on-failure
```

`--reuseport` requires Linux 3.9 or later (`SO_REUSEPORT`) and is compiled in
only where the kernel headers provide it.

Every instance is a **separate process** with nothing shared between them, so
plan for these per-instance consequences:

- **The ruleset is per instance.** Each process runs its own Lua VM with its own
  state — the `libruleset` biglists, and `agent.lua`'s peer database, connection
  state, route index and gossip digests. N instances are N independent rulesets;
  they converge only through whatever your ruleset syncs over RPC.
- **`--api` reaches one arbitrary instance.** The API is just another listener,
  so under a shared `--reuseport` port a request lands on whichever instance the
  kernel picks — `/ruleset/update`, `/ruleset/invoke`, `/ruleset/gc` and
  `POST /stats` then act on that **one** process, not the fleet. A hot reload
  does *not* propagate; give each instance its own API address (as above) and
  drive them individually to update or inspect all of them.
- **Limits are per process.** `--max-sessions` and `--max-startups` are enforced
  independently by each instance, so the effective ceiling across N instances is
  N times the configured value — divide the target accordingly.
- **Counters are per process.** `/stats` and `/metrics` report the queried
  instance's own counters, never a fleet total; scrape every instance and sum.


## Battery-Powered Deployment

On a phone or any battery-powered host, the cost of a daemon is dominated by how
often it wakes the CPU and the radio, not by how much work it does when it runs.

An idle neosocksd performs **no periodic work at all**: an established relay
carries no timer, and with no ruleset tick armed the event loop blocks
indefinitely. Everything that still wakes it is something you configure.

### Measuring on the device

Measure before tuning. Start the daemon, leave it idle, and count its wakeups:

```sh
PID=$(pidof neosocksd)
grep voluntary_ctxt_switches /proc/$PID/status  # wait a few minutes, compare
awk '{print $14+$15}' /proc/$PID/stat           # utime+stime, in clock ticks
```

An idle daemon with no ruleset tick should hold both counters completely still.
Anything else is traffic or a tick, and the sources below explain which.

```sh
ss -tio                     # per-connection state, including keepalive timers
dumpsys batterystats        # Android's own attribution, for the whole picture
```

### Wakeup sources, in order of impact

- **The ruleset tick.** `neosocksd.setinterval(n)` wakes the loop every `n`
  seconds forever, whether or not anything is connected. Every shipped example
  ruleset arms `neosocksd.setinterval(60)`; if your ruleset does not need
  periodic work, do not arm it at all.
- **`neosocksd.setinterval(n)` with a negative `n`** runs `ruleset.tick()` on
  every loop iteration and never blocks — a full core, indefinitely. It exists
  for latency-critical setups; never use it on battery.
- **`agent.lua`.** The overlay agent probes every peer over the network on an
  adaptive interval, and re-enters Lua every `PROBE_INTERVAL_MIN` seconds
  regardless of how far the interval has backed off. Do not load it unless you
  are actually running a mesh.
- **TCP keepalive.** Enabled by default on every accepted and dialed socket.
  Each probe on an idle connection is a radio wakeup. The kernel defaults are
  tuned for servers (2 hours idle); `tcp_keepidle`, `tcp_keepintvl` and
  `tcp_keepcnt` in the boot config let you trade failure-detection speed for
  quiet, and `tcp_keepalive = false` turns probing off entirely — at the cost of
  the liveness detection that streaming responses and `CONNECT` tunnels rely on.

### Suggested profile

```sh
cmake -DCMAKE_BUILD_TYPE="Release" -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
    -DENABLE_THREADS=OFF ..
```

`ENABLE_THREADS=OFF` keeps everything on one thread and one event loop; the I/O
offload thread pays off under concurrency a phone will not reach.

At runtime, omit `--api` unless you use it, keep the log quiet (`--loglevel 3`),
and pass `-4` where IPv6 is not needed — resolving a name without it queries
both `A` and `AAAA`, doubling the DNS round trips. `--pipe` moves payload with
`splice(2)` instead of copying it through userspace, at the cost of two extra
file descriptors per session.


## Installation

### Runtime Dependencies

**Statically linked setup**: Download a `-static` build from the [Releases](https://github.com/hexian000/neosocksd/releases) section — no additional runtime dependencies are needed.

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
