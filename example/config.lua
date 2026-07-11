-- [[ config.lua: comprehensive boot configuration example ]] --
-- Load with: neosocksd -c config.lua
--
-- Loaded in "config" mode; must return a Lua table.  Fields set to nil are
-- inherited from command-line arguments (or defaults).
--
-- To install a ruleset, set `_G.ruleset` in this script's body, or set the
-- `ruleset` field below to a table.  For a standalone ruleset file, use the
-- `-r'/`--ruleset' command-line option instead (`-c' and `-r' are mutually
-- exclusive).

-- [[ optional: read extra arguments from the command line ]] --
-- Example: neosocksd -c config.lua --dev eth0
local netdev = nil
do
    local argv = { ... }
    local argc = #argv
    local i = 1
    while i <= argc do
        if argv[i] == "--dev" and i < argc then
            i = i + 1
            netdev = argv[i]
        end
        i = i + 1
    end
end

-- [[ return the effective configuration table ]] --
return {
    -- ------------------------------------------------------------------ --
    -- Listener addresses (host:port or [host]:port for IPv6)             --
    -- ------------------------------------------------------------------ --

    -- SOCKS 4/4a/5 proxy listen address (required unless http_listen is set)
    listen              = "0.0.0.0:1080",

    -- HTTP proxy listen address; if set without listen, acts as HTTP-only.
    -- Incompatible with forward and transparent.
    -- http_listen = "0.0.0.0:8080",

    -- TCP port-forwarding target; replaces proxy behaviour with plain forward.
    -- Incompatible with http_listen and transparent.
    -- Use ":" to rely on the ruleset for the destination.
    -- forward = "127.0.0.1:8080",

    -- RESTful API listen address (recommended: loopback only)
    restapi             = "127.0.1.1:9080",

    -- ------------------------------------------------------------------ --
    -- Outbound                                                           --
    -- ------------------------------------------------------------------ --

    -- Upstream proxy chain (comma-separated, evaluated left-to-right).
    -- Supported schemes: socks4a://, socks5://, http://
    -- Overridden at runtime when a ruleset is loaded.
    -- proxy = "socks5://user:pass@gate.internal:1080",
    -- proxy = "socks4a://proxy1:1080,socks4a://proxy2:1080",

    -- ------------------------------------------------------------------ --
    -- Ruleset (requires a build with Lua scripting support)              --
    -- ------------------------------------------------------------------ --

    -- The ruleset: a table used directly as _G.ruleset
    -- (e.g. require("libruleset")).  When active, it overrides the proxy above.
    -- Incompatible with socks5_bind and socks5_udp.  For a standalone ruleset
    -- file, use `-r'/`--ruleset' on the command line instead.
    -- ruleset = require("libruleset"),

    -- Print a full Lua traceback on ruleset errors (useful for debugging).
    -- traceback = false,

    -- Soft limit on total Lua object memory in MiB (0 = unlimited).
    -- memlimit = 64,

    -- ------------------------------------------------------------------ --
    -- Authentication (requires a build with Lua scripting support; pass  --
    -- --auth-required to enforce; credentials are validated inside the   --
    -- ruleset)                                                           --
    -- ------------------------------------------------------------------ --

    -- auth_required = false,

    -- ------------------------------------------------------------------ --
    -- DNS resolution                                                     --
    -- ------------------------------------------------------------------ --

    -- Address family used when resolving domain names requested by clients.
    --   0  = PF_UNSPEC  (system default, may return IPv4 or IPv6)
    --   2  = PF_INET    (IPv4 only, equivalent to -4)
    --   10 = PF_INET6   (IPv6 only, equivalent to -6)
    resolve_pf          = 0,

    -- Custom nameserver address (needs a build with asynchronous DNS support).
    -- nameserver = "8.8.8.8",

    -- ------------------------------------------------------------------ --
    -- Network device binding (GNU/Linux only)                            --
    -- ------------------------------------------------------------------ --

    -- Bind all outgoing connections to this network interface.
    netdev              = netdev, -- nil unless --dev was passed on the command line

    -- ------------------------------------------------------------------ --
    -- TCP options                                                        --
    -- ------------------------------------------------------------------ --

    -- Disable Nagle's algorithm; reduces latency at the cost of bandwidth.
    tcp_nodelay         = true,

    -- Enable SO_KEEPALIVE; helps detect dead peers.
    tcp_keepalive       = true,

    -- Server-side TCP Fast Open (RFC 7413).  Requires Linux 3.7 or later.
    -- tcp_fastopen = true,

    -- Client-side TCP Fast Open.  Requires Linux 4.11 or later.
    -- May cause issues with --pipe and server-speaks-first protocols.
    -- tcp_fastopen_connect = false,

    -- TCP send/receive socket buffer sizes in bytes (0 = system default).
    -- Values below 16384 trigger a warning.
    tcp_sndbuf          = 0,
    tcp_rcvbuf          = 0,

    -- Use splice(2)/pipes to move data between connections (GNU/Linux only).
    -- Trade-off: uses 2 extra fds per connection, but improves throughput.
    -- pipe = false,

    -- Allow multiple neosocksd instances to share the same listen port.
    -- Requires Linux 3.9 or later.
    -- reuseport = false,

    -- Enable transparent proxy mode (GNU/Linux only).
    -- Incompatible with http_listen and forward.
    -- transparent = false,

    -- ------------------------------------------------------------------ --
    -- Connection management                                              --
    -- ------------------------------------------------------------------ --

    -- Enable SOCKS5 BIND command.  Incompatible with ruleset and proxy.
    socks5_bind         = false,

    -- Enable SOCKS5 UDP ASSOCIATE command.  Incompatible with ruleset and proxy.
    socks5_udp          = false,

    -- Maximum number of concurrent fully-established sessions (0 = unlimited).
    max_sessions        = 0,

    -- Throttle half-open (connecting) sessions using an sshd-style ramp.
    -- Format mirrors --max-startups start:rate:full:
    --   start: refuse no connections below this count
    --   rate:  refuse this % of new connections once start is exceeded (0-100)
    --   full:  refuse all new connections at or above this count
    -- All three must be 0 (disabled) or satisfy start <= full.
    startup_limit_start = 0,
    startup_limit_rate  = 30,
    startup_limit_full  = 0,

    -- Half-open connection timeout in seconds [5.0, 86400.0].
    timeout             = 60.0,

    -- ------------------------------------------------------------------ --
    -- Outbound address filtering                                         --
    -- ------------------------------------------------------------------ --

    -- Block connections destined for loopback addresses (127.0.0.0/8, ::1).
    block_loopback      = false,

    -- Block connections destined for multicast addresses (default: true).
    block_multicast     = true,

    -- Block connections to RFC-1918 / ULA addresses (10/8, 172.16/12,
    -- 192.168/16, fc00::/7, link-local, etc.).
    -- Mutually exclusive with block_global.
    block_local         = false,

    -- Block all globally routable outbound connections.
    -- Mutually exclusive with block_local.
    block_global        = false,

    -- ------------------------------------------------------------------ --
    -- Logging and process management                                     --
    -- ------------------------------------------------------------------ --

    -- Log verbosity level:
    --   0 Silence  1 Fatal  2 Error  3 Warning  4 Notice (default)
    --   5 Info     6 Debug  7 Verbose  8 VeryVerbose
    loglevel            = 4,

    -- Drop privileges after binding sockets.  Format: "user" or "user:group".
    -- user_name = "nobody:nogroup",

    -- Detach from the terminal and write logs to syslog.
    daemonize           = false,
}
