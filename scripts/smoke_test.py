#!/usr/bin/env python3

"""End-to-end smoke test for the built neosocksd binary.

Drives the real `neosocksd` executable the way live clients do: speaks
SOCKS4/4A/5 and HTTP (CONNECT) over real sockets, exercises the
RESTful API over HTTP, and validates ruleset routing, hot reload, proxy chaining
and TCP forwarding.

The test is hermetic: it starts its own loopback TCP echo server and a tiny
HTTP responder as proxy targets, so it needs no internet access or external DNS.
It uses the Python standard library only -- the SOCKS/HTTP proxy clients are
hand-rolled. Privileged features (TPROXY, privilege drop) are out of scope.

Usage:
    scripts/smoke_test.py [--build DIR] [--binary PATH] [--loglevel N]
                          [--filter SUBSTR] [--list] [-o OUTPUT] [-k]
"""

from __future__ import annotations

import argparse
import http.client
import random
import re
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple


ROOT = Path.cwd().resolve()
DEFAULT_BUILD_DIR = ROOT / "build"
DEFAULT_OUTPUT = DEFAULT_BUILD_DIR / "smoke_test.md"

HOST = "127.0.0.1"
HOST6 = "::1"
READY_TIMEOUT = 5.0
IO_TIMEOUT = 5.0
SHUTDOWN_TIMEOUT = 5.0

# the /ruleset/rpcall wire contract, mirroring MIME_RPCALL and
# RPCALL_COMPRESS_THRESHOLD in src/proto/http.h
RPCALL_MIME = "application/x-neosocksd-rpc; version=1"
RPCALL_COMPRESS_THRESHOLD = 256


def log(message: str) -> None:
    print(message, file=sys.stderr)


def ensure_project_root(root: Path) -> None:
    if not (root / "CMakeLists.txt").exists():
        raise SystemExit(
            "working directory does not look like the project root: %s" % root
        )


# --------------------------------------------------------------------------- #
# Low-level socket helpers
# --------------------------------------------------------------------------- #


def free_port() -> int:
    """Return a currently-unused TCP port on the loopback interface.

    There is an inherent race between closing the probe socket and the daemon
    binding the port, but in practice neosocksd binds immediately on startup and
    nothing else competes for loopback ephemeral ports during the test.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise AssertionError(
                "connection closed after %d/%d bytes" % (
                    count - remaining, count)
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def echo_roundtrip(sock: socket.socket, size: int = 4096) -> None:
    """Send a random payload and assert it is echoed back verbatim."""
    payload = random.randbytes(size)
    sock.sendall(payload)
    got = recv_exact(sock, size)
    if got != payload:
        raise AssertionError("echo payload mismatch (%d bytes)" % size)


class SocksError(Exception):
    """A SOCKS handshake failure. `stage` names where it failed ("method",
    "userpass", "connect") and `code` carries the protocol reply byte, so a
    negative test can assert the specific failure cause rather than accepting
    any SOCKS failure."""

    def __init__(
        self,
        message: str,
        *,
        stage: Optional[str] = None,
        code: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.code = code


# --------------------------------------------------------------------------- #
# Hand-rolled proxy clients
# --------------------------------------------------------------------------- #


def _connect(host: str, port: int) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=IO_TIMEOUT)
    sock.settimeout(IO_TIMEOUT)
    return sock


def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    dst_host: str,
    dst_port: int,
    user: Optional[str] = None,
    password: Optional[str] = None,
    offer_noauth: bool = True,
) -> socket.socket:
    """Open a SOCKS5 CONNECT tunnel and return the connected socket."""
    sock = _connect(proxy_host, proxy_port)
    try:
        methods = bytearray()
        if offer_noauth:
            methods.append(0x00)
        if user is not None:
            methods.append(0x02)
        if not methods:
            methods.append(0x00)
        sock.sendall(bytes([0x05, len(methods)]) + bytes(methods))
        ver, method = recv_exact(sock, 2)
        if ver != 0x05:
            raise SocksError("bad SOCKS5 version in method reply: %d" % ver)
        if method == 0xFF:
            raise SocksError(
                "no acceptable authentication method",
                stage="method",
                code=0xFF,
            )
        if method == 0x02:
            if user is None:
                raise SocksError("server demanded user/pass but none supplied")
            u = user.encode()
            p = (password or "").encode()
            sock.sendall(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
            _, status = recv_exact(sock, 2)
            if status != 0x00:
                raise SocksError(
                    "username/password auth failed",
                    stage="userpass",
                    code=status,
                )
        elif method != 0x00:
            raise SocksError("unexpected auth method selected: %d" % method)

        req = bytearray([0x05, 0x01, 0x00])
        try:
            req.append(0x01)  # ATYP IPv4
            req += socket.inet_pton(socket.AF_INET, dst_host)
        except OSError:
            try:
                packed6 = socket.inet_pton(socket.AF_INET6, dst_host)
                req[-1] = 0x04  # ATYP IPv6
                req += packed6
            except OSError:
                del req[-1]
                host = dst_host.encode()
                req.append(0x03)  # ATYP domain
                req.append(len(host))
                req += host
        req += struct.pack("!H", dst_port)
        sock.sendall(bytes(req))

        ver, rep, _rsv, atyp = recv_exact(sock, 4)
        if ver != 0x05:
            raise SocksError("bad SOCKS5 version in reply: %d" % ver)
        if rep != 0x00:
            raise SocksError(
                "SOCKS5 CONNECT failed, reply code %d" % rep,
                stage="connect",
                code=rep,
            )
        if atyp == 0x01:
            recv_exact(sock, 4)
        elif atyp == 0x04:
            recv_exact(sock, 16)
        elif atyp == 0x03:
            n = recv_exact(sock, 1)[0]
            recv_exact(sock, n)
        else:
            raise SocksError("unexpected bound ATYP: %d" % atyp)
        recv_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


def _socks4_request(
    proxy_host: str,
    proxy_port: int,
    dst_ip: bytes,
    dst_port: int,
    hostname: Optional[bytes] = None,
) -> socket.socket:
    sock = _connect(proxy_host, proxy_port)
    try:
        req = bytearray([0x04, 0x01])
        req += struct.pack("!H", dst_port)
        req += dst_ip
        req += b"\x00"  # empty userid
        if hostname is not None:
            req += hostname + b"\x00"
        sock.sendall(bytes(req))
        reply = recv_exact(sock, 8)
        if reply[0] != 0x00:
            raise SocksError("bad SOCKS4 reply version: %d" % reply[0])
        if reply[1] != 0x5A:
            raise SocksError("SOCKS4 request rejected, code 0x%02X" % reply[1])
        return sock
    except Exception:
        sock.close()
        raise


def _socks5_greet(sock: socket.socket) -> None:
    """Perform the SOCKS5 no-auth method negotiation on an open socket."""
    sock.sendall(bytes([0x05, 0x01, 0x00]))
    ver, method = recv_exact(sock, 2)
    if ver != 0x05 or method != 0x00:
        raise SocksError(
            "SOCKS5 no-auth negotiation failed: ver=%d method=%d"
            % (ver, method)
        )


def _socks5_addr(host: str, port: int) -> bytes:
    """Encode a SOCKS5 ATYP+ADDR+PORT tuple for a request or UDP header."""
    try:
        body = bytes([0x01]) + socket.inet_pton(socket.AF_INET, host)
    except OSError:
        try:
            body = bytes([0x04]) + socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            h = host.encode()
            body = bytes([0x03, len(h)]) + h
    return body + struct.pack("!H", port)


def _socks5_read_reply(sock: socket.socket) -> Tuple[int, str, int]:
    """Read a SOCKS5 reply, returning (reply_code, bnd_host, bnd_port)."""
    ver, rep, _rsv, atyp = recv_exact(sock, 4)
    if ver != 0x05:
        raise SocksError("bad SOCKS5 version in reply: %d" % ver)
    if atyp == 0x01:
        host = socket.inet_ntop(socket.AF_INET, recv_exact(sock, 4))
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    elif atyp == 0x03:
        (n,) = struct.unpack("!B", recv_exact(sock, 1))
        host = recv_exact(sock, n).decode()
    else:
        raise SocksError("unexpected ATYP in SOCKS5 reply: %d" % atyp)
    (port,) = struct.unpack("!H", recv_exact(sock, 2))
    return rep, host, port


def socks4_connect(
    proxy_host: str, proxy_port: int, dst_ip: str, dst_port: int
) -> socket.socket:
    return _socks4_request(
        proxy_host, proxy_port, socket.inet_aton(dst_ip), dst_port
    )


def socks4a_connect(
    proxy_host: str, proxy_port: int, dst_host: str, dst_port: int
) -> socket.socket:
    # SOCKS4A sentinel: 0.0.0.x (x != 0) marks the hostname form.
    return _socks4_request(
        proxy_host, proxy_port, b"\x00\x00\x00\x01", dst_port, dst_host.encode()
    )


def http_connect(
    proxy_host: str, proxy_port: int, dst_host: str, dst_port: int
) -> socket.socket:
    sock = _connect(proxy_host, proxy_port)
    try:
        target = "%s:%d" % (dst_host, dst_port)
        request = (
            "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (target, target)
        ).encode()
        sock.sendall(request)
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = sock.recv(4096)
            if not chunk:
                raise SocksError("connection closed during CONNECT handshake")
            header += chunk
        status_line = header.split(b"\r\n", 1)[0]
        parts = status_line.split(b" ", 2)
        if len(parts) < 2 or parts[1] != b"200":
            raise SocksError("HTTP CONNECT failed: %r" % status_line)
        return sock
    except Exception:
        sock.close()
        raise


# --------------------------------------------------------------------------- #
# Local target servers (proxy destinations)
# --------------------------------------------------------------------------- #


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(IO_TIMEOUT)
        try:
            while True:
                data = self.request.recv(65536)
                if not data:
                    break
                self.request.sendall(data)
        except OSError:
            pass


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ThreadingTCPServer6(_ThreadingTCPServer):
    address_family = socket.AF_INET6


class _UDPEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(data, self.client_address)


class _ThreadingUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def _bind_echo_dual() -> Tuple[_ThreadingTCPServer, _ThreadingTCPServer, int]:
    """Bind IPv4 and IPv6 echo servers sharing one loopback port.

    A hostname target is resolved by the daemon itself with AF_UNSPEC, so the
    test cannot know which family the host returns for a name like "localhost".
    Serving the same port on both loopback addresses makes that choice
    irrelevant instead of depending on the host's resolver ordering.

    An ephemeral port is picked on ::1 and then claimed on 127.0.0.1; the two
    addresses are distinct, so only an unrelated listener already holding the
    IPv4 port can collide, which the retry resolves.
    """
    for _ in range(16):
        srv6 = _ThreadingTCPServer6((HOST6, 0), _EchoHandler)
        port = srv6.server_address[1]
        try:
            srv4 = _ThreadingTCPServer((HOST, port), _EchoHandler)
        except OSError:
            srv6.server_close()
            continue
        return srv4, srv6, port
    raise RuntimeError("found no loopback port free on both IPv4 and IPv6")


class Targets:
    """Loopback echo servers used as proxy destinations."""

    def __init__(self) -> None:
        self.echo = _ThreadingTCPServer((HOST, 0), _EchoHandler)
        self.echo6 = _ThreadingTCPServer6((HOST6, 0), _EchoHandler)
        self.udp_echo = _ThreadingUDPServer((HOST, 0), _UDPEchoHandler)
        self.echo_any, self.echo_any6, self.echo_any_port = _bind_echo_dual()
        self.echo_port = self.echo.server_address[1]
        self.echo6_port = self.echo6.server_address[1]
        self.udp_echo_port = self.udp_echo.server_address[1]
        self._threads = [
            threading.Thread(target=self.echo.serve_forever, daemon=True),
            threading.Thread(target=self.echo6.serve_forever, daemon=True),
            threading.Thread(target=self.udp_echo.serve_forever, daemon=True),
            threading.Thread(target=self.echo_any.serve_forever, daemon=True),
            threading.Thread(target=self.echo_any6.serve_forever, daemon=True),
        ]

    def start(self) -> "Targets":
        for t in self._threads:
            t.start()
        return self

    def stop(self) -> None:
        for srv in (
            self.echo,
            self.echo6,
            self.udp_echo,
            self.echo_any,
            self.echo_any6,
        ):
            try:
                srv.shutdown()
                srv.server_close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# REST API client
# --------------------------------------------------------------------------- #


def api_request_full(
    api_port: int,
    method: str,
    path: str,
    body: Optional[bytes] = None,
    headers: Optional[dict] = None,
) -> Tuple[int, dict, bytes]:
    """Drive one API request and return (status, headers, body).

    Header names are lowercased so a lookup does not depend on the daemon's
    spelling. The body is returned exactly as received -- http.client does not
    decode content, so a deflated response stays compressed and the test can
    assert on the negotiated encoding.
    """
    conn = http.client.HTTPConnection(HOST, api_port, timeout=IO_TIMEOUT)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        received = {name.lower(): value for name, value in resp.getheaders()}
        return resp.status, received, resp.read()
    finally:
        conn.close()


def api_request(
    api_port: int,
    method: str,
    path: str,
    body: Optional[bytes] = None,
    headers: Optional[dict] = None,
) -> Tuple[int, bytes]:
    status, _, data = api_request_full(api_port, method, path, body, headers)
    return status, data


# --------------------------------------------------------------------------- #
# neosocksd process harness
# --------------------------------------------------------------------------- #


class Daemon:
    """Context manager that runs a neosocksd instance and tears it down."""

    def __init__(
        self,
        binary: Path,
        extra_args: List[str],
        *,
        api_port: Optional[int] = None,
        listen_port: Optional[int] = None,
        loglevel: int = 4,
        timeout: float = 30.0,
        name: str = "neosocksd",
    ) -> None:
        self.binary = binary
        self.extra_args = extra_args
        self.api_port = api_port
        self.listen_port = listen_port
        self.loglevel = loglevel
        self.timeout = timeout
        self.name = name
        self.proc: Optional[subprocess.Popen] = None
        self._stderr = tempfile.TemporaryFile(mode="w+b")

    def _argv(self) -> List[str]:
        argv = [str(self.binary)]
        argv += self.extra_args
        if self.api_port is not None:
            argv += ["--api", "%s:%d" % (HOST, self.api_port)]
        argv += ["-t", "%.1f" % self.timeout, "--loglevel", str(self.loglevel)]
        return argv

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + READY_TIMEOUT
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    "%s exited during startup (code %d)\n%s"
                    % (self.name, self.proc.returncode, self.stderr_text())
                )
            try:
                if self.api_port is not None:
                    status, _ = api_request(self.api_port, "GET", "/healthy")
                    if status == 200:
                        return
                elif self.listen_port is not None:
                    with socket.create_connection(
                        (HOST, self.listen_port), timeout=0.5
                    ):
                        return
                else:
                    return
            except OSError:
                pass
            time.sleep(0.05)
        raise RuntimeError(
            "%s did not become ready within %.1fs\n%s"
            % (self.name, READY_TIMEOUT, self.stderr_text())
        )

    def stderr_all(self) -> str:
        """Everything the daemon has logged so far, untruncated. Assertions on
        log content need this; stderr_text() below is for failure reports."""
        self._stderr.seek(0)
        return self._stderr.read().decode(errors="replace")

    def stderr_text(self) -> str:
        # keep the report compact: only the tail matters for diagnosis
        lines = self.stderr_all().splitlines()
        return "\n".join(lines[-25:])

    def __enter__(self) -> "Daemon":
        self.proc = subprocess.Popen(
            self._argv(),
            cwd=str(ROOT),
            stdout=subprocess.DEVNULL,
            stderr=self._stderr,
        )
        try:
            self._wait_ready()
        except Exception:
            # tear down best-effort; the startup error is what matters
            self._terminate(check=False)
            raise
        return self

    def _terminate(self, check: bool = True) -> None:
        """Stop the daemon. When check is True (a clean with-block), a shutdown
        that was not graceful raises RuntimeError so the case fails: the daemon
        having already exited on its own (a mid-test crash/abort), a nonzero or
        signal exit after SIGTERM (a broken shutdown path), or a hang that had
        to be SIGKILLed. When check is False (an error is already propagating,
        or startup failed) it only tears down, so it never masks that error."""
        if self.proc is None:
            return
        if self.proc.poll() is not None:
            rc = self.proc.returncode
            if check:
                raise RuntimeError(
                    "%s exited unexpectedly during the test (code %d)\n%s"
                    % (self.name, rc, self.stderr_text())
                )
            return
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=SHUTDOWN_TIMEOUT)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=SHUTDOWN_TIMEOUT)
            if check:
                raise RuntimeError(
                    "%s did not exit within %.1fs of SIGTERM; had to SIGKILL\n%s"
                    % (self.name, SHUTDOWN_TIMEOUT, self.stderr_text())
                )
            return
        rc = self.proc.returncode
        if check and rc != 0:
            # a graceful SIGTERM handler exits 0; nonzero or a signal kill
            # (rc < 0) means the shutdown path crashed or aborted
            raise RuntimeError(
                "%s exited abnormally after SIGTERM (code %d)\n%s"
                % (self.name, rc, self.stderr_text())
            )

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        try:
            self._terminate(check=exc_type is None)
        finally:
            self._stderr.close()


# --------------------------------------------------------------------------- #
# Ruleset fixtures
# --------------------------------------------------------------------------- #


def write_ruleset(tmpdir: Path, name: str, body: str) -> Path:
    path = tmpdir / name
    path.write_text(body)
    return path


def direct_ruleset() -> str:
    """A ruleset that connects everything directly (passthrough)."""
    return (
        "local ruleset = {}\n"
        "function ruleset.resolve(addr) return addr end\n"
        "function ruleset.route(addr) return addr end\n"
        "function ruleset.route6(addr) return addr end\n"
        "return ruleset\n"
    )


def redirect_ruleset(fake_host: str, echo_addr: str) -> str:
    """Redirect a fake hostname to the echo target; reject every other host.

    Unknown hostnames are rejected (return nil) rather than passed through, so a
    stale route after a hot reload fails hermetically instead of triggering a
    real resolver lookup (which the suite promises never to do)."""
    return (
        "local ECHO = %r\n"
        "local FAKE = %r\n"
        "local ruleset = {}\n"
        "function ruleset.resolve(addr)\n"
        "    if addr == FAKE then return ECHO end\n"
        "    return nil\n"
        "end\n"
        "function ruleset.route(addr) return addr end\n"
        "function ruleset.route6(addr) return addr end\n"
        "return ruleset\n"
    ) % (echo_addr, fake_host)


def credential_ruleset(allowed_user: str) -> str:
    """Route directly only when the SOCKS5 username matches; else reject.

    The ruleset entry points receive the client's credentials as
    (addr, username, password), so this pins that they actually reach Lua."""
    return (
        "local ALLOWED = %r\n"
        "local ruleset = {}\n"
        "local function check(addr, username)\n"
        "    if username == ALLOWED then return addr end\n"
        "    return nil\n"
        "end\n"
        "function ruleset.route(addr, username, password)\n"
        "    return check(addr, username)\n"
        "end\n"
        "function ruleset.route6(addr, username, password)\n"
        "    return check(addr, username)\n"
        "end\n"
        "function ruleset.resolve(addr, username, password)\n"
        "    return check(addr, username)\n"
        "end\n"
        "return ruleset\n"
    ) % (allowed_user,)


# --------------------------------------------------------------------------- #
# Test registry
# --------------------------------------------------------------------------- #


@dataclass
class Context:
    binary: Path
    tmpdir: Path
    loglevel: int
    targets: Targets

    @property
    def echo_port(self) -> int:
        return self.targets.echo_port

    @property
    def echo6_port(self) -> int:
        return self.targets.echo6_port

    @property
    def echo_any_port(self) -> int:
        """Echo port served on both loopback families, for hostname targets."""
        return self.targets.echo_any_port

    @property
    def udp_echo_port(self) -> int:
        return self.targets.udp_echo_port

    @property
    def echo_addr(self) -> str:
        return "%s:%d" % (HOST, self.targets.echo_port)


class SkipTest(Exception):
    pass


@dataclass
class Case:
    name: str
    fn: Callable[[Context], None]


@dataclass
class Result:
    name: str
    status: str  # PASS / FAIL / SKIP
    detail: str = ""
    duration: float = 0.0


CASES: List[Case] = []


def test(name: str) -> Callable[[Callable[[Context], None]], Callable]:
    def deco(fn: Callable[[Context], None]) -> Callable:
        CASES.append(Case(name, fn))
        return fn

    return deco


# --------------------------------------------------------------------------- #
# A. Process / CLI sanity
# --------------------------------------------------------------------------- #


@test("cli/help")
def t_cli_help(ctx: Context) -> None:
    proc = subprocess.run(
        [str(ctx.binary), "--help"], capture_output=True, timeout=10
    )
    # `--help` prints usage to stderr and exits non-zero by design
    # (mirrors the CMake `neosocksd_help` test marked WILL_FAIL).
    assert proc.returncode != 0, "expected non-zero exit, got 0"
    text = (proc.stdout + proc.stderr).decode(errors="replace").lower()
    assert "usage" in text, "help output missing 'usage'"


@test("cli/unknown-flag")
def t_cli_unknown_flag(ctx: Context) -> None:
    proc = subprocess.run(
        [str(ctx.binary), "--definitely-not-a-flag"],
        capture_output=True,
        timeout=10,
    )
    assert proc.returncode != 0, "expected non-zero exit for unknown flag"


@test("cli/missing-listen")
def t_cli_missing_listen(ctx: Context) -> None:
    proc = subprocess.run(
        [str(ctx.binary), "--loglevel", "0"], capture_output=True, timeout=10
    )
    assert proc.returncode != 0, "expected non-zero exit when no listener given"


# The startup notice cases below pin loglevel 4 rather than taking ctx.loglevel:
# the notice is logged at NOTICE, so a run with --loglevel 3 would silence it and
# the assertions would pass vacuously.
PROXY_CHAIN_NOTICE = "extends the `-x' proxy chain"


def proxy_chain_notices(log: str) -> List[str]:
    return [line for line in log.splitlines() if "proxy chain" in line]


@test("cli/ruleset-proxy-notice")
def t_cli_ruleset_proxy_notice(ctx: Context) -> None:
    """A ruleset extends the -x chain rather than replacing it, and the startup
    notice must say so exactly once. It once claimed the chain would be
    "overwritten by ruleset", and main() validated the config twice on the -r
    path, so it was also logged twice."""
    listen = free_port()
    ruleset = write_ruleset(ctx.tmpdir, "direct.lua", direct_ruleset())
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen),
         "-x", "socks5://%s:%d" % (HOST, free_port()),
         "-r", str(ruleset)],
        listen_port=listen,
        loglevel=4,
    ) as d:
        log = d.stderr_all()
    hits = proxy_chain_notices(log)
    assert len(hits) == 1, (
        "expected exactly 1 proxy-chain notice, got %d:\n%s" % (len(hits), log)
    )
    assert "overwritten" not in log, (
        "startup log still claims the proxy is overwritten:\n%s" % log
    )
    assert PROXY_CHAIN_NOTICE in hits[0], "unexpected notice text: %s" % hits[0]


@test("cli/no-ruleset-no-proxy-notice")
def t_cli_no_ruleset_no_proxy_notice(ctx: Context) -> None:
    """-x without a ruleset has nothing to extend it, so nothing is said."""
    listen = free_port()
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen),
         "-x", "socks5://%s:%d" % (HOST, free_port())],
        listen_port=listen,
        loglevel=4,
    ) as d:
        log = d.stderr_all()
    assert not proxy_chain_notices(log), (
        "proxy-chain notice logged without a ruleset:\n%s" % log
    )


@test("cli/startup-shutdown")
def t_cli_startup_shutdown(ctx: Context) -> None:
    port = free_port()
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, port)],
        listen_port=port,
        loglevel=ctx.loglevel,
    ) as d:
        # the daemon must still be running here; graceful SIGTERM shutdown is
        # driven and now verified (exit status 0) by Daemon.__exit__ on the way
        # out of this block.
        assert d.proc.poll() is None, "daemon should still be running"


# --------------------------------------------------------------------------- #
# B. SOCKS proxy (no ruleset, direct connect)
# --------------------------------------------------------------------------- #


def _socks_daemon(ctx: Context) -> Tuple[Daemon, int, int]:
    listen = free_port()
    api = free_port()
    d = Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen)],
        api_port=api,
        loglevel=ctx.loglevel,
    )
    return d, listen, api


@test("socks5/ipv4")
def t_socks5_ipv4(ctx: Context) -> None:
    d, listen, _ = _socks_daemon(ctx)
    with d:
        sock = socks5_connect(HOST, listen, HOST, ctx.echo_port)
        with sock:
            echo_roundtrip(sock)


@test("socks5/domain")
def t_socks5_domain(ctx: Context) -> None:
    """Dial a hostname target (SOCKS5 ATYP 0x03) via the daemon's resolver.

    The target port is served on both loopback families, so the case does not
    care which one the host resolves "localhost" to first.
    """
    d, listen, _ = _socks_daemon(ctx)
    with d:
        sock = socks5_connect(HOST, listen, "localhost", ctx.echo_any_port)
        with sock:
            echo_roundtrip(sock)


@test("socks5/ipv6")
def t_socks5_ipv6(ctx: Context) -> None:
    """Dial an IPv6 literal target (SOCKS5 ATYP 0x04) through ruleset.route6()."""
    listen = free_port()
    ruleset = write_ruleset(ctx.tmpdir, "direct.lua", direct_ruleset())
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen), "-r", str(ruleset)],
        listen_port=listen,
        loglevel=ctx.loglevel,
    ):
        with socks5_connect(HOST, listen, HOST6, ctx.echo6_port) as sock:
            echo_roundtrip(sock)


@test("socks5/udp-associate")
def t_socks5_udp(ctx: Context) -> None:
    """SOCKS5 UDP ASSOCIATE relays a datagram to a UDP echo target and back."""
    listen = free_port()
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen), "--enable-socks5-udp"],
        listen_port=listen,
        loglevel=ctx.loglevel,
    ):
        ctrl = _connect(HOST, listen)
        with ctrl:
            _socks5_greet(ctrl)
            # UDP ASSOCIATE (CMD 0x03); the client's own addr is unknown yet
            ctrl.sendall(bytes([0x05, 0x03, 0x00]) + _socks5_addr("0.0.0.0", 0))
            rep, relay_host, relay_port = _socks5_read_reply(ctrl)
            if rep != 0x00:
                raise SocksError(
                    "UDP ASSOCIATE failed, reply code %d" % rep,
                    stage="connect", code=rep,
                )
            if relay_host in ("0.0.0.0", "::"):
                relay_host = HOST
            usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            usock.settimeout(IO_TIMEOUT)
            with usock:
                payload = b"udp-relay-smoke"
                header = bytes([0x00, 0x00, 0x00]) + _socks5_addr(
                    HOST, ctx.udp_echo_port
                )
                usock.sendto(header + payload, (relay_host, relay_port))
                data, _ = usock.recvfrom(4096)
            # the reply is SOCKS5-UDP-header-prefixed; the echoed payload trails
            assert data.endswith(payload), (
                "UDP relay returned %r, expected trailing %r" % (data, payload)
            )


@test("socks5/bind")
def t_socks5_bind(ctx: Context) -> None:
    """SOCKS5 BIND opens a listener, a peer connects, and data relays both ways."""
    listen = free_port()
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen), "--enable-socks5-bind"],
        listen_port=listen,
        loglevel=ctx.loglevel,
    ):
        ctrl = _connect(HOST, listen)
        with ctrl:
            _socks5_greet(ctrl)
            # BIND (CMD 0x02); the target address is the advisory expected peer
            ctrl.sendall(bytes([0x05, 0x02, 0x00]) + _socks5_addr(HOST, 0))
            rep, bnd_host, bnd_port = _socks5_read_reply(ctrl)
            if rep != 0x00:
                raise SocksError(
                    "BIND first reply failed, code %d" % rep,
                    stage="connect", code=rep,
                )
            if bnd_host in ("0.0.0.0", "::"):
                bnd_host = HOST
            # a peer connects to the bound port; the daemon sends its second reply
            peer = socket.create_connection(
                (bnd_host, bnd_port), timeout=IO_TIMEOUT
            )
            peer.settimeout(IO_TIMEOUT)
            with peer:
                rep2, _, _ = _socks5_read_reply(ctrl)
                assert rep2 == 0x00, "BIND second reply failed, code %d" % rep2
                # data relays both directions between client and peer
                msg = b"bind-relay-smoke"
                ctrl.sendall(msg)
                assert recv_exact(peer, len(msg)) == msg, "BIND client->peer"
                peer.sendall(msg[::-1])
                assert recv_exact(ctrl, len(msg)) == msg[::-1], "BIND peer->client"


@test("socks5/refused")
def t_socks5_refused(ctx: Context) -> None:
    d, listen, _ = _socks_daemon(ctx)
    dead = free_port()  # nothing listening here
    with d:
        try:
            socks5_connect(HOST, listen, HOST, dead).close()
        except SocksError as e:
            assert e.stage == "connect", (
                "expected a CONNECT-stage failure, got stage=%r" % e.stage
            )
            return
        raise AssertionError("expected SOCKS5 failure for closed target port")


@test("socks4/ipv4")
def t_socks4_ipv4(ctx: Context) -> None:
    d, listen, _ = _socks_daemon(ctx)
    with d:
        sock = socks4_connect(HOST, listen, HOST, ctx.echo_port)
        with sock:
            echo_roundtrip(sock)


@test("socks4a/hostname")
def t_socks4a_hostname(ctx: Context) -> None:
    """Dial a hostname target (SOCKS4A) via the daemon's resolver.

    Uses the dual-family echo port for the same reason as socks5/domain.
    """
    d, listen, _ = _socks_daemon(ctx)
    with d:
        sock = socks4a_connect(HOST, listen, "localhost", ctx.echo_any_port)
        with sock:
            echo_roundtrip(sock)


# --------------------------------------------------------------------------- #
# C. SOCKS5 authentication
# --------------------------------------------------------------------------- #


@test("socks5/auth-required-rejects-noauth")
def t_auth_rejects_noauth(ctx: Context) -> None:
    listen = free_port()
    ruleset = write_ruleset(ctx.tmpdir, "direct.lua", direct_ruleset())
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen), "--auth-required",
         "-r", str(ruleset)],
        listen_port=listen,
        loglevel=ctx.loglevel,
    ):
        try:
            socks5_connect(
                HOST, listen, HOST, ctx.echo_port, offer_noauth=True
            ).close()
        except SocksError as e:
            assert e.stage == "method" and e.code == 0xFF, (
                "expected a method-selection rejection (0xFF), got "
                "stage=%r code=%r" % (e.stage, e.code)
            )
            return
        raise AssertionError("auth-required server accepted a no-auth client")


@test("socks5/auth-required-accepts-userpass")
def t_auth_accepts_userpass(ctx: Context) -> None:
    listen = free_port()
    ruleset = write_ruleset(ctx.tmpdir, "direct.lua", direct_ruleset())
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen), "--auth-required",
         "-r", str(ruleset)],
        listen_port=listen,
        loglevel=ctx.loglevel,
    ):
        sock = socks5_connect(
            HOST,
            listen,
            HOST,
            ctx.echo_port,
            user="smoke",
            password="secret",
            offer_noauth=False,
        )
        with sock:
            echo_roundtrip(sock)


@test("socks5/ruleset-credentials")
def t_ruleset_credentials(ctx: Context) -> None:
    """The SOCKS5 username must reach the ruleset: a matching user routes to
    echo, a wrong user is rejected at the CONNECT stage."""
    listen = free_port()
    ruleset = write_ruleset(
        ctx.tmpdir, "cred.lua", credential_ruleset("smoke")
    )
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen), "--auth-required",
         "-r", str(ruleset)],
        listen_port=listen,
        loglevel=ctx.loglevel,
    ):
        # the allowed username reaches the ruleset, which routes to echo
        with socks5_connect(
            HOST, listen, HOST, ctx.echo_port,
            user="smoke", password="secret", offer_noauth=False,
        ) as sock:
            echo_roundtrip(sock)
        # a different username is rejected by the ruleset (CONNECT stage),
        # proving the credential was actually inspected
        try:
            socks5_connect(
                HOST, listen, HOST, ctx.echo_port,
                user="intruder", password="secret", offer_noauth=False,
            ).close()
        except SocksError as e:
            assert e.stage == "connect", (
                "wrong credentials must be rejected by the ruleset at the "
                "CONNECT stage, got stage=%r" % e.stage
            )
        else:
            raise AssertionError("ruleset accepted a wrong-username client")


# --------------------------------------------------------------------------- #
# D. HTTP proxy (CONNECT)
# --------------------------------------------------------------------------- #


def _http_daemon(ctx: Context, extra: Tuple[str, ...] = ()) -> Tuple[Daemon, int]:
    """Start a daemon with a SOCKS listener and an HTTP proxy port."""
    listen = free_port()
    http_port = free_port()
    args = [
        "-l", "%s:%d" % (HOST, listen),
        "--http", "%s:%d" % (HOST, http_port),
    ]
    args += list(extra)
    d = Daemon(
        ctx.binary, args, listen_port=http_port, loglevel=ctx.loglevel
    )
    return d, http_port


@test("http/connect")
def t_http_connect(ctx: Context) -> None:
    d, http_port = _http_daemon(ctx)
    with d:
        sock = http_connect(HOST, http_port, HOST, ctx.echo_port)
        with sock:
            echo_roundtrip(sock)


# --------------------------------------------------------------------------- #
# E. TCP port forwarding
# --------------------------------------------------------------------------- #


@test("forward/tcp")
def t_forward_tcp(ctx: Context) -> None:
    listen = free_port()
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen), "-f", ctx.echo_addr],
        listen_port=listen,
        loglevel=ctx.loglevel,
    ):
        with _connect(HOST, listen) as sock:
            echo_roundtrip(sock)


# --------------------------------------------------------------------------- #
# F. Proxy chaining (-x)
# --------------------------------------------------------------------------- #


@test("chain/socks5-over-socks5")
def t_chain(ctx: Context) -> None:
    upstream = free_port()
    front = free_port()
    up = Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, upstream)],
        listen_port=upstream,
        loglevel=ctx.loglevel,
        name="upstream",
    )
    with up:
        fr = Daemon(
            ctx.binary,
            [
                "-l",
                "%s:%d" % (HOST, front),
                "-x",
                "socks5://%s:%d" % (HOST, upstream),
            ],
            listen_port=front,
            loglevel=ctx.loglevel,
            name="front",
        )
        with fr:
            sock = socks5_connect(HOST, front, HOST, ctx.echo_port)
            with sock:
                echo_roundtrip(sock)


@test("chain/socks5-over-http")
def t_chain_over_http(ctx: Context) -> None:
    """Chain a client's SOCKS5 request out through an http:// upstream dialer."""
    up_socks = free_port()
    up_http = free_port()
    front = free_port()
    up = Daemon(
        ctx.binary,
        [
            "-l", "%s:%d" % (HOST, up_socks),
            "--http", "%s:%d" % (HOST, up_http),
        ],
        listen_port=up_http,
        loglevel=ctx.loglevel,
        name="upstream",
    )
    with up:
        fr = Daemon(
            ctx.binary,
            [
                "-l", "%s:%d" % (HOST, front),
                "-x", "http://%s:%d" % (HOST, up_http),
            ],
            listen_port=front,
            loglevel=ctx.loglevel,
            name="front",
        )
        with fr:
            sock = socks5_connect(HOST, front, HOST, ctx.echo_port)
            with sock:
                echo_roundtrip(sock)


@test("chain/socks5-over-socks4a")
def t_chain_over_socks4a(ctx: Context) -> None:
    """Chain a client's SOCKS5 request out through a socks4a:// upstream."""
    upstream = free_port()
    front = free_port()
    up = Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, upstream)],
        listen_port=upstream,
        loglevel=ctx.loglevel,
        name="upstream",
    )
    with up:
        fr = Daemon(
            ctx.binary,
            [
                "-l", "%s:%d" % (HOST, front),
                "-x", "socks4a://%s:%d" % (HOST, upstream),
            ],
            listen_port=front,
            loglevel=ctx.loglevel,
            name="front",
        )
        with fr:
            sock = socks5_connect(HOST, front, HOST, ctx.echo_port)
            with sock:
                echo_roundtrip(sock)


@test("forward/pipe")
def t_pipe(ctx: Context) -> None:
    """The splice/pipe transfer path (--pipe) must still relay data."""
    probe = subprocess.run(
        [str(ctx.binary), "--pipe", "-l", "%s:0" % HOST, "--dump-config"],
        capture_output=True,
        timeout=10,
    )
    if probe.returncode != 0:
        raise SkipTest("binary built without --pipe (WITH_SPLICE) support")
    listen = free_port()
    d = Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen), "--pipe"],
        listen_port=listen,
        loglevel=ctx.loglevel,
    )
    with d:
        sock = socks5_connect(HOST, listen, HOST, ctx.echo_port)
        with sock:
            echo_roundtrip(sock)


# --------------------------------------------------------------------------- #
# G. Ruleset routing
# --------------------------------------------------------------------------- #


@test("ruleset/redirect")
def t_ruleset_redirect(ctx: Context) -> None:
    listen = free_port()
    api = free_port()
    ruleset = write_ruleset(
        ctx.tmpdir, "redirect.lua", redirect_ruleset(
            "smoke.test:80", ctx.echo_addr)
    )
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen), "-r", str(ruleset)],
        api_port=api,
        loglevel=ctx.loglevel,
    ):
        # SOCKS4A hostname -> resolve() redirect to the echo target
        sock = socks4a_connect(HOST, listen, "smoke.test", 80)
        with sock:
            echo_roundtrip(sock)


@test("ruleset/reject")
def t_ruleset_reject(ctx: Context) -> None:
    listen = free_port()
    api = free_port()
    ruleset = write_ruleset(
        ctx.tmpdir, "redirect.lua", redirect_ruleset(
            "smoke.test:80", ctx.echo_addr)
    )
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen), "-r", str(ruleset)],
        api_port=api,
        loglevel=ctx.loglevel,
    ):
        try:
            socks5_connect(HOST, listen, "reject.test", 80).close()
        except SocksError as e:
            assert e.stage == "connect", (
                "a ruleset reject must surface as a CONNECT-stage failure, "
                "got stage=%r code=%r" % (e.stage, e.code)
            )
            return
        raise AssertionError("ruleset reject was not honored")


# --------------------------------------------------------------------------- #
# H. REST API
# --------------------------------------------------------------------------- #


@test("api/healthy")
def t_api_healthy(ctx: Context) -> None:
    d, _, api = _socks_daemon(ctx)
    with d:
        status, _ = api_request(api, "GET", "/healthy")
        assert status == 200, "healthy returned %d" % status


@test("api/stats")
def t_api_stats(ctx: Context) -> None:
    d, _, api = _socks_daemon(ctx)
    with d:
        status, body = api_request(api, "GET", "/stats")
        assert status == 200, "GET /stats returned %d" % status
        assert b"neosocksd" in body, "stats banner missing"
        assert b"Uptime" in body, "stats body missing Uptime"

        status, nb = api_request(api, "GET", "/stats?nobanner=1")
        assert status == 200, "GET /stats?nobanner=1 returned %d" % status
        assert b"neosocksd" not in nb, "nobanner=1 did not omit the banner"

        status, _ = api_request(api, "POST", "/stats")
        assert status == 200, "POST /stats returned %d" % status


@test("api/metrics")
def t_api_metrics(ctx: Context) -> None:
    d, _, api = _socks_daemon(ctx)
    with d:
        status, body = api_request(api, "GET", "/metrics")
        assert status == 200, "GET /metrics returned %d" % status
        assert b"neosocksd_" in body, "metrics missing neosocksd_ series"


@test("api/invoke")
def t_api_invoke(ctx: Context) -> None:
    listen = free_port()
    api = free_port()
    ruleset = write_ruleset(ctx.tmpdir, "direct.lua", direct_ruleset())
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen), "-r", str(ruleset)],
        api_port=api,
        loglevel=ctx.loglevel,
    ):
        status, _ = api_request(
            api, "POST", "/ruleset/invoke", b"_G.smoke_ok = true")
        assert status == 200, "invoke (set) returned %d" % status
        # read back: assert fails -> HTTP 500 if state did not persist
        status, body = api_request(
            api, "POST", "/ruleset/invoke", b"assert(_G.smoke_ok, 'state lost')"
        )
        assert status == 200, "invoke (read-back) returned %d: %r" % (status, body)


def _lua_longstring(data: bytes) -> str:
    """Quote bytes as a Lua long-bracket string literal.

    The bracket level grows until it cannot terminate early, so any payload
    embeds verbatim -- no escaping, and no dependence on how the daemon spells
    the marshalled result.
    """
    text = data.decode()
    level = ""
    while "]%s]" % level in text:
        level += "="
    return "[%s[%s]%s]" % (level, text, level)


def _check_rpcall_result(api_port: int, marshalled: bytes, expr: str) -> None:
    """Load an rpcall response body back on the daemon and assert `expr`.

    The body is a marshalled `return <ok>, <values>` chunk, so loading it is
    what the caller's `await.invoke` does with it. `expr` sees `ok` (the rpc
    status flag) plus the first two returned values as `a` and `b`. Checking
    the chunk by running it pins the contract without pinning marshal's exact
    spelling.
    """
    code = (
        "local ok, a, b = assert(load(%s))()\n"
        "assert(%s, 'rpcall result mismatch')\n"
    ) % (_lua_longstring(marshalled), expr)
    status, body = api_request(api_port, "POST", "/ruleset/invoke", code.encode())
    assert status == 200, "rpcall result check returned %d: %r" % (status, body)


@test("api/rpcall")
def t_api_rpcall(ctx: Context) -> None:
    """/ruleset/rpcall is the only endpoint with a content-type contract on both
    directions, the only one that negotiates a deflated response, and the only
    one whose body is a marshalled Lua chunk. Drive all three."""
    listen = free_port()
    api = free_port()
    ruleset = write_ruleset(ctx.tmpdir, "direct.lua", direct_ruleset())
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen), "-r", str(ruleset)],
        api_port=api,
        loglevel=ctx.loglevel,
    ):
        # a well-formed call answers with the RPC content type and a body that
        # loads back into the values the chunk returned
        status, headers, body = api_request_full(
            api,
            "POST",
            "/ruleset/rpcall",
            b'return 2 + 3, "smoke"',
            {"Content-Type": RPCALL_MIME},
        )
        assert status == 200, "rpcall returned %d: %r" % (status, body)
        assert headers.get("content-type") == RPCALL_MIME, (
            "rpcall response content-type is %r" % headers.get("content-type")
        )
        assert "content-encoding" not in headers, (
            "a client that did not accept deflate got %r"
            % headers.get("content-encoding")
        )
        _check_rpcall_result(api, body, 'ok == true and a == 5 and b == "smoke"')

        # the request content type is enforced: no type, the wrong type, and a
        # future protocol version are all rejected before the chunk runs
        for ctype in (None, "text/plain", "application/x-neosocksd-rpc; version=99"):
            sent = {} if ctype is None else {"Content-Type": ctype}
            status, body = api_request(
                api, "POST", "/ruleset/rpcall", b"return 1", sent
            )
            assert status == 400, (
                "rpcall with content-type %r returned %d, want 400: %r"
                % (ctype, status, body)
            )

        # a chunk that raises is an rpc failure, not a marshalled false result
        status, body = api_request(
            api,
            "POST",
            "/ruleset/rpcall",
            b'error("smoke boom")',
            {"Content-Type": RPCALL_MIME},
        )
        assert status == 500, "a raising rpc chunk returned %d: %r" % (status, body)

        # a result at or over the threshold is deflated when the client accepts
        # it, and still loads back to the same value once inflated
        status, headers, body = api_request_full(
            api,
            "POST",
            "/ruleset/rpcall",
            ('return string.rep("x", %d)' % RPCALL_COMPRESS_THRESHOLD).encode(),
            {"Content-Type": RPCALL_MIME, "Accept-Encoding": "deflate"},
        )
        assert status == 200, "deflate rpcall returned %d: %r" % (status, body)
        assert headers.get("content-encoding") == "deflate", (
            "a large result was not deflated: %r" % headers.get("content-encoding")
        )
        inflated = zlib.decompress(body)
        assert len(body) < len(inflated), "deflate did not shrink the payload"
        _check_rpcall_result(
            api, inflated, 'ok == true and a == string.rep("x", %d)'
            % RPCALL_COMPRESS_THRESHOLD
        )

        # ...but a result below the threshold stays plain even so
        status, headers, body = api_request_full(
            api,
            "POST",
            "/ruleset/rpcall",
            b'return "tiny"',
            {"Content-Type": RPCALL_MIME, "Accept-Encoding": "deflate"},
        )
        assert status == 200, "small rpcall returned %d: %r" % (status, body)
        assert "content-encoding" not in headers, (
            "a result below the %d-byte threshold was deflated"
            % RPCALL_COMPRESS_THRESHOLD
        )
        _check_rpcall_result(api, body, 'ok == true and a == "tiny"')


def _rpc_caller_code(remote_api: int) -> bytes:
    """An invoke chunk that RPC-calls another daemon and records the outcome.

    `neosocksd.async` is the coroutine runner `await.invoke` needs; the shipped
    `libruleset.lua` wraps it as `_G.async`, but the suite's fixtures are
    standalone rulesets, so drive the primitive directly. The outcome lands in a
    global because the invoke request returns before the call completes.
    """
    code = (
        "_G.smoke_rpc = nil\n"
        "neosocksd.async(function(ok, value)\n"
        "    if not ok then\n"
        "        _G.smoke_rpc = 'async error: ' .. tostring(value)\n"
        "        return\n"
        "    end\n"
        "    _G.smoke_rpc = value\n"
        "end, function()\n"
        "    local ok, result = await.invoke([[return \"pong\", 42]], %r)\n"
        "    if not ok then\n"
        "        return 'invoke failed: ' .. tostring(result)\n"
        "    end\n"
        "    local rok, a, b = result()\n"
        "    if not rok then\n"
        "        return 'remote error: ' .. tostring(a)\n"
        "    end\n"
        "    return tostring(a) .. '/' .. tostring(b)\n"
        "end)\n"
    ) % ("%s:%d" % (HOST, remote_api),)
    return code.encode()


@test("api/rpcall-invoke")
def t_api_rpcall_invoke(ctx: Context) -> None:
    """await.invoke() runs src/api_client.c against a second daemon's
    /ruleset/rpcall, so request building, response decode and the result
    hand-back cross a real socket instead of a mocked collaborator."""
    ruleset = write_ruleset(ctx.tmpdir, "direct.lua", direct_ruleset())
    remote_listen = free_port()
    remote_api = free_port()
    remote = Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, remote_listen), "-r", str(ruleset)],
        api_port=remote_api,
        loglevel=ctx.loglevel,
        name="rpc-remote",
    )
    with remote:
        listen = free_port()
        api = free_port()
        with Daemon(
            ctx.binary,
            ["-l", "%s:%d" % (HOST, listen), "-r", str(ruleset)],
            api_port=api,
            loglevel=ctx.loglevel,
            name="rpc-caller",
        ):
            status, body = api_request(
                api, "POST", "/ruleset/invoke", _rpc_caller_code(remote_api)
            )
            assert status == 200, "starting the rpc routine returned %d: %r" % (
                status,
                body,
            )
            # the routine outlives its invoke request: poll until it records an
            # outcome, then assert on it
            deadline = time.monotonic() + IO_TIMEOUT
            while True:
                status, body = api_request(
                    api,
                    "POST",
                    "/ruleset/invoke",
                    b"assert(_G.smoke_rpc ~= nil, 'pending')",
                )
                if status == 200:
                    break
                if time.monotonic() >= deadline:
                    raise AssertionError(
                        "await.invoke did not complete within %.1fs: %r"
                        % (IO_TIMEOUT, body)
                    )
                time.sleep(0.05)
            status, body = api_request(
                api,
                "POST",
                "/ruleset/invoke",
                b"assert(_G.smoke_rpc == 'pong/42', _G.smoke_rpc)",
            )
            assert status == 200, "await.invoke result: %r" % body

            # the call went out through api_client.c, so its counters moved
            status, stats = api_request(api, "POST", "/stats")
            assert status == 200, "POST /stats returned %d" % status
            m = re.search(
                rb"API Client\s*:\s*(\d+) reqs, Rx (\S+), Tx (\S+)", stats)
            assert m is not None, "stats has no API Client line: %r" % stats
            assert int(m.group(1)) >= 1, "api_client request counter did not move"
            assert m.group(2) != b"0" and m.group(3) != b"0", (
                "api_client byte counters did not move: %r" % m.group(0)
            )


@test("api/ruleset-update")
def t_api_ruleset_update(ctx: Context) -> None:
    listen = free_port()
    api = free_port()
    initial = write_ruleset(
        ctx.tmpdir, "ru0.lua", redirect_ruleset("smoke.test:80", ctx.echo_addr)
    )
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen), "-r", str(initial)],
        api_port=api,
        loglevel=ctx.loglevel,
    ):
        # initially smoke.test routes to echo
        with socks4a_connect(HOST, listen, "smoke.test", 80) as sock:
            echo_roundtrip(sock)
        # hot-reload: now smoke.test is rejected, hotpath.test routes to echo
        new_ruleset = redirect_ruleset("hotpath.test:80", ctx.echo_addr)
        status, body = api_request(
            api,
            "POST",
            "/ruleset/update?chunkname=%40ruleset.lua",
            new_ruleset.encode(),
        )
        assert status == 200, "ruleset update returned %d: %r" % (status, body)
        # new routing takes effect
        with socks4a_connect(HOST, listen, "hotpath.test", 80) as sock:
            echo_roundtrip(sock)
        # old route is gone -> rejected
        stale_rejected = False
        try:
            socks4a_connect(HOST, listen, "smoke.test", 80).close()
        except SocksError:
            stale_rejected = True
        assert stale_rejected, "stale route survived ruleset hot reload"

        # a rejected update (a chunk that fails to compile) must return non-200
        # AND leave the previously loaded ruleset routing traffic: a bad push
        # must never take down routing.
        status, body = api_request(
            api,
            "POST",
            "/ruleset/update?chunkname=%40ruleset.lua",
            b"return (((  -- deliberately not valid Lua\n",
        )
        assert status != 200, (
            "invalid ruleset update unexpectedly returned 200: %r" % body
        )
        # the current route must survive the rejected update
        with socks4a_connect(HOST, listen, "hotpath.test", 80) as sock:
            echo_roundtrip(sock)


@test("api/gc")
def t_api_gc(ctx: Context) -> None:
    listen = free_port()
    api = free_port()
    ruleset = write_ruleset(ctx.tmpdir, "direct.lua", direct_ruleset())
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, listen), "-r", str(ruleset)],
        api_port=api,
        loglevel=ctx.loglevel,
    ):
        status, _ = api_request(api, "POST", "/ruleset/gc")
        assert status == 200, "POST /ruleset/gc returned %d" % status


# --------------------------------------------------------------------------- #
# I. Config-file boot (-c)
# --------------------------------------------------------------------------- #


@test("config/boot")
def t_config_boot(ctx: Context) -> None:
    listen = free_port()
    api = free_port()
    config = (
        "local ruleset = {}\n"
        "function ruleset.resolve(addr) return addr end\n"
        "function ruleset.route(addr) return addr end\n"
        "function ruleset.route6(addr) return addr end\n"
        "return {\n"
        "    listen = %r,\n"
        "    restapi = %r,\n"
        "    loglevel = %d,\n"
        "    ruleset = ruleset,\n"
        "}\n"
    ) % ("%s:%d" % (HOST, listen), "%s:%d" % (HOST, api), ctx.loglevel)
    cfg = write_ruleset(ctx.tmpdir, "boot.lua", config)
    with Daemon(
        ctx.binary,
        ["-c", str(cfg)],
        api_port=api,
        loglevel=ctx.loglevel,
    ):
        status, _ = api_request(api, "GET", "/healthy")
        assert status == 200, "boot-config healthy returned %d" % status
        with socks5_connect(HOST, listen, HOST, ctx.echo_port) as sock:
            echo_roundtrip(sock)


@test("config/boot-proxy-notice")
def t_config_boot_proxy_notice(ctx: Context) -> None:
    """The proxy-chain notice must fire for a ruleset installed from a boot
    config too. It once tested the -r filename, which a boot config never sets,
    so this configuration was silently never told."""
    listen = free_port()
    config = (
        "local ruleset = {}\n"
        "function ruleset.resolve(addr) return addr end\n"
        "function ruleset.route(addr) return addr end\n"
        "function ruleset.route6(addr) return addr end\n"
        "return {\n"
        "    listen = %r,\n"
        "    proxy = %r,\n"
        "    loglevel = 4,\n"
        "    ruleset = ruleset,\n"
        "}\n"
    ) % (
        "%s:%d" % (HOST, listen),
        "socks5://%s:%d" % (HOST, free_port()),
    )
    cfg = write_ruleset(ctx.tmpdir, "boot_proxy.lua", config)
    with Daemon(
        ctx.binary, ["-c", str(cfg)], listen_port=listen, loglevel=4
    ) as d:
        log = d.stderr_all()
    hits = proxy_chain_notices(log)
    assert len(hits) == 1, (
        "expected exactly 1 proxy-chain notice, got %d:\n%s" % (len(hits), log)
    )
    assert PROXY_CHAIN_NOTICE in hits[0], "unexpected notice text: %s" % hits[0]


@test("config/boot-rejects-invalid")
def t_config_boot_rejects_invalid(ctx: Context) -> None:
    """The config check is deferred to after the boot config loads, so it is
    the only one that sees a boot-supplied field. A boot config carrying an
    out-of-range value must still be rejected."""
    config = (
        "return {\n"
        "    listen = %r,\n"
        "    timeout = 1.0,\n"
        "}\n"
    ) % ("%s:%d" % (HOST, free_port()),)
    cfg = write_ruleset(ctx.tmpdir, "boot_invalid.lua", config)
    proc = subprocess.run(
        [str(ctx.binary), "-c", str(cfg)], capture_output=True, timeout=10
    )
    assert proc.returncode != 0, (
        "expected non-zero exit for an out-of-range boot timeout"
    )


# --------------------------------------------------------------------------- #
# Runner / reporting
# --------------------------------------------------------------------------- #


def run_cases(ctx: Context, cases: List[Case], keep_going: bool) -> List[Result]:
    results: List[Result] = []
    for case in cases:
        start = time.monotonic()
        try:
            case.fn(ctx)
        except SkipTest as exc:
            res = Result(case.name, "SKIP", str(exc))
        except Exception as exc:  # noqa: BLE001 -- report any failure
            detail = "%s: %s" % (type(exc).__name__, exc)
            res = Result(case.name, "FAIL", detail)
        else:
            res = Result(case.name, "PASS")
        res.duration = time.monotonic() - start
        results.append(res)

        suffix = "" if not res.detail else "  -- %s" % res.detail.splitlines()[
            0]
        log("[%s] %-40s %6.2fs%s" %
            (res.status, case.name, res.duration, suffix))
        if res.status == "FAIL" and not keep_going:
            log("aborting on first failure (use -k to keep going)")
            break
    return results


def write_report(path: Path, results: List[Result]) -> None:
    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    skipped = sum(1 for r in results if r.status == "SKIP")
    lines = [
        "# neosocksd smoke test",
        "",
        "%d passed, %d failed, %d skipped" % (passed, failed, skipped),
        "",
        "| Test | Result | Time | Detail |",
        "| --- | --- | --- | --- |",
    ]
    for r in results:
        detail = r.detail.splitlines()[0] if r.detail else ""
        detail = detail.replace("|", "\\|")
        lines.append(
            "| %s | %s | %.2fs | %s |" % (r.name, r.status, r.duration, detail)
        )
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    # Failure details can carry U+FFFD from stderr_text(); pin UTF-8 so the
    # report write does not raise UnicodeEncodeError under a non-UTF-8 locale.
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build", default=str(DEFAULT_BUILD_DIR), help="build dir")
    parser.add_argument("--binary", default=None,
                        help="path to neosocksd binary")
    parser.add_argument("--loglevel", type=int,
                        default=4, help="daemon loglevel")
    parser.add_argument("--filter", default=None,
                        help="run tests matching SUBSTR")
    parser.add_argument("--list", action="store_true",
                        help="list tests and exit")
    parser.add_argument("-o", "--output", default=None,
                        help="markdown report path")
    parser.add_argument(
        "-k", "--keep-going", action="store_true", help="run all tests on failure"
    )
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)

    if args.list:
        for case in CASES:
            print(case.name)
        return 0

    ensure_project_root(ROOT)

    build_dir = Path(args.build)
    if not build_dir.is_absolute():
        build_dir = (ROOT / build_dir).resolve()
    binary = (
        Path(args.binary).resolve()
        if args.binary
        else build_dir / "bin" / "neosocksd"
    )
    if not binary.exists():
        log("neosocksd binary not found: %s" % binary)
        log("build the project first, or pass --binary/--build")
        return 2

    cases = CASES
    if args.filter:
        cases = [c for c in CASES if args.filter in c.name]
        if not cases:
            log("no tests match filter: %s" % args.filter)
            return 2

    output = Path(args.output) if args.output else build_dir / "smoke_test.md"

    targets = Targets().start()
    try:
        with tempfile.TemporaryDirectory(prefix="neosocksd-smoke-") as td:
            ctx = Context(
                binary=binary,
                tmpdir=Path(td),
                loglevel=args.loglevel,
                targets=targets,
            )
            log("binary : %s" % binary)
            log("echo   : %s:%d" % (HOST, targets.echo_port))
            log("running %d test(s)\n" % len(cases))
            results = run_cases(ctx, cases, args.keep_going)
    finally:
        targets.stop()

    write_report(output, results)

    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    skipped = sum(1 for r in results if r.status == "SKIP")
    log("")
    log(
        "summary: %d passed, %d failed, %d skipped  (report: %s)"
        % (passed, failed, skipped, output)
    )
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(130)
