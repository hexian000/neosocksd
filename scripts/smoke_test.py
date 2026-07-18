#!/usr/bin/env python3

"""End-to-end smoke test for the built neosocksd binary.

Drives the real `neosocksd` executable the way live clients do: speaks
SOCKS4/4A/5 and HTTP (CONNECT + forward proxy) over real sockets, exercises the
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
import base64
import hashlib
import http.client
import random
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Callable, List, Optional, Tuple


ROOT = Path.cwd().resolve()
DEFAULT_BUILD_DIR = ROOT / "build"
DEFAULT_OUTPUT = DEFAULT_BUILD_DIR / "smoke_test.md"

HOST = "127.0.0.1"
HTTP_BODY = b"neosocksd-smoke-ok\n"
READY_TIMEOUT = 5.0
IO_TIMEOUT = 5.0
SHUTDOWN_TIMEOUT = 5.0


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
    pass


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
            raise SocksError("no acceptable authentication method")
        if method == 0x02:
            if user is None:
                raise SocksError("server demanded user/pass but none supplied")
            u = user.encode()
            p = (password or "").encode()
            sock.sendall(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
            _, status = recv_exact(sock, 2)
            if status != 0x00:
                raise SocksError("username/password auth failed")
        elif method != 0x00:
            raise SocksError("unexpected auth method selected: %d" % method)

        req = bytearray([0x05, 0x01, 0x00])
        try:
            packed = socket.inet_aton(dst_host)
            req.append(0x01)
            req += packed
        except OSError:
            host = dst_host.encode()
            req.append(0x03)
            req.append(len(host))
            req += host
        req += struct.pack("!H", dst_port)
        sock.sendall(bytes(req))

        ver, rep, _rsv, atyp = recv_exact(sock, 4)
        if ver != 0x05:
            raise SocksError("bad SOCKS5 version in reply: %d" % ver)
        if rep != 0x00:
            raise SocksError("SOCKS5 CONNECT failed, reply code %d" % rep)
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


def _encode_chunked(body: bytes, parts: int = 3) -> bytes:
    """Frame `body` as HTTP/1.1 chunked transfer coding (at least one chunk)."""
    if not body:
        return b"0\r\n\r\n"
    step = max(1, -(-len(body) // parts))  # ceil division into `parts` chunks
    out = bytearray()
    for off in range(0, len(body), step):
        piece = body[off:off + step]
        out += b"%X\r\n" % len(piece) + piece + b"\r\n"
    out += b"0\r\n\r\n"
    return bytes(out)


def _decode_chunked(data: bytes) -> bytes:
    """Decode a chunked-framed body, ignoring chunk extensions and trailers."""
    out = bytearray()
    i = 0
    while True:
        eol = data.index(b"\r\n", i)
        size = int(data[i:eol].split(b";", 1)[0], 16)
        i = eol + 2
        if size == 0:
            break
        out += data[i:i + size]
        i += size + 2  # trailing CRLF after the chunk data
    return bytes(out)


def _parse_http_response(data: bytes, method: str) -> Tuple[int, dict, bytes]:
    """Split a full HTTP/1.1 response into (status, headers, decoded body).

    The body is delimited by Transfer-Encoding: chunked, Content-Length, or EOF,
    in that order of precedence; a HEAD response is always bodiless.
    """
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ", 2)
    if len(parts) < 2:
        raise SocksError("malformed HTTP response: %r" % lines[0])
    status = int(parts[1])
    headers: dict = {}
    for line in lines[1:]:
        key, _, value = line.partition(b":")
        headers[key.strip().lower()] = value.strip()
    if method == "HEAD":
        body = b""
    elif b"chunked" in headers.get(b"transfer-encoding", b"").lower():
        body = _decode_chunked(rest)
    elif b"content-length" in headers:
        body = rest[: int(headers[b"content-length"])]
    else:
        body = rest  # length delimited by connection close
    return status, headers, body


def http_forward(
    proxy_host: str,
    proxy_port: int,
    dst_host: str,
    dst_port: int,
    path: str = "/",
    *,
    method: str = "GET",
    body: Optional[bytes] = None,
    chunked: bool = False,
    extra_headers: Optional[List[Tuple[str, str]]] = None,
    raw_target: Optional[str] = None,
) -> Tuple[int, dict, bytes]:
    """Drive one proxy_pass (absolute-URI) exchange through the HTTP proxy.

    Reads the whole response -- the proxy answers with `Connection: close` -- and
    decodes the body per its framing. `raw_target` overrides the request target
    verbatim to exercise malformed-request handling.
    """
    sock = _connect(proxy_host, proxy_port)
    try:
        target = (
            raw_target
            if raw_target is not None
            else "http://%s:%d%s" % (dst_host, dst_port, path)
        )
        head = [
            "%s %s HTTP/1.1" % (method, target),
            "Host: %s:%d" % (dst_host, dst_port),
            "Connection: close",
        ]
        for key, value in extra_headers or []:
            head.append("%s: %s" % (key, value))
        payload = b""
        if body is not None:
            if chunked:
                head.append("Transfer-Encoding: chunked")
                payload = _encode_chunked(body)
            else:
                head.append("Content-Length: %d" % len(body))
                payload = body
        request = ("\r\n".join(head) + "\r\n\r\n").encode() + payload
        sock.sendall(request)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return _parse_http_response(data, method)
    finally:
        sock.close()


def http_forward_get(
    proxy_host: str, proxy_port: int, dst_host: str, dst_port: int, path: str = "/"
) -> Tuple[int, bytes]:
    """Perform an absolute-URI GET through an HTTP forward proxy."""
    status, _headers, body = http_forward(
        proxy_host, proxy_port, dst_host, dst_port, path
    )
    return status, body


def http_websocket(
    proxy_host: str,
    proxy_port: int,
    dst_host: str,
    dst_port: int,
    payload: bytes,
) -> Tuple[str, bool, bytes]:
    """Drive a ws:// (absolute-URI) upgrade through the HTTP forward proxy, then
    exchange one payload over the resulting raw tunnel.

    Returns (status_line, accept_valid, echoed_payload) where accept_valid is
    whether the Sec-WebSocket-Accept matched the RFC 6455 key derivation.
    """
    key = base64.b64encode(bytes(random.getrandbits(8) for _ in range(16)))
    expected = base64.b64encode(hashlib.sha1(key + _WS_GUID.encode()).digest())
    sock = _connect(proxy_host, proxy_port)
    try:
        request = (
            "GET http://%s:%d/chat HTTP/1.1\r\n" % (dst_host, dst_port)
            + "Host: %s:%d\r\n" % (dst_host, dst_port)
            + "Upgrade: websocket\r\n"
            + "Connection: Upgrade\r\n"
            + "Sec-WebSocket-Key: %s\r\n" % key.decode("ascii")
            + "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        sock.sendall(request)
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk:
                raise SocksError("connection closed during ws handshake")
            head += chunk
        header_block, _, rest = head.partition(b"\r\n\r\n")
        status_line = header_block.split(b"\r\n", 1)[0].decode("latin-1")
        accept = b""
        for line in header_block.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"sec-websocket-accept":
                accept = value.strip()
        # send a post-upgrade payload; the raw tunnel must echo it back
        sock.sendall(payload)
        echoed = rest
        while len(echoed) < len(payload):
            chunk = sock.recv(4096)
            if not chunk:
                break
            echoed += chunk
        return status_line, accept == expected, echoed
    finally:
        sock.close()


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


class _HTTPHandler(BaseHTTPRequestHandler):
    """Proxy destination for proxy_pass tests.

    Routes by path/method so a single instance exercises request-body forwarding
    (POST echo), response re-framing (chunked), bodiless HEAD responses, and
    header rewriting (`/echo-headers` reflects what the proxy forwarded).
    """

    protocol_version = "HTTP/1.1"

    def _read_request_body(self) -> bytes:
        te = self.headers.get("Transfer-Encoding", "")
        if "chunked" in te.lower():
            body = bytearray()
            while True:
                size_line = self.rfile.readline()
                size = int(size_line.split(b";", 1)[0].strip() or b"0", 16)
                if size == 0:
                    # consume optional trailers up to the terminating blank line
                    while self.rfile.readline().strip():
                        pass
                    break
                body += self.rfile.read(size)
                self.rfile.read(2)  # CRLF following the chunk data
            return bytes(body)
        length = self.headers.get("Content-Length")
        if length is not None:
            return self.rfile.read(int(length))
        return b""

    def _respond(self, body: bytes, *, chunked: bool = False) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
        else:
            self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if chunked:
            step = max(1, -(-len(body) // 3))  # split into ~3 chunks
            for off in range(0, len(body), step):
                piece = body[off:off + step]
                self.wfile.write(b"%X\r\n" % len(piece) + piece + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.wfile.write(body)
        self.close_connection = True

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        self._read_request_body()  # drain any body to keep framing correct
        if self.path == "/chunked":
            self._respond(HTTP_BODY, chunked=True)
        elif self.path == "/echo-headers":
            reflected = "".join(
                "%s: %s\n" % (k, v) for k, v in self.headers.items()
            ).encode()
            self._respond(reflected)
        else:
            self._respond(HTTP_BODY)

    def do_HEAD(self) -> None:  # noqa: N802
        # advertise a body via Content-Length but send none, per HTTP semantics
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(HTTP_BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def do_POST(self) -> None:  # noqa: N802
        self._respond(self._read_request_body())

    def log_message(self, *args) -> None:  # silence
        pass


_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"  # RFC 6455 §4.2.2


class _WebSocketHandler(socketserver.BaseRequestHandler):
    """Raw ws:// origin: completes the RFC 6455 handshake it receives from the
    proxy -- proving the proxy forwarded the origin-form request together with
    the Connection/Upgrade switch-protocol headers -- then echoes the
    post-upgrade byte stream, proving the connection became a raw tunnel.
    """

    def handle(self) -> None:
        self.request.settimeout(IO_TIMEOUT)
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                head += chunk
            header_block, _, rest = head.partition(b"\r\n\r\n")
            lower = header_block.lower()
            key = None
            for line in header_block.split(b"\r\n")[1:]:
                name, _, value = line.partition(b":")
                if name.strip().lower() == b"sec-websocket-key":
                    key = value.strip()
            # only upgrade when the proxy actually forwarded both switch-protocol
            # headers; otherwise the tunnel must not be established
            if (
                b"upgrade: websocket" not in lower
                or b"connection: upgrade" not in lower
                or key is None
            ):
                self.request.sendall(
                    b"HTTP/1.1 426 Upgrade Required\r\n"
                    b"Connection: close\r\n\r\n"
                )
                return
            accept = base64.b64encode(
                hashlib.sha1(key + _WS_GUID.encode()).digest()
            )
            self.request.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
            )
            # raw tunnel established: echo everything, including any bytes the
            # client pipelined right behind the handshake
            if rest:
                self.request.sendall(rest)
            while True:
                data = self.request.recv(65536)
                if not data:
                    break
                self.request.sendall(data)
        except OSError:
            pass


class Targets:
    """Loopback echo + HTTP + WebSocket servers used as proxy destinations."""

    def __init__(self) -> None:
        self.echo = _ThreadingTCPServer((HOST, 0), _EchoHandler)
        self.http = _ThreadingTCPServer((HOST, 0), _HTTPHandler)
        self.ws = _ThreadingTCPServer((HOST, 0), _WebSocketHandler)
        self.echo_port = self.echo.server_address[1]
        self.http_port = self.http.server_address[1]
        self.ws_port = self.ws.server_address[1]
        self._threads = [
            threading.Thread(target=self.echo.serve_forever, daemon=True),
            threading.Thread(target=self.http.serve_forever, daemon=True),
            threading.Thread(target=self.ws.serve_forever, daemon=True),
        ]

    def start(self) -> "Targets":
        for t in self._threads:
            t.start()
        return self

    def stop(self) -> None:
        for srv in (self.echo, self.http, self.ws):
            try:
                srv.shutdown()
                srv.server_close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# REST API client
# --------------------------------------------------------------------------- #


def api_request(
    api_port: int, method: str, path: str, body: Optional[bytes] = None
) -> Tuple[int, bytes]:
    conn = http.client.HTTPConnection(HOST, api_port, timeout=IO_TIMEOUT)
    try:
        conn.request(method, path, body=body)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


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

    def stderr_text(self) -> str:
        self._stderr.seek(0)
        data = self._stderr.read().decode(errors="replace")
        # keep the report compact: only the tail matters for diagnosis
        lines = data.splitlines()
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
            self._terminate()
            raise
        return self

    def _terminate(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=SHUTDOWN_TIMEOUT)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=SHUTDOWN_TIMEOUT)

    def __exit__(self, *exc) -> None:
        self._terminate()
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
    """Redirect a fake hostname to the echo target; reject `reject.test`."""
    return (
        "local ECHO = %r\n"
        "local FAKE = %r\n"
        "local ruleset = {}\n"
        "function ruleset.resolve(addr)\n"
        "    if addr == FAKE then return ECHO end\n"
        "    if addr == 'reject.test:80' then return nil end\n"
        "    return addr\n"
        "end\n"
        "function ruleset.route(addr) return addr end\n"
        "function ruleset.route6(addr) return addr end\n"
        "return ruleset\n"
    ) % (echo_addr, fake_host)


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
    def http_port(self) -> int:
        return self.targets.http_port

    @property
    def ws_port(self) -> int:
        return self.targets.ws_port

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


@test("cli/startup-shutdown")
def t_cli_startup_shutdown(ctx: Context) -> None:
    port = free_port()
    with Daemon(
        ctx.binary,
        ["-l", "%s:%d" % (HOST, port)],
        listen_port=port,
        loglevel=ctx.loglevel,
    ) as d:
        # graceful SIGTERM is exercised by the harness on exit
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
    d, listen, _ = _socks_daemon(ctx)
    with d:
        sock = socks5_connect(HOST, listen, "localhost", ctx.echo_port)
        with sock:
            echo_roundtrip(sock)


@test("socks5/refused")
def t_socks5_refused(ctx: Context) -> None:
    d, listen, _ = _socks_daemon(ctx)
    dead = free_port()  # nothing listening here
    with d:
        try:
            socks5_connect(HOST, listen, HOST, dead).close()
        except SocksError:
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
    d, listen, _ = _socks_daemon(ctx)
    with d:
        sock = socks4a_connect(HOST, listen, "localhost", ctx.echo_port)
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
        except SocksError:
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


# --------------------------------------------------------------------------- #
# D. HTTP proxy (CONNECT + proxy_pass)
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


@test("http/forward")
def t_http_forward(ctx: Context) -> None:
    d, http_port = _http_daemon(ctx)
    with d:
        status, body = http_forward_get(HOST, http_port, HOST, ctx.http_port)
        assert status == 200, "forward proxy returned status %d" % status
        assert HTTP_BODY in body, "forward proxy body mismatch: %r" % body


@test("http/proxy-pass-post-echo")
def t_http_proxy_pass_post(ctx: Context) -> None:
    """A Content-Length request body is forwarded intact and echoed back."""
    d, http_port = _http_daemon(ctx)
    payload = random.randbytes(2048)
    with d:
        status, _hdr, body = http_forward(
            HOST, http_port, HOST, ctx.http_port, "/echo",
            method="POST", body=payload,
        )
        assert status == 200, "POST proxy_pass returned %d" % status
        assert body == payload, "request body not forwarded verbatim"


@test("http/proxy-pass-chunked-request")
def t_http_proxy_pass_chunked_request(ctx: Context) -> None:
    """A chunked request body is dechunked/re-framed and forwarded intact."""
    d, http_port = _http_daemon(ctx)
    payload = random.randbytes(5000)
    with d:
        status, _hdr, body = http_forward(
            HOST, http_port, HOST, ctx.http_port, "/echo",
            method="POST", body=payload, chunked=True,
        )
        assert status == 200, "chunked POST proxy_pass returned %d" % status
        assert body == payload, "chunked request body not forwarded verbatim"


@test("http/proxy-pass-chunked-response")
def t_http_proxy_pass_chunked_response(ctx: Context) -> None:
    """A chunked upstream response is re-framed and reaches the client whole."""
    d, http_port = _http_daemon(ctx)
    with d:
        status, _hdr, body = http_forward(
            HOST, http_port, HOST, ctx.http_port, "/chunked"
        )
        assert status == 200, "chunked-response proxy_pass returned %d" % status
        assert body == HTTP_BODY, "chunked response body mismatch: %r" % body


@test("http/proxy-pass-head")
def t_http_proxy_pass_head(ctx: Context) -> None:
    """A HEAD response carries headers but no body across the proxy."""
    d, http_port = _http_daemon(ctx)
    with d:
        status, _hdr, body = http_forward(
            HOST, http_port, HOST, ctx.http_port, "/", method="HEAD"
        )
        assert status == 200, "HEAD proxy_pass returned %d" % status
        assert body == b"", "HEAD response leaked a body: %r" % body


@test("http/proxy-pass-large-body")
def t_http_proxy_pass_large_body(ctx: Context) -> None:
    """A megabyte-scale body survives a proxy_pass round trip byte-for-byte."""
    d, http_port = _http_daemon(ctx)
    payload = random.randbytes(1 << 20)
    with d:
        status, _hdr, body = http_forward(
            HOST, http_port, HOST, ctx.http_port, "/echo",
            method="POST", body=payload,
        )
        assert status == 200, "large-body proxy_pass returned %d" % status
        assert body == payload, "large body corrupted (%d bytes)" % len(body)


@test("http/proxy-pass-header-rewrite")
def t_http_proxy_pass_headers(ctx: Context) -> None:
    """The proxy regenerates Host, appends Via, and forwards custom headers."""
    d, http_port = _http_daemon(ctx)
    with d:
        status, _hdr, body = http_forward(
            HOST, http_port, HOST, ctx.http_port, "/echo-headers",
            extra_headers=[("X-Smoke-Test", "hello")],
        )
        assert status == 200, "header-rewrite proxy_pass returned %d" % status
        reflected = body.lower()
        assert b"via: 1.1 neosocksd" in reflected, "Via header not appended"
        assert b"x-smoke-test: hello" in reflected, "custom header not forwarded"
        assert b"host: %s:%d" % (HOST.encode(), ctx.http_port) in reflected, (
            "Host not regenerated from the request target"
        )


@test("http/proxy-pass-bad-target")
def t_http_proxy_pass_bad_target(ctx: Context) -> None:
    """A non-absolute request target is rejected with 400 (proxy needs a URI)."""
    d, http_port = _http_daemon(ctx)
    with d:
        status, _hdr, _body = http_forward(
            HOST, http_port, HOST, ctx.http_port, raw_target="/relative-path"
        )
        assert status == 400, "expected 400 for non-absolute target, got %d" % status


@test("http/proxy-pass-ruleset-redirect")
def t_http_proxy_pass_ruleset(ctx: Context) -> None:
    """proxy_pass honors a ruleset that redirects the target host."""
    http_addr = "%s:%d" % (HOST, ctx.http_port)
    ruleset = write_ruleset(
        ctx.tmpdir, "http_redirect.lua",
        redirect_ruleset("smoke.test:80", http_addr),
    )
    d, http_port = _http_daemon(ctx, ("-r", str(ruleset)))
    with d:
        status, _hdr, body = http_forward(HOST, http_port, "smoke.test", 80)
        assert status == 200, "ruleset proxy_pass returned %d" % status
        assert body == HTTP_BODY, "ruleset proxy_pass body mismatch: %r" % body


@test("http/websocket-upgrade")
def t_http_websocket_upgrade(ctx: Context) -> None:
    """A ws:// upgrade is forwarded with the switch-protocol headers intact and
    the connection becomes a raw tunnel (101 handshake + echoed frame)."""
    d, http_port = _http_daemon(ctx)
    payload = b"\x81\x8bframe-over-the-tunnel"
    with d:
        status_line, accept_ok, echoed = http_websocket(
            HOST, http_port, HOST, ctx.ws_port, payload
        )
        assert "101" in status_line, "ws upgrade returned %r" % status_line
        assert accept_ok, "Sec-WebSocket-Accept mismatch (handshake not relayed)"
        assert echoed == payload, "tunnel did not echo frame: %r" % echoed


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
        except SocksError:
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
        try:
            socks4a_connect(HOST, listen, "smoke.test", 80).close()
        except SocksError:
            return
        raise AssertionError("stale route survived ruleset hot reload")


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
    path.write_text("\n".join(lines))


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
            log("http   : %s:%d" % (HOST, targets.http_port))
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
