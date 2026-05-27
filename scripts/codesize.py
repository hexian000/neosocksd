#!/usr/bin/env python3
"""Build the project with Release config and report per-file object file sizes.

Usage:
  scripts/codesize.py                  # build then report
  scripts/codesize.py -o PATH          # custom output file
  scripts/codesize.py --build DIR      # custom release build directory
  scripts/codesize.py --no-rebuild     # skip cmake configure and build steps

Output: build/codesize.md (Markdown table sorted by size, largest first)

Source files are discovered from compile_commands.json; every source whose
object file exists on disk is included (no regex filtering).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path.cwd().resolve()
DEFAULT_BUILD_DIR = ROOT / "build"
DEFAULT_RELEASE_BUILD_DIR = DEFAULT_BUILD_DIR / "codesize"
DEFAULT_OUTPUT = DEFAULT_BUILD_DIR / "codesize.md"

CACHE_LINE_RE = re.compile(r"^([A-Za-z0-9_]+):[^=]+=(.*)$")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def log(message: str) -> None:
    print(message, file=sys.stderr)


def ensure_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        sys.exit(f"error: required tool not found: {name}")
    return path


def ensure_project_root(root: Path) -> None:
    if not (root / "CMakeLists.txt").exists():
        sys.exit(
            f"error: working directory does not look like the project root: {root}"
        )


def parse_cmake_cache(cache_path: Path) -> dict[str, str]:
    cache: dict[str, str] = {}
    if not cache_path.exists():
        return cache
    with cache_path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            m = CACHE_LINE_RE.match(line)
            if m:
                cache[m.group(1)] = m.group(2)
    return cache


def _human(n: int) -> str:
    """Return a concise human-readable byte count."""
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KiB"
    return f"{n / (1024 * 1024):.1f} MiB"


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_release(cmake: str, build_dir: Path, base_cache: dict[str, str], config: str) -> None:
    if build_dir.exists():
        log(
            f"Removing existing build directory {build_dir.relative_to(ROOT)} …")
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True)

    configure_cmd = [
        cmake,
        "-S", str(ROOT),
        "-B", str(build_dir),
        f"-DCMAKE_BUILD_TYPE={config}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        "-DENABLE_SANITIZERS=OFF",
        "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF",
    ]
    compiler = base_cache.get("CMAKE_C_COMPILER")
    if compiler:
        configure_cmd.append(f"-DCMAKE_C_COMPILER={compiler}")

    log("+ " + " ".join(configure_cmd))
    proc = subprocess.run(configure_cmd)
    if proc.returncode != 0:
        sys.exit(proc.returncode)

    jobs = os.cpu_count() or 1
    build_cmd = [cmake, "--build", str(build_dir), f"-j{jobs}"]
    log("+ " + " ".join(build_cmd))
    proc = subprocess.run(build_cmd)
    if proc.returncode != 0:
        sys.exit(proc.returncode)


# ---------------------------------------------------------------------------
# compile_commands.json helper
# ---------------------------------------------------------------------------

def _extract_obj(entry: dict) -> Path | None:
    """Return the object file path from a compile_commands.json entry.

    Prefer the ``arguments`` list when present; otherwise split ``command``.
    Handles both absolute and relative (relative to ``directory``) -o values.
    """
    args: list[str] = entry.get("arguments") or shlex.split(
        entry.get("command", ""))
    for i, arg in enumerate(args):
        if arg == "-o" and i + 1 < len(args):
            p = Path(args[i + 1])
            if not p.is_absolute():
                p = Path(entry["directory"]) / p
            return p
    return None


# ---------------------------------------------------------------------------
# SLOC counter
# ---------------------------------------------------------------------------

def _sloc(path: Path) -> int:
    """Count non-blank, non-comment source lines in a C file (approximate)."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 0
    count = 0
    in_block = False
    for raw in lines:
        s = raw.strip()
        if not s:
            continue
        if in_block:
            if "*/" in s:
                s = s[s.index("*/") + 2:].strip()
                in_block = False
                if not s or s.startswith("//"):
                    continue
            else:
                continue
        # Strip inline block comments: /* ... */
        while "/*" in s:
            before, _, rest = s.partition("/*")
            if "*/" in rest:
                s = (before + " " + rest[rest.index("*/") + 2:]).strip()
            else:
                s = before.strip()
                in_block = True
                break
        if not s or s.startswith("//"):
            continue
        count += 1
    return count


# ---------------------------------------------------------------------------
# Size collection
# ---------------------------------------------------------------------------

def collect_sizes(build_dir: Path, target: str | None = None) -> list[tuple[str, int, int]]:
    """Return [(source_rel, byte_size, sloc), ...] from compile_commands.json.

    Each entry's ``-o`` path is used to locate the actual object file.  Entries
    whose object file does not exist on disk are skipped (e.g. not built).
    When the same source appears in multiple entries (compiled into multiple
    targets), keep only the largest object file.

    If *target* is given, only entries whose object file lives under
    ``CMakeFiles/<target>.dir/`` are considered.
    """
    db_path = build_dir / "compile_commands.json"
    if not db_path.exists():
        sys.exit(f"error: {db_path} not found — run cmake configure first")
    db: list[dict] = json.loads(db_path.read_text(encoding="utf-8"))

    target_dir = f"{target}.dir" if target is not None else None
    best: dict[str, int] = {}
    for entry in db:
        src_abs = Path(entry["file"])
        try:
            src_rel = str(src_abs.relative_to(ROOT))
        except ValueError:
            continue
        obj = _extract_obj(entry)
        if obj is None or not obj.exists():
            continue
        if target_dir is not None:
            parts = obj.parts
            try:
                idx = parts.index("CMakeFiles")
            except ValueError:
                continue
            if idx + 1 >= len(parts) or parts[idx + 1] != target_dir:
                continue
        sz = obj.stat().st_size
        if sz > best.get(src_rel, 0):
            best[src_rel] = sz
    return [(src, sz, _sloc(ROOT / src)) for src, sz in best.items()]


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def write_report(
    rows: list[tuple[str, int, int]],
    output: Path,
    elapsed: float,
    config: str,
) -> None:
    total_bytes = sum(sz for _, sz, _ in rows)
    total_sloc = sum(sl for _, _, sl in rows)
    date = datetime.date.today().isoformat()

    lines: list[str] = [
        "# Code Size Report",
        "",
        f"**Date:** {date} &ensp;"
        f" **Config:** {config} &ensp;"
        f" **Elapsed:** {elapsed:.1f} s &ensp;"
        f" **Files:** {len(rows)} &ensp;"
        f" **SLOC:** {total_sloc:,} &ensp;"
        f" **Total:** {total_bytes:,} B ({_human(total_bytes)})",
        "",
        "Sizes are unstripped Release-build object files (`*.c.o`)."
        " Sources are taken directly from `compile_commands.json`; every source"
        " whose object file exists on disk is included.",
        "",
        "| File | SLOC | Bytes | % |",
        "|---|---:|---:|---:|",
    ]
    for src, sz, sloc in sorted(rows, key=lambda x: (-x[1], x[0])):
        pct = sz / total_bytes * 100 if total_bytes else 0
        lines.append(f"| `{src}` | {sloc:,} | {sz:,} | {pct:.1f} |")
    lines.append(
        f"| **Total** | **{total_sloc:,}** | **{total_bytes:,}** | **100.0** |"
    )
    lines.append("")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")
    log(f"wrote {output.relative_to(ROOT)}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "-o", "--output",
        metavar="FILE",
        default=str(DEFAULT_OUTPUT),
        help="output Markdown file (default: %(default)s)",
    )
    ap.add_argument(
        "--build",
        metavar="DIR",
        default=str(DEFAULT_RELEASE_BUILD_DIR),
        help="release build directory (default: %(default)s)",
    )
    ap.add_argument(
        "--config",
        metavar="TYPE",
        default="Release",
        help="cmake build type (default: %(default)s)",
    )
    ap.add_argument(
        "-t", "--target",
        metavar="TARGET",
        default=None,
        help="restrict report to sources compiled for cmake target TARGET",
    )
    ap.add_argument(
        "--no-rebuild",
        action="store_true",
        help="skip cmake configure and build steps",
    )
    args = ap.parse_args()

    ensure_project_root(ROOT)

    build_dir = Path(args.build)
    if not build_dir.is_absolute():
        build_dir = ROOT / build_dir
    output = Path(args.output)
    if not output.is_absolute():
        output = ROOT / output

    t0 = time.monotonic()

    if not args.no_rebuild:
        cmake = ensure_tool("cmake")
        base_cache = parse_cmake_cache(DEFAULT_BUILD_DIR / "CMakeCache.txt")
        log(
            f"Configuring and building {args.config} in {build_dir.relative_to(ROOT)} …")
        build_release(cmake, build_dir, base_cache, args.config)

    log("Collecting object file sizes …")
    rows = collect_sizes(build_dir, target=args.target)
    if not rows:
        sys.exit(
            f"error: no compiled sources found via {build_dir / 'compile_commands.json'}")

    elapsed = time.monotonic() - t0
    log(f"{len(rows)} file(s), {sum(sl for _, _, sl in rows):,} SLOC, total {_human(sum(sz for _, sz, _ in rows))}, {elapsed:.1f} s")

    write_report(rows, output, elapsed, args.config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
