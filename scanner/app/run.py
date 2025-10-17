"""Scheduled Nmap scanner container entrypoint."""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List

DEFAULT_INTERVAL = int(os.getenv("SCAN_INTERVAL", "600"))
OUTPUT_DIR = Path(os.getenv("SCAN_OUTPUT_DIR", "/data/scans"))

_raw_targets = os.getenv("SCAN_TARGETS", "127.0.0.1")
TARGETS: List[str] = shlex.split(_raw_targets) or ["127.0.0.1"]

_raw_options = os.getenv("SCAN_OPTIONS", "-sV -Pn")
BASE_OPTIONS: List[str] = shlex.split(_raw_options)

_host_timeout = os.getenv("SCAN_HOST_TIMEOUT")
if _host_timeout:
    BASE_OPTIONS += ["--host-timeout", _host_timeout]

_max_runtime = os.getenv("SCAN_MAX_RUNTIME")
MAX_RUNTIME: float | None
try:
    MAX_RUNTIME = float(_max_runtime) if _max_runtime else None
except ValueError:
    print(
        f"[scanner] invalid SCAN_MAX_RUNTIME value '{_max_runtime}', ignoring",
        file=sys.stderr,
    )
    MAX_RUNTIME = None

DRY_RUN = os.getenv("SCAN_DRY_RUN", "").lower() in {"1", "true", "yes"}


def _build_command(output_path: Path, targets: Iterable[str]) -> list[str]:
    opts = list(BASE_OPTIONS)
    return ["nmap", *opts, *targets, "-oX", str(output_path)]


def _write_stub_scan(path: Path) -> None:
    """Emit a minimal Nmap XML file so downstream stages can continue."""

    content = """<?xml version='1.0' encoding='UTF-8'?>
<nmaprun scanner='nmap' args='stub' startstr='stub'>
  <scaninfo type='dry-run' protocol='tcp'/>
  <runstats>
    <finished time='0' elapsed='0.00' summary='dry run'/>
  </runstats>
</nmaprun>
"""
    path.write_text(content)

DEFAULT_INTERVAL = int(os.getenv("SCAN_INTERVAL", "600"))
DEFAULT_TARGETS = os.getenv("SCAN_TARGETS", "127.0.0.1")
OUTPUT_DIR = Path("/data/scans")


def run_scan() -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = OUTPUT_DIR / f"scan_{timestamp}.xml"

    if DRY_RUN:
        _write_stub_scan(output_path)
        print(f"[scanner] dry-run: wrote stub scan -> {output_path}")
        return output_path

    cmd = _build_command(output_path, TARGETS)
    print(f"[scanner] running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, check=False, timeout=MAX_RUNTIME)
        if result.returncode != 0:
            print(
                f"[scanner] nmap exited with code {result.returncode}",
                file=sys.stderr,
            )
    except subprocess.TimeoutExpired:
        print(
            f"[scanner] scan timed out after {MAX_RUNTIME} seconds",
            file=sys.stderr,
        )
    finally:
        if not output_path.exists():
            _write_stub_scan(output_path)

    cmd = [
        "nmap",
        "-sV",
        "-O",
        "-Pn",
        DEFAULT_TARGETS,
        "-oX",
        str(output_path),
    ]
    subprocess.run(cmd, check=False)
    return output_path


def loop(interval: int) -> None:
    while True:
        path = run_scan()
        print(f"[scanner] completed scan -> {path}")
        time.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Run a single scan and exit")
    args = parser.parse_args()

    interval = DEFAULT_INTERVAL
    if args.once:
        run_scan()
        return

    try:
        loop(interval)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
