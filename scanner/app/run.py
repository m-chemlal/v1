"""Scheduled Nmap scanner container entrypoint."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_INTERVAL = int(os.getenv("SCAN_INTERVAL", "600"))
DEFAULT_TARGETS = os.getenv("SCAN_TARGETS", "127.0.0.1")
OUTPUT_DIR = Path("/data/scans")


def run_scan() -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = OUTPUT_DIR / f"scan_{timestamp}.xml"
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
