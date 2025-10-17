"""Automated response worker that tails alerts.jsonl."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path

DATA_DIR = Path("/data/alerts")
AUDIT_DIR = Path("/data/audit")
POLICY_PATH = Path(os.getenv("RESPONSE_POLICY", "/app/policy.yaml"))


def load_policy() -> dict:
    with POLICY_PATH.open("r", encoding="utf-8") as f:
        raw = f.read()

    try:
        import yaml  # type: ignore
    except ModuleNotFoundError:
        return _parse_simple_yaml(raw)
    else:
        return yaml.safe_load(raw)


def _parse_simple_yaml(text: str) -> dict:
    """Parse the small subset of YAML used in ``policy.yaml``.

    The project runs in environments where installing PyYAML may not be
    possible.  Rather than fail outright we implement a minimal parser that
    understands the ``key: value`` and ``parent:\n  child: value`` constructs
    present in the default policy file.  The parser intentionally ignores more
    complex YAML features; if advanced syntax is required users should install
    PyYAML inside the container image.
    """

    result: dict[str, dict[str, object] | object] = {}
    current_section: dict[str, object] | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.endswith(":"):
            key = line[:-1].strip()
            section: dict[str, object] = {}
            result[key] = section
            current_section = section
            continue

        if ":" not in line:
            continue

        key, value = [part.strip() for part in line.split(":", 1)]
        parsed_value: object

        if value.lower() in {"true", "false"}:
            parsed_value = value.lower() == "true"
        else:
            try:
                parsed_value = float(value)
            except ValueError:
                parsed_value = value.strip('"')

        target = current_section if current_section is not None else result
        target[key] = parsed_value

    return result


def iter_alerts(file_path: Path):
    file_path.parent.mkdir(parents=True, exist_ok=True)
    if not file_path.exists():
        file_path.touch()
    with file_path.open("r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            yield json.loads(line)


def should_block(score: float, policy: dict) -> bool:
    thresholds = policy.get("score_thresholds", {})
    return score >= thresholds.get("block_ip", 0.9)


def should_email(score: float, policy: dict) -> bool:
    thresholds = policy.get("score_thresholds", {})
    return score >= thresholds.get("email_only", 0.7)


def block_ip(ip: str, policy: dict, dry_run: bool = False) -> None:
    cmd = policy.get("actions", {}).get("block_cmd", "ufw deny from {src_ip}").format(src_ip=ip)
    if dry_run:
        print(f"[responder] DRY RUN block: {cmd}")
        return
    subprocess.run(cmd.split(), check=False)


def send_email(alert: dict, policy: dict, dry_run: bool = False) -> None:
    recipient = policy.get("actions", {}).get("mail_to")
    if not recipient:
        return
    if dry_run:
        print(f"[responder] DRY RUN email to {recipient}: {alert}")
        return
    # Placeholder for actual email integration
    print(f"[responder] would send email to {recipient}: {alert}")


def audit(entry: dict) -> None:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    with (AUDIT_DIR / "response.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def process_alerts(dry_run: bool = False) -> None:
    policy = load_policy()
    for alert in iter_alerts(DATA_DIR / "alerts.jsonl"):
        score = alert.get("alert", {}).get("score", 0)
        dst_ip = alert.get("alert", {}).get("dst_ip")
        actions = []
        if dst_ip and should_block(score, policy):
            block_ip(dst_ip, policy, dry_run=dry_run)
            actions.append("block_ip")
        if should_email(score, policy):
            send_email(alert, policy, dry_run=dry_run)
            actions.append("email")
        audit({
            "timestamp": time.time(),
            "actions": actions,
            "alert": alert,
        })


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Simulate actions without executing")
    args = parser.parse_args()
    process_alerts(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
