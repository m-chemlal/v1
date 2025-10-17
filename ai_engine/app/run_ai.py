"""AI engine entrypoint for parsing Nmap XML and generating alerts.

This implementation only relies on the Python standard library so it can run
in restricted environments (such as the execution sandbox used for the
automated tests in this repository) without requiring network access to fetch
third-party dependencies.  The previous version depended on :mod:`pandas` and
``xmltodict`` which could not be installed during tests, causing the program to
fail before doing any work.  The parsing logic now uses ``xml.etree`` and the
scoring pipeline operates on plain dictionaries.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, List

DATA_ROOT = Path("/data")
SCAN_DIR = DATA_ROOT / "scans"
ALERT_DIR = DATA_ROOT / "alerts"
AUDIT_DIR = DATA_ROOT / "audit"
ALERT_THRESHOLD = float(os.getenv("ALERT_SCORE_THRESHOLD", "0.75"))
SYSLOG_HOST = os.getenv("WAZUH_SYSLOG_HOST", "wazuh-manager")
SYSLOG_PORT = int(os.getenv("WAZUH_SYSLOG_PORT", "1514"))


def load_scans() -> Iterable[Path]:
    SCAN_DIR.mkdir(parents=True, exist_ok=True)
    return sorted(SCAN_DIR.glob("*.xml"))


def parse_scan(path: Path) -> List[dict]:
    """Parse a single Nmap XML scan into a list of service records."""

    if not path.exists() or path.stat().st_size == 0:
        return []

    try:
        tree = ET.parse(path)
    except ET.ParseError:
        # Malformed scans should not crash the pipeline; they simply yield no
        # alerts and can be inspected separately.
        return []

    root = tree.getroot()
    alerts: List[dict] = []

    for host in root.findall("host"):
        ipv4 = "unknown"
        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                ipv4 = address.get("addr", "unknown")
                break

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            service = port.find("service")
            alert = {
                "host": ipv4,
                "protocol": port.get("protocol"),
                "port": int(port.get("portid", "0")),
                "service": service.get("name") if service is not None else None,
                "product": service.get("product") if service is not None else None,
                "version": service.get("version") if service is not None else None,
            }
            alerts.append(alert)

    return alerts


def score(alerts: List[dict]) -> List[dict]:
    """Attach a rudimentary risk score and explanation to each alert."""

    results: List[dict] = []
    for alert in alerts:
        score_value = 0.3
        explanations: List[str] = []

        if alert.get("port") in {22, 3389, 5900}:
            score_value += 0.4
            explanations.append("sensitive_port")

        service = (alert.get("service") or "").lower()
        if any(proto in service for proto in ("ftp", "telnet")):
            score_value += 0.3
            explanations.append("legacy_protocol")

        alert_with_score = {
            **alert,
            "score": max(0.0, min(score_value, 1.0)),
            "explanation": explanations,
        }
        results.append(alert_with_score)

    return results


def write_alerts(scored_alerts: List[dict], source: Path) -> List[dict]:
    """Persist alerts that cross the risk threshold and return them."""

    ALERT_DIR.mkdir(parents=True, exist_ok=True)
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    alerts: List[dict] = []

    for record in scored_alerts:
        if record.get("score", 0.0) < ALERT_THRESHOLD:
            continue

        payload = {
            "event_type": "ai_alert",
            "alert": {
                "summary": f"Service {record.get('service')} exposed on port {record.get('port')}",
                "score": record.get("score"),
                "src_ip": "n/a",
                "dst_ip": record.get("host"),
                "features": {
                    "port": record.get("port"),
                    "service": record.get("service"),
                    "product": record.get("product"),
                },
                "xai": {
                    "top_factors": record.get("explanation", []),
                },
                "reference": f"file:{source}",
            },
        }

        alerts.append(payload)

        with (ALERT_DIR / "alerts.jsonl").open("a", encoding="utf-8") as alert_file:
            alert_file.write(json.dumps(payload) + "\n")

        audit_entry = {
            "timestamp": _utc_timestamp(),
            "source": str(source),
            "payload": payload,
        }
        with (AUDIT_DIR / "audit.jsonl").open("a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(audit_entry) + "\n")

    return alerts


def _utc_timestamp() -> str:
    """Return an ISO formatted UTC timestamp."""

    return __import__("datetime").datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def ship_to_wazuh(alerts: list[dict]) -> None:
    if not alerts:
        return
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for alert in alerts:
        wire = f"TRUSTED_AI_SOC {json.dumps(alert, separators=(',', ':'))}"
        sock.sendto(wire.encode(), (SYSLOG_HOST, SYSLOG_PORT))
    sock.close()


def process_once() -> None:
    for scan in load_scans():
        alerts = parse_scan(scan)
        scored = score(alerts)
        payloads = write_alerts(scored, scan)
        ship_to_wazuh(payloads)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Process scans once and exit")
    parser.add_argument("--demo", action="store_true", help="Send a synthetic alert")
    args = parser.parse_args()

    if args.demo:
        demo_alert = {
            "event_type": "ai_alert",
            "alert": {
                "summary": "Demo high risk SSH exposed",
                "score": 0.95,
                "src_ip": "203.0.113.5",
                "dst_ip": "192.168.1.10",
                "features": {"port": 22, "service": "ssh"},
                "xai": {"top_factors": ["sensitive_port", "internet_exposed"]},
                "reference": "demo",
            },
        }
        ship_to_wazuh([demo_alert])
        return

    process_once()
    if args.once:
        return

    # In production you would add a filesystem watcher or scheduler


if __name__ == "__main__":
    main()
