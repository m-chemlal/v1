"""Utility module to send demo alerts to Wazuh."""
from __future__ import annotations

import argparse
import json
import os
import socket

SYSLOG_HOST = os.getenv("WAZUH_SYSLOG_HOST", "wazuh-manager")
SYSLOG_PORT = int(os.getenv("WAZUH_SYSLOG_PORT", "1514"))


def send_demo_alert() -> None:
    payload = {
        "event_type": "ai_alert",
        "alert": {
            "summary": "Synthetic alert for pipeline validation",
            "score": 0.9,
            "src_ip": "203.0.113.99",
            "dst_ip": "192.168.56.101",
            "features": {
                "port": 3389,
                "service": "rdp",
            },
            "xai": {
                "top_factors": ["sensitive_port"],
            },
            "reference": "demo",
        },
    }
    wire = f"TRUSTED_AI_SOC {json.dumps(payload, separators=(',', ':'))}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(wire.encode(), (SYSLOG_HOST, SYSLOG_PORT))
    sock.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", action="store_true", help="Send the demo alert")
    args = parser.parse_args()
    if args.demo:
        send_demo_alert()
    else:
        send_demo_alert()


if __name__ == "__main__":
    main()
