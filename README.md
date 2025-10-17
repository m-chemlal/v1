# TRUSTED AI SOC LITE

Prototype architecture for a Dockerised mini-SOC combining automated Nmap scans, AI/XAI analytics, Wazuh SIEM ingestion, and automated response workflows. This repository provides the scaffold to deploy the stack on a single Debian VM using Docker Compose.

## Quick start

```bash
cp .env.example .env
make up
```

Then follow the detailed instructions in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Quick smoke tests

The provided `make` targets run lightweight validations without needing full
network scans:

```bash
make scan   # runs the scanner in dry-run mode and lists the output files
make ai     # parses the most recent scan and emits AI alerts
make responder  # exercises the automated responder in dry-run mode
```

To perform a real discovery scan, override the dry-run flag and adjust targets:

```bash
SCAN_DRY_RUN=0 SCAN_TARGETS="192.168.1.0/24" make scan
```

> **Note:** The scanner defaults to dry-run mode even if `SCAN_DRY_RUN` is not
> defined. This prevents long-running network probes during quick demos. Set
> `SCAN_DRY_RUN=0` (or `false`) when you are ready to execute real scans.
