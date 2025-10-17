# TRUSTED AI SOC LITE

Prototype architecture for a Dockerised mini-SOC combining automated Nmap scans, AI/XAI analytics, Wazuh SIEM ingestion, and automated response workflows. This repository provides the scaffold to deploy the stack on a single Debian VM using Docker Compose.

## Quick start

```bash
cp .env.example .env
make up
```

Then follow the detailed instructions in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
