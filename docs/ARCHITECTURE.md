# TRUSTED AI SOC LITE Architecture

This document captures the recommended single-VM architecture for the Trusted AI SOC Lite prototype that runs on a Debian host using Docker Compose.

## 1. High-level layout

```
Debian Host (8 GB RAM / 4 vCPU / ≥80 GB disk)
└─ Docker network: soc-net
   ├─ wazuh-manager        (rules/decoders, API)
   ├─ wazuh-indexer        (OpenSearch single-node backend)
   ├─ wazuh-dashboard      (Kibana-style UI)
   ├─ soc-nmap             (scheduled Nmap scans)
   ├─ soc-ai               (parsing, ML scoring, XAI)
   ├─ soc-responder        (playbooks, audit logging)
   └─ soc-ui (optional)    (Streamlit custom dashboards)
```

### Minimum sizing

| Resource | Recommendation |
| --- | --- |
| RAM | 8 GB |
| CPU | 4 cores |
| Disk | 80 GB+ persistent storage for Wazuh indexer |

Expose only what is needed: Kibana/Wazuh dashboard (5601/tcp) and optionally the Wazuh API (55000/tcp). Keep syslog ingestion on the internal Docker network.

## 2. Data flow

1. **soc-nmap** performs scheduled scans (e.g., cron or loop) using `nmap -sV -O -Pn`. Output is stored as XML under `/data/scans` on a shared volume.
2. **soc-ai** parses XML into normalized JSON assets, enriches with heuristics (service, CVE hints), performs ML scoring and XAI using SHAP/LIME, and writes alerts/audit entries to `/data/alerts` and `/data/audit`. It also forwards JSON events to Wazuh via syslog over UDP.
3. **wazuh-manager/indexer/dashboard** ingest and index the alerts using custom decoders/rules. Analysts use the dashboard to pivot on AI scores and explanations.
4. **soc-responder** monitors the alert feed and executes playbooks (e.g., block IP via UFW, send notifications). It appends every decision to the audit log.
5. **soc-ui** (optional) surfaces AI-native visualizations (feature importance trends, anomaly clusters) using Streamlit.

## 3. Repository structure

```
.
├── docker-compose.yml
├── Makefile
├── .env.example
├── docs/
│   └── ARCHITECTURE.md
├── scanner/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       └── run.py
├── ai_engine/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── run_ai.py
│       └── ship_to_wazuh.py
├── response/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── responder.py
│       └── policy.yaml
├── dashboard/ (optional)
│   ├── Dockerfile
│   └── app/
│       └── main.py
└── wazuh/
    └── config/
        ├── decoders.d/trusted_ai_soc_decoders.xml
        └── rules.d/trusted_ai_soc_rules.xml
```

Each service uses the shared `data-shared` volume mounted at `/data` to exchange artifacts.

## 4. Docker Compose overview

The Compose file spins up the Wazuh stack plus three SOC microservices. Key points:

- One user-defined network (`soc-net`).
- Named volumes for Wazuh persistence (`wazuh-data`, `indexer-data`) and a shared data volume (`data-shared`).
- Environment variables stored in `.env` (copy from `.env.example`).
- Minimal resources for app containers to leave room for Wazuh.

## 5. Wazuh integration

1. Mount custom decoder and rule XML files into `/var/ossec/etc/` using the `wazuh-data` volume.
2. After editing, restart the manager container: `docker compose restart wazuh-manager`.
3. The AI service emits syslog messages prefixed with `TRUSTED_AI_SOC` followed by a JSON payload. The decoder parses JSON; the rule enriches Wazuh events with dynamic fields and MITRE tags.

## 6. Automated response policy

`soc-responder` reads a YAML policy that maps risk scores to actions (block IP, email, ticket). Every action writes to the audit log (`/data/audit/response.jsonl`). Use cooldown windows to avoid repeated actions.

## 7. Operations checklist

1. `make up` to start the stack.
2. `make scan` to run a dry-run validation (set `SCAN_DRY_RUN=0` for a real scan).
3. `make ai` to process the latest scans manually during testing.
4. Check Wazuh dashboard at `http://<host>:5601` for AI alerts.
5. `make down` to stop; `make clean` to purge local data (demo environments only).

## 8. Hardening tips

- Keep syslog ingestion internal; restrict exposed ports via firewall.
- Add TLS certificates for Wazuh dashboard/API once the PoC is validated.
- Backup `wazuh-data` and `indexer-data` volumes before demos.
- Use Debian `ufw` on the host to restrict external access.

## 9. Future extensions

- Add OpenVAS container for deeper vulnerability scanning.
- Integrate threat intel feeds (MISP/OTX) within `soc-ai` enrichment.
- Generate scheduled PDF reports from alert summaries.
- Deploy a honeypot container to feed additional telemetry.
