.PHONY: up down logs scan ai responder demo clean status

up:
docker compose up -d

status:
docker compose ps

logs:
docker compose logs -f --tail=200

scan:
docker compose exec -e SCAN_DRY_RUN=1 soc-nmap python -m app.run --once
docker compose exec soc-nmap python -m app.run --once
docker compose exec soc-nmap ls -1 /data/scans | tail -n5

ai:
docker compose exec soc-ai python -m app.run_ai --once

responder:
docker compose exec soc-responder python -m app.responder --dry-run

demo:
docker compose exec soc-ai python -m app.ship_to_wazuh --demo

down:
docker compose down

clean:
rm -rf data/*
