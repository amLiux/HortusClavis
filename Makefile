.PHONY: dev lint format test migrate makemigrations deps-up deps-up-all deps-down deps-down-all \
	logs logs-app grafana loki-ready compose-config preflight

# Container runtime: podman first (this repo's dev machines), docker as fallback.
RUNTIME ?= $(shell if command -v podman >/dev/null 2>&1; then echo podman; \
	elif command -v docker >/dev/null 2>&1; then echo docker; \
	else echo podman; fi)
COMPOSE ?= $(shell if command -v podman >/dev/null 2>&1; then echo podman compose; \
	elif command -v docker >/dev/null 2>&1; then echo docker compose; \
	else echo podman compose; fi)

# App port. Postgres/Redis/Grafana/Loki are offset in docker-compose.yml so a
# sibling project (DevCadence) can keep the standard 5432/6379/3000 ports.
PORT ?= 8001

# `make dev` binds 8001, the same host port as the `iam` container in
# `make deps-up-all`. Do not run both: pick one (app from your shell, or the container).
dev:
	@RUNTIME=$(RUNTIME) sh infra/preflight-ports.sh $(PORT) || { \
	  echo "       (use 'PORT=8002 make dev' to pick another port)"; exit 1; }
	uv run uvicorn app.main:app --reload --port $(PORT)

lint:
	uv run ruff check .

format:
	uv run ruff format .

test:
	uv run pytest

migrate:
	uv run alembic upgrade head

makemigrations:
	uv run alembic revision --autogenerate -m "$(message)"

# Infrastructure

# Refuse to start when something else already owns the ports, and say what to stop.
preflight:
	@RUNTIME=$(RUNTIME) sh infra/preflight-ports.sh 5433 6380

deps-up: preflight
	$(COMPOSE) up -d postgres redis

deps-up-all:
	$(COMPOSE) up -d

deps-down:
	$(COMPOSE) down

deps-down-all:
	$(COMPOSE) down -v

compose-config:
	$(COMPOSE) config

logs:
	$(COMPOSE) logs -f

logs-app:
	$(COMPOSE) logs -f iam

# Observability

grafana:
	@echo "Grafana: http://localhost:3001"
	@command -v xdg-open >/dev/null 2>&1 && xdg-open http://localhost:3001 || true

loki-ready:
	@echo "Waiting for Loki...";
	@until curl -s http://localhost:3101/ready > /dev/null 2>&1; do sleep 1; done; echo "Loki ready!"
