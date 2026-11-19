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
	@if $(RUNTIME) ps --filter "publish=$(PORT)" --format "{{.Names}}" 2>/dev/null | grep -q .; then \
	  echo "error: port $(PORT) is already taken by a container — 'make deps-up-all' runs iam there."; \
	  echo "       use 'make deps-down-all' or set PORT=8002 make dev"; \
	  exit 1; \
	fi
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
	@for port in 5433 6380; do \
	  name=$$($(RUNTIME) ps --filter "publish=$$port" --format "{{.Names}}" 2>/dev/null | head -1); \
	  if [ -n "$$name" ]; then \
	    echo "error: host port $$port is already taken by container '$$name'"; \
	    echo "       stop it first:  $(RUNTIME) stop $$name"; \
	    echo "       ports 5433/6380 are reserved for this compose stack"; \
	    exit 1; \
	  fi; \
	done
	@if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -qE ':(5433|6380) '; then \
	  echo "error: port 5433 or 6380 is in use by a non-container process"; \
	  exit 1; \
	fi

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
