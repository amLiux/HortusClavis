.PHONY: dev lint format test migrate makemigrations deps-up deps-down logs logs-app logs-grafana

dev:
	uv run uvicorn app.main:app --reload

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

deps-up:
	docker compose up -d

deps-up-all:
	docker compose up -d --profile all

deps-down:
	docker compose down

deps-down-all:
	docker compose down -v

logs:
	docker compose logs -f

logs-app:
	docker compose logs -f iam

# Observability

grafana:
	open http://localhost:3000

loki-ready:
	@echo "Waiting for Loki...";
	@until curl -s http://localhost:3100/ready > /dev/null 2>&1; do sleep 1; done; echo "Loki ready!"
