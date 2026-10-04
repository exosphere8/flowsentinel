.PHONY: help up down dev test test-db lint fmt check fixtures

CARGO ?= cargo

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

up: ## Start PostgreSQL and Redis and wait until healthy
	docker compose up -d --wait

down: ## Stop PostgreSQL and Redis (data volumes are kept)
	docker compose down

dev: ## Run the API server on 127.0.0.1:8080 with settings from .env
	@test -f .env || { echo "copy .env.example to .env and set the passwords first"; exit 1; }
	set -a && . ./.env && set +a && $(CARGO) run -p api-server

test: ## Run all workspace tests (database tests skip without a server)
	$(CARGO) test --workspace

test-db: ## Run the storage and API tests against the Compose PostgreSQL
	@test -f .env || { echo "copy .env.example to .env and run make up first"; exit 1; }
	set -a && . ./.env && set +a && \
	  FLOWSENTINEL_TEST_DATABASE_URL="$$FLOWSENTINEL_DATABASE_URL" FLOWSENTINEL_REQUIRE_DB_TESTS=1 \
	  $(CARGO) test -p storage -p api-server

lint: ## Run clippy with warnings as errors
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fmt: ## Format all Rust code
	$(CARGO) fmt --all

fixtures: ## Regenerate the synthetic PCAP fixtures
	python3 scripts/generate_pcap_fixtures.py

check: ## Run the full CI gate: format check, lint, test, build
	$(CARGO) fmt --all --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	$(CARGO) test --workspace
	$(CARGO) build --workspace
