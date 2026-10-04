.PHONY: help up down dev test lint fmt check

CARGO ?= cargo

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

up: ## Start PostgreSQL and Redis and wait until healthy
	docker compose up -d --wait

down: ## Stop PostgreSQL and Redis (data volumes are kept)
	docker compose down

dev: ## Run the API server on 127.0.0.1:8080
	$(CARGO) run -p api-server

test: ## Run all workspace tests
	$(CARGO) test --workspace

lint: ## Run clippy with warnings as errors
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fmt: ## Format all Rust code
	$(CARGO) fmt --all

check: ## Run the full CI gate: format check, lint, test, build
	$(CARGO) fmt --all --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	$(CARGO) test --workspace
	$(CARGO) build --workspace
