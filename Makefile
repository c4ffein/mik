.PHONY: help lint lint-check test fast-validate

help:
	@echo "mik - Makefile commands"
	@echo "──────────────────────────────────────────────────────"
	@echo "  make lint          - Fix linting issues with ruff"
	@echo "  make lint-check    - Check linting without fixing"
	@echo "  make test          - Run the test suite"
	@echo "  make fast-validate - Run lint-check + test"

lint:
	uv run ruff check --fix; uv run ruff format

lint-check:
	uv run ruff check --no-fix && uv run ruff format --check

test:
	uv run python test.py

fast-validate: lint-check test
