.PHONY: help lint lint-check format-check test fast-validate

help:
	@echo "mik - Makefile commands"
	@echo "──────────────────────────────────────────────────────"
	@echo "  make lint          - Fix linting + formatting issues with ruff"
	@echo "  make lint-check    - Check linting without fixing"
	@echo "  make format-check  - Check formatting without fixing"
	@echo "  make test          - Run the test suite"
	@echo "  make fast-validate - Run lint-check + format-check + test"

lint:
	uv run ruff check --fix; uv run ruff format

lint-check:
	uv run ruff check --no-fix

format-check:
	uv run ruff format --check

test:
	uv run python test.py

fast-validate: lint-check format-check test
