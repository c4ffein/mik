.PHONY: help lint lint-check format-check test fast-validate verify

help:
	@echo "mik - Makefile commands"
	@echo "──────────────────────────────────────────────────────"
	@echo "  make lint          - Fix linting + formatting issues with ruff"
	@echo "  make lint-check    - Check linting without fixing"
	@echo "  make format-check  - Check formatting without fixing"
	@echo "  make test          - Run the test suite"
	@echo "  make fast-validate - Run lint-check + format-check + test"
	@echo "  make verify        - Read-only gate: pinned ruff check + test suite (no env needed)"

lint:
	uv run ruff check --fix; uv run ruff format

lint-check:
	uv run ruff check --no-fix

format-check:
	uv run ruff format --check

test:
	uv run python test.py

fast-validate: lint-check format-check test

# Read-only "is this ready?" gate, shared shape across the collection. Runs ruff pinned to the
# version resolved in uv.lock (throwaway via uvx, no venv) + the stdlib-only test suite directly.
verify:
	uvx ruff@0.15.20 check --no-fix .
	python3 test.py
