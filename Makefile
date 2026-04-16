PROJECT := cti-graph
VERSION ?= $(shell git describe --tags 2>/dev/null || echo "dev")

.PHONY: test lint format build clean serve

test:
	uv run pytest tests/ -v

lint:
	uv run ruff check src/ tests/
	uv run ruff format --check src/ tests/

format:
	uv run ruff check --fix src/ tests/
	uv run ruff format src/ tests/

build:
	uv build --out-dir dist/

clean:
	rm -rf dist/ .pytest_cache/ .coverage htmlcov/ .ruff_cache/

serve:
	uv run cti-graph serve
