env:
	uv venv

install:
	uv sync --all-extras

run:
	uv run script.py

format:
	ruff check --select I --fix .
	ruff format .

.PHONY: env install run format
.DEFAULT_GOAL := run
