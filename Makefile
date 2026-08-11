.PHONY: install lint typecheck test security build verify

install:
	python -m pip install -e '.[dev]'

lint:
	ruff check .
	ruff format --check .

typecheck:
	mypy

test:
	pytest

security:
	bandit -c pyproject.toml -r src

build:
	python -m build

verify: lint typecheck test security build
