.PHONY: install lint type-check test security build clean

install:
	pip install -e ".[dev]"
	pre-commit install

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

type-check:
	mypy src/

test:
	pytest

security:
	bandit -r src/

build:
	hatch build

clean:
	rm -rf dist/ build/ .coverage htmlcov/ .pytest_cache/ .mypy_cache/
