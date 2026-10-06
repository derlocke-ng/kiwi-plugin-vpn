.PHONY: test lint fmt setup install
# kiwi-fox must be importable for the tests: a sibling checkout, or KIWI_FOX_SRC.
PY := $(shell [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)
export PYTHONPATH := .

setup:
	python3 -m venv .venv
	.venv/bin/python -m pip install -q --upgrade pip
	.venv/bin/python -m pip install -q pydantic pytest ruff

test:
	$(PY) -m pytest tests/unit -q

lint:
	.venv/bin/ruff check module tests
	.venv/bin/ruff format --check module tests

fmt:
	.venv/bin/ruff format module tests
	.venv/bin/ruff check --fix module tests

install:
	./install.sh install
