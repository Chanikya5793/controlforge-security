.PHONY: install lint typecheck test security build macos-contract cloud-verify website-verify verify verify-all

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

macos-contract:
	python tools/verify_macos_package_contract.py
	/bin/sh -n deployment/macos/build-pkg.sh
	/bin/sh -n deployment/macos/provision-system-keychain.sh
	/bin/sh -n deployment/macos/scripts/preinstall
	/bin/sh -n deployment/macos/scripts/postinstall

cloud-verify:
	cd cloud && npm run check

website-verify:
	cd website && npm run lint && npm run build

verify: lint typecheck test security build macos-contract

verify-all: verify cloud-verify website-verify
