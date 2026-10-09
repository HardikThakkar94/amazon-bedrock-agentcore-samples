PY ?= python3
# Optional: path to a disclosure denylist kept OUTSIDE this repo. When set, a missing file is an error.
DENYLIST ?=

.PHONY: test demo stages check check-tags tags lint preflight

test:
	uv run pytest

demo:
	uv run python -m sec310_sample.demo all

stages:
	@for s in unsafe identity untrusted tools containment telemetry; do echo "uv run python -m sec310_sample.demo $$s"; done

check:
	$(PY) scripts/scan_identifiers.py $(if $(DENYLIST),--denylist $(DENYLIST)) .

check-tags:
	scripts/check_tags.sh

lint:
	uv run --with 'ruff==0.16.8' ruff check src tests scripts && uv run --with 'ruff==0.16.8' ruff format --check src tests scripts
	sh -n scripts/live_setup.sh scripts/live_teardown.sh scripts/check_tags.sh

preflight: test lint
	$(PY) scripts/scan_identifiers.py $(if $(DENYLIST),--denylist $(DENYLIST)) .
	scripts/check_tags.sh

tags:
	@git tag --list 'v*' -n1
