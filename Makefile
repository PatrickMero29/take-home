.PHONY: up down status check test browser-test verify-login export-ca

up:
	docker compose up --build --wait idp sp-a sp-b

down:
	docker compose down

status:
	docker compose ps

check:
	uv run ruff check src tests migrations
	uv run ruff format --check src tests migrations
	uv run mypy src tests

test:
	@test -n "$(TESTS)" || (printf '%s\n' 'Specify affected tests: make test TESTS="tests/integration/test_lifecycle.py"' >&2; exit 2)
	uv run pytest $(TESTS) -q

browser-test:
	uv run playwright install chromium
	uv run pytest tests/e2e -q

verify-login:
	uv run federationctl verify-login

export-ca:
	@docker compose run --rm --no-deps --entrypoint /app/.venv/bin/python bootstrap-assets -c 'import sys; sys.stdout.buffer.write(open("/state/authority/ca.crt", "rb").read())'
