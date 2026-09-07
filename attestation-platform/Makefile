DATABASE_URL ?= postgres://localhost/attestation
PSQL := psql "$(DATABASE_URL)"
export PYTHONPATH := src

.PHONY: migrate demo test install fmt

install:
	pip install -e ".[dev]"

migrate:
	@for f in migrations/*.sql; do echo ">> $$f"; $(PSQL) -v ON_ERROR_STOP=1 -f $$f; done

demo:
	python scripts/demo_phase0.py

demo-evaluate:
	python scripts/demo_evaluate.py

demo-packet:
	python scripts/demo_packet.py

test:
	pytest -q
