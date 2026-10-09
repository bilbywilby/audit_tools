.PHONY: install test lint run clean

install:
uv pip install -e .

test:
pytest -q

run:
audit_manifest $(FILE)

clean:
rm -rf .pytest_cache .ruff_cache build dist *.egg-info
