.PHONY: up test lint reset

up:
	uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

test:
	pytest backend/tests -v

lint:
	ruff check backend/app backend/tests

reset:
	python -c "from backend.app.store.db import clear_all; clear_all(keep_datasets=True); print('Database reset successfully.')"
