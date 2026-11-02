PY ?= .venv/bin/python
PIP ?= .venv/bin/pip

.PHONY: install run dev test demo feeds darkweb phishing docker-build docker-up clean

install:            ## create venv and install with dev extras
	python3 -m venv .venv
	$(PIP) install -e ".[dev]"

run:                ## start the web UI + API on TW_HOST:TW_PORT (default 127.0.0.1:8000)
	$(PY) -m threatwatch serve

dev:                ## auto-reload server, scheduler off
	TW_SCHEDULER_ENABLED=false $(PY) -m threatwatch serve --reload

test:               ## run the test suite
	$(PY) -m pytest -q

demo:               ## load the fictional Acme Corp demo dataset (wipes data)
	$(PY) -m threatwatch seed-demo --reset

feeds:              ## collect all available threat-intel feeds now
	$(PY) -m threatwatch feeds

darkweb:            ## run the dark web scan for the watchlist
	$(PY) -m threatwatch darkweb

phishing:           ## run the look-alike domain scan for watchlist domains
	$(PY) -m threatwatch phishing

docker-build:
	docker compose build

docker-up:
	docker compose up -d

clean:
	rm -rf .pytest_cache build dist *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
