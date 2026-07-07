# PS7 — AI-SOC.  Run `make` (or `make help`) to see all targets.
SHELL := /bin/bash
.DEFAULT_GOAL := help

VENV     := .venv
PY       := $(VENV)/bin/python
PIP      := $(VENV)/bin/pip
UVICORN  := $(VENV)/bin/uvicorn
PYTEST   := $(VENV)/bin/pytest
API_PORT := 8000
WEB_PORT := 5173
API_BASE := http://localhost:$(API_PORT)

# ---- setup ------------------------------------------------------------------

$(VENV): pyproject.toml requirements.txt
	python3 -m venv $(VENV)
	$(PIP) install -q --upgrade pip
	$(PIP) install -q -r requirements.txt
	@touch $(VENV)

frontend/node_modules: frontend/package.json
	cd frontend && npm install

.PHONY: setup
setup: $(VENV) frontend/node_modules ## Install everything (backend .venv + frontend deps)

# ---- run --------------------------------------------------------------------

.PHONY: backend
backend: $(VENV) ## Run the FastAPI backend (:8000, auto-reload)
	$(UVICORN) orchestrator.main:app --reload --port $(API_PORT)

.PHONY: frontend
frontend: frontend/node_modules ## Run the dashboard in MOCK mode — no backend needed (:5173)
	cd frontend && npm run dev -- --port $(WEB_PORT)

.PHONY: frontend-live
frontend-live: frontend/node_modules ## Run the dashboard in LIVE mode against the backend
	cd frontend && VITE_DATA_SOURCE=live VITE_API_BASE=$(API_BASE) npm run dev -- --port $(WEB_PORT)

.PHONY: dev
dev: $(VENV) frontend/node_modules ## Run backend + frontend (LIVE) together; Ctrl-C stops both
	@echo "backend  -> $(API_BASE)"
	@echo "frontend -> http://localhost:$(WEB_PORT) (live)  ·  run 'make replay' to feed the feed"
	@trap 'kill 0' EXIT INT TERM; \
	$(UVICORN) orchestrator.main:app --port $(API_PORT) & \
	( cd frontend && VITE_DATA_SOURCE=live VITE_API_BASE=$(API_BASE) npm run dev -- --port $(WEB_PORT) ) & \
	wait

# ---- feed / test ------------------------------------------------------------

define REPLAY_PY
import json, time, urllib.request as u
for e in json.load(open("data/fixtures/anomaly_events.json")):
    u.urlopen(u.Request("$(API_BASE)/events", data=json.dumps(e).encode(),
                        headers={"content-type": "application/json"}))
    print("sent", e["event_id"]); time.sleep(2)
endef
export REPLAY_PY

.PHONY: replay
replay: $(VENV) ## Feed the anomaly fixtures into a running backend (drives the live feed)
	@$(PY) -c "$$REPLAY_PY"

.PHONY: test
test: $(VENV) ## Run the backend test suite
	$(PYTEST) -q

.PHONY: test-frontend
test-frontend: frontend/node_modules ## Run the frontend unit tests
	cd frontend && npx vitest run

# ---- housekeeping -----------------------------------------------------------

.PHONY: clean
clean: ## Remove venv, node_modules, caches, runtime audit log
	rm -rf $(VENV) frontend/node_modules .pytest_cache audit_log.jsonl
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
