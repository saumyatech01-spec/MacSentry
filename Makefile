# MacSentry — developer convenience targets
# Usage: make <target>

.PHONY: install install-ui start-flask start-ai start-ui start test help

# ── Python deps ──────────────────────────────────────────────────────────────
install:
	pip install -r requirements.txt

# ── UI deps ───────────────────────────────────────────────────────────────────
install-ui:
	cd ui/react-dashboard && npm install

# ── Servers ───────────────────────────────────────────────────────────────────

## Start the legacy Flask dashboard (port 5001)
start-flask:
	python3 ui/web_dashboard.py

## Start the FastAPI AI-suggestion microservice (port 5002)
## Run this in a SEPARATE terminal before clicking "Get AI Suggestion"
start-ai:
	uvicorn api.main:app --port 5002 --reload

## Start the Vite React dev server (port 5173)
## Proxies /api/ai-suggestion → :5002 and /api → :5001 automatically
start-ui:
	cd ui/react-dashboard && npm run dev

## Start all three servers in parallel (requires GNU make + background jobs)
start:
	$(MAKE) start-flask &
	$(MAKE) start-ai &
	$(MAKE) start-ui

# ── Tests ────────────────────────────────────────────────────────────────────
test:
	python3 -m pytest tests/ -v

# ── Help ─────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "MacSentry — available targets:"
	@echo "  make install       Install Python dependencies"
	@echo "  make install-ui    Install React/Node dependencies"
	@echo "  make start-flask   Start legacy Flask dashboard on :5001"
	@echo "  make start-ai      Start FastAPI AI service on :5002  <-- run this!"
	@echo "  make start-ui      Start Vite dev server on :5173"
	@echo "  make start         Start all three servers in parallel"
	@echo "  make test          Run pytest test suite"
	@echo ""
