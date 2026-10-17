.DEFAULT_GOAL := help
.PHONY: help install dev dev-backend dev-frontend build test test-backend test-frontend lint format db-up db-down clean

SHELL := bash
UV := uv
NPM := npm

install:
	@echo "==> Installing backend dependencies with uv..."
	cd backend && $(UV) sync
	@echo "==> Installing frontend dependencies with npm..."
	cd frontend && $(NPM) install

dev-backend:
	@echo "==> Starting backend server on http://localhost:8000..."
	cd backend && $(UV) run uvicorn app:app --app-dir src --host 0.0.0.0 --port 8000 --reload

dev-frontend: 
	@echo "==> Starting frontend server on http://localhost:3000..."
	cd frontend && $(NPM) run dev

build:
	@echo "==> Building frontend..."
	cd frontend && $(NPM) run build

test-backend:
	@echo "==> Running backend tests..."
	cd backend && $(UV) run pytest

test-frontend:
	@echo "==> Checking frontend build..."
	cd frontend && $(NPM) run build

test: test-backend test-frontend 

lint:
	@echo "==> Running frontend Biome lint..."
	cd frontend && npx @biomejs/biome check src
	@echo "==> Running backend tests syntax check..."
	cd backend && $(UV) run pytest --collect-only -q

clean:
	@echo "==> Cleaning cache directories..."
	rm -rf frontend/.next frontend/node_modules/.cache
	rm -rf backend/.pytest_cache backend/**/__pycache__
