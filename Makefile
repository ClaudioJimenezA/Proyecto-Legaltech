BACKEND_DIR := backend
FRONTEND_DIR := frontend

# Un venv de Windows pone los ejecutables en Scripts/ y uno POSIX en bin/.
# El Makefile mezclaba las dos convenciones: `run-backend` usaba Scripts/ y
# `run` e `install-backend` seguian usando bin/, asi que `make run` fallaba en
# Windows y `make run-backend` fallaba en macOS/Linux. Se resuelve una sola vez
# aca en vez de parchear cada receta.
#
# El otro problema en Windows es el shell. `/usr/bin/env` no existe ahi, asi
# que make cae a cmd.exe y la receta de `run` revienta con ") was unexpected at
# this time": cmd no entiende el subshell POSIX. La version de GnuWin32 es Make
# 3.81, que NO soporta .SHELLFLAGS, asi que la unica forma de mantener UN solo
# juego de recetas es apuntar SHELL al bash que ya trae Git. PROGRA~1 es el
# nombre corto de "Program Files": make 3.81 no sabe citar el espacio.
ifeq ($(OS),Windows_NT)
# Git no siempre esta en el mismo sitio: 64/32 bits o instalacion por usuario.
GIT_BASH := $(firstword $(wildcard   C:/PROGRA~1/Git/bin/bash.exe   C:/PROGRA~2/Git/bin/bash.exe   $(subst \,/,$(LOCALAPPDATA))/Programs/Git/bin/bash.exe))
ifneq ($(GIT_BASH),)
SHELL := $(GIT_BASH)
endif
VENV_BIN := .venv/Scripts
# En Windows `python3` suele ser el alias de la Microsoft Store, que abre la
# tienda en vez de crear el venv.
PYTHON := python
else
SHELL := /usr/bin/env bash
VENV_BIN := .venv/bin
PYTHON := python3
endif

.PHONY: all help install install-backend install-frontend run-backend run-frontend run test test-backend test-frontend

all: run

help:
	@echo "LexPloit - Comandos disponibles:"
	@echo "  make install           - Instalar dependencias de backend y frontend"
	@echo "  make install-backend   - Crear venv e instalar dependencias Python"
	@echo "  make install-frontend  - Instalar dependencias Node.js en frontend"
	@echo "  make run-backend       - Iniciar servidor FastAPI (puerto 8000)"
	@echo "  make run-frontend      - Iniciar servidor Vite (puerto 5173)"
	@echo "  make run               - Iniciar backend y frontend en simultaneo"
	@echo "  make test-backend      - Ejecutar pruebas pytest (Tier 1)"
	@echo "  make test-frontend     - Ejecutar pruebas vitest en frontend"
	@echo "  make test              - Ejecutar todas las pruebas"
	@echo ""
	@echo "Nota: En Windows sin Git Bash, ejecutar 'make run-backend' y 'make run-frontend' en terminales separadas."

install: install-backend install-frontend

# El venv se crea solo si no existe. Recrearlo en cada `make run` fallaba con
# "Unable to copy venvlauncher.exe": si el venv esta activado en la terminal,
# python.exe esta tomado y no se puede sobrescribir.
#
# La condicion es de make, no del shell: `[` no existe en cmd.exe, y sin el bash
# de Git las recetas corren ahi. Asi `install-backend` y `run-backend` —el
# camino alternativo que sugiere `help`— funcionan igual en una maquina sin Git
# bash, que es donde se necesitan.
install-backend:
ifeq ($(wildcard $(BACKEND_DIR)/.venv),)
	$(PYTHON) -m venv $(BACKEND_DIR)/.venv
endif
	$(BACKEND_DIR)/$(VENV_BIN)/python -m pip install -r $(BACKEND_DIR)/requirements.txt

install-frontend:
	cd $(FRONTEND_DIR) && npm install

run-backend:
	cd $(BACKEND_DIR) && $(VENV_BIN)/uvicorn app.main:app --reload --port 8000

run-frontend:
	cd $(FRONTEND_DIR) && npm run dev -- --host 0.0.0.0

run: install-backend install-frontend
	@echo "Starting backend in the background..."
	(cd $(BACKEND_DIR) && $(VENV_BIN)/uvicorn app.main:app --reload --port 8000 >/dev/null 2>&1 &) ; cd $(FRONTEND_DIR) && npm run dev -- --host 0.0.0.0

test-backend:
	cd $(BACKEND_DIR) && $(VENV_BIN)/pytest tests/

test-frontend:
	cd $(FRONTEND_DIR) && npm test

test: test-backend test-frontend
