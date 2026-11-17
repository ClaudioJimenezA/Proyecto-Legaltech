# LexPloit (v2.0) — Plataforma LegalTech de Compliance para Pentesting

LexPloit es una plataforma integral de informática legal y cumplimiento normativo diseñada para dotar de respaldo jurídico vinculante, trazabilidad operacional en tiempo real y certeza probatoria a las auditorías de ciberseguridad, pruebas de penetración (pentesting) y ejercicios de Red Team en Chile.

El sistema operacionaliza de manera técnica los cuatro pilares del ordenamiento jurídico chileno:
1. **Ley N° 21.459 (Delitos Informáticos)**: Evaluación técnica de las 4 causales eximentes de responsabilidad penal (Art. 2°).
2. **Ley N° 21.663 (Ley Marco de Ciberseguridad)**: Mecanismo de desconflicto espacio-temporal ($\pm 2$ min) para operadores de importancia vital antes de reportar incidentes a la ANCI.
3. **Ley N° 21.719 (Protección de Datos Personales)**: Almacenamiento cifrado en reposo, minimización y purga de evidencias técnicas.
4. **Ley N° 19.799 (Firma Electrónica)**: Inmutabilidad de los Acuerdos de Reglas de Compromiso (RoE) mediante sellado criptográfico canonical SHA-256.

---

## 🏛️ Filosofía Arquitectónica: *"Two Layers, Everywhere"*

El sistema implementa una estricta separación de dos capas en todos sus módulos:
* **Capa Pura (Pure Logic Layer)**: Módulos deterministas libres de efectos secundarios (side-effect free). Sin I/O, sin llamadas de red ni base de datos (`backend/app/compliance_engine/` y `frontend/src/lib/`).
* **Capa de Cableado (Wiring Layer)**: Módulos de infraestructura, controladores REST de FastAPI, cliente Supabase, enrutamiento y componentes React (`backend/app/api/` y `frontend/src/features/`).

---

## 📋 Requisitos Previos

* **Python 3.12+** (Recomendado en WSL Ubuntu / Linux o macOS; compatible con Windows).
* **Node.js 18+** y npm.
* **Proyecto en Supabase** (PostgreSQL 15+ con RLS y Storage activado).

---

## ⚙️ Configuración de Variables de Entorno

Antes de iniciar los servidores, asegúrate de que ambos entornos tengan su archivo `.env` configurado:

### 1. Backend (`backend/.env`)
Crea o edita `backend/.env` (puedes guiarte con `backend/.env.example`):
```env
SUPABASE_URL=https://<tu-proyecto>.supabase.co
SUPABASE_SECRET_KEY=sb_secret_<tu_secret_key>
JWT_SECRET=<tu_jwt_secret_de_supabase_o_generado>
ALLOWED_ORIGINS=http://localhost:5173,https://<tu-app>.vercel.app
```

### 2. Frontend (`frontend/.env`)
Crea o edita `frontend/.env` (puedes guiarte con `frontend/.env.example`):
```env
VITE_SUPABASE_URL=https://<tu-proyecto>.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY=sb_publishable_<tu_publishable_key>
VITE_API_URL=http://localhost:8000
```

---

## 🚀 Cómo Levantar el Proyecto en Local

### Opción 1: Con Makefile (Recomendado para WSL / Linux / Git Bash)

Desde la raíz del proyecto:

```bash
# 1. Instalar dependencias completas (Backend + Frontend)
make install

# 2. Levantar ambos servidores en simultáneo
make run
```

Si prefieres levantarlos en terminales separadas:
* **Terminal 1 (Backend):** `make run-backend`
* **Terminal 2 (Frontend):** `make run-frontend`

---

### Opción 2: Manual paso a paso

#### Terminal 1 — Backend (FastAPI)

* **En WSL Ubuntu / Linux / macOS:**
  ```bash
  cd backend
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -r requirements.txt
  uvicorn app.main:app --reload --port 8000
  ```

* **En Windows (PowerShell):**
  ```powershell
  cd backend
  python -m venv .venv
  .\.venv\Scripts\Activate.ps1
  pip install -r requirements.txt
  uvicorn app.main:app --reload --port 8000
  ```

> 🌐 Backend API disponible en: [http://localhost:8000](http://localhost:8000)  
> 📖 Documentación interactiva Swagger: [http://localhost:8000/docs](http://localhost:8000/docs)

#### Terminal 2 — Frontend (React 19 + Vite)

```bash
cd frontend
npm install
npm run dev
```

> 💻 Aplicación Web disponible en: [http://localhost:5173](http://localhost:5173)

---

## 🧪 Ejecución de Pruebas (Tier 1)

El aseguramiento de calidad valida los algoritmos matemáticos y deterministas de la Capa Pura:

```bash
# Ejecutar todas las pruebas (Backend + Frontend)
make test

# O ejecutar por separado:
make test-backend   # pytest en backend/tests
make test-frontend  # vitest en frontend
```

---

## 📂 Estructura General del Repositorio

```
.
├── backend/
│   ├── api/
│   │   └── index.py               # Entrypoint Serverless para Vercel (@vercel/python)
│   ├── app/
│   │   ├── api/v1/endpoints/      # Controladores REST (auth, roe, logger, deconfliction)
│   │   ├── compliance_engine/     # CAPA PURA: Reglas Ley 21.459, Desconflicto, SHA-256
│   │   ├── core/                  # Configuración, seguridad y cliente Supabase
│   │   ├── schemas/               # Contratos estrictos Pydantic v2
│   │   ├── serializers/           # Motor documental PDF y estándar CSAF 2.0
│   │   └── main.py                # Instancia principal FastAPI y CORS
│   ├── tests/                     # Suite de pruebas automatizadas Tier 1 (Pytest)
│   ├── requirements.txt
│   └── vercel.json                # Configuración de despliegue en Vercel
├── frontend/
│   ├── src/
│   │   ├── features/              # Dominios modulares: auth, roe, live_logger, vulns
│   │   ├── lib/                   # CAPA PURA: Calculador CVSS, validadores de red, WebCrypto
│   │   ├── routes/                # Enrutador con guardias por rol
│   │   ├── services/              # Cliente @supabase/supabase-js
│   │   └── shared/                # Componentes UI transversales
│   ├── package.json
│   └── vite.config.js
├── supabase/
│   ├── migrations/                # Scripts DDL reproducibles con RLS
│   └── schema.sql                 # Esquema activo de base de datos
├── Makefile                       # Automatización de tareas de compilación y ejecución
└── README.md
```
