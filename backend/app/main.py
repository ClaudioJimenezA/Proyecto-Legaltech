import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="LexPloit API",
    description="API de Informática Legal y Compliance para Pentesting (Leyes 21.459, 21.663, 21.719)",
    version="2.0.0"
)

# Orígenes permitidos: tu frontend local + el dominio de Vercel
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://lexploit-app.vercel.app",  # Cambia por la URL final que te asigne Vercel
]

# Permite agregar URLs adicionales desde el archivo .env si fuera necesario
extra_origins = os.getenv("ALLOWED_ORIGINS")
if extra_origins:
    origins.extend([o.strip() for o in extra_origins.split(",") if o.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def health_check():
    return {"status": "ok", "service": "LexPloit Backend"}