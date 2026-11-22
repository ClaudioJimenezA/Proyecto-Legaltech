"""Main API v1 router aggregating all LexPloit functional domains."""

from fastapi import APIRouter

from app.api.v1.endpoints import deconfliction, exports, logger, roe, vulnerabilities

api_router = APIRouter()
api_router.include_router(
    roe.router,
    prefix="/roe",
    tags=["Paso 1: RoE Negotiation & Sealing"],
)
api_router.include_router(
    logger.router,
    prefix="/logs",
    tags=["Paso 2: Live Assessment Logger"],
)
api_router.include_router(
    deconfliction.router,
    prefix="/deconfliction",
    tags=["Paso 2: SOC & ANCI Deconfliction"],
)
api_router.include_router(
    vulnerabilities.router,
    prefix="/vulnerabilities",
    tags=["Paso 3: Vulnerability Tracking & Retest"],
)
api_router.include_router(
    exports.router,
    prefix="/exports",
    tags=["Paso 3: ANCI Dual Exports (PDF + CSAF 2.0) & Ley 21.719 Purge"],
)
