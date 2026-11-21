"""VERITAS-X Application Gateway & FastAPI Entrypoint."""
import uuid
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from core.config import settings
from indexing.engine import search_engine
from vault.storage import vault
from api.routes.cases import router as cases_router
from api.routes.evidence import router as evidence_router
from api.routes.investigations import router as investigations_router
from api.routes.claims import router as claims_router
from api.routes.playbooks import router as playbooks_router
from api.routes.reports import router as reports_router
from api.routes.audit import router as audit_router

app = FastAPI(
    title="VERITAS-X Digital Forensics Platform",
    description="Offline-first, modular digital forensic intelligence and claim verification platform.",
    version=settings.app_version,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Standardized Exception Handling
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    req_id = f"req_{uuid.uuid4().hex[:8]}"
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": str(exc),
            },
            "request_id": req_id,
        },
    )

# Startup Hook
@app.on_event("startup")
def on_startup():
    search_engine.initialize_indexes()

# Health & Status API
@app.get("/api/v1/health", tags=["system"])
def health_check():
    opensearch_ok = search_engine.check_opensearch()
    return {
        "success": True,
        "data": {
            "status": "healthy",
            "app_name": settings.app_name,
            "version": settings.app_version,
            "environment": settings.environment,
            "vault_path": str(settings.vault_path),
            "opensearch_connected": opensearch_ok,
            "ai_enabled": settings.enable_ai,
        },
        "request_id": f"req_{uuid.uuid4().hex[:8]}",
    }

# Register API v1 Routers
app.include_router(cases_router, prefix="/api/v1")
app.include_router(evidence_router, prefix="/api/v1")
app.include_router(investigations_router, prefix="/api/v1")
app.include_router(claims_router, prefix="/api/v1")
app.include_router(playbooks_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")

import sys

# Locate static web assets across frozen and source runtimes
candidate_web_dirs = []
if getattr(sys, "frozen", False):
    candidate_web_dirs.append(Path(sys.executable).parent / "_internal" / "web" / "dist")
    if hasattr(sys, "_MEIPASS"):
        candidate_web_dirs.append(Path(sys._MEIPASS) / "web" / "dist")
    candidate_web_dirs.append(Path(sys.executable).parent / "web" / "dist")
candidate_web_dirs.append(Path(__file__).resolve().parent.parent / "web" / "dist")

web_dist = None
for candidate in candidate_web_dirs:
    if (candidate / "index.html").exists():
        web_dist = candidate
        break

if web_dist and web_dist.exists():
    assets_dir = web_dist / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        file_path = web_dist / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(web_dist / "index.html")
