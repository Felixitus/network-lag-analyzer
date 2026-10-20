"""FastAPI-Anwendung: REST-API unter /api, Frontend als statische Dateien."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from . import dashboard, devices, incidents, sessions, system
from .security import SecurityMiddleware, SessionSigner

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))


def create_app(core) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await core.start()
        try:
            yield
        finally:
            await core.stop()

    app = FastAPI(title="Network Lag Analyzer", version=core.version, lifespan=lifespan,
                  docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
    app.state.core = core
    app.state.signer = SessionSigner(core.cfg.data_dir)
    app.add_middleware(SecurityMiddleware, core=core, signer=app.state.signer)
    for r in (dashboard.router, incidents.router, devices.router, sessions.router, system.router):
        app.include_router(r)

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"), headers={"Cache-Control": "no-cache"})

    class NoCacheStatic(StaticFiles):
        """Frontend-Dateien nie cachen – sonst läuft nach einem Update altes JS im Browser."""

        def file_response(self, *args, **kwargs) -> Response:   # type: ignore[override]
            resp = super().file_response(*args, **kwargs)
            resp.headers["Cache-Control"] = "no-cache, must-revalidate"
            return resp

    app.mount("/", NoCacheStatic(directory=FRONTEND_DIR), name="frontend")
    return app
