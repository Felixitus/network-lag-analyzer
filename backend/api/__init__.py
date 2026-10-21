"""FastAPI application: REST API under /api, frontend as static files."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from . import auth, dashboard, devices, dns, dns_export, incidents, sessions, system
from .security import SecurityMiddleware

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
    app.add_middleware(SecurityMiddleware, core=core)
    for r in (auth.router, dashboard.router, incidents.router, devices.router, dns.router, dns_export.router, sessions.router,
              system.router):
        app.include_router(r)

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"), headers={"Cache-Control": "no-cache"})

    class NoCacheStatic(StaticFiles):
        """Never cache frontend files - otherwise stale JS keeps running in the browser after an update."""

        def file_response(self, *args, **kwargs) -> Response:   # type: ignore[override]
            resp = super().file_response(*args, **kwargs)
            resp.headers["Cache-Control"] = "no-cache, must-revalidate"
            return resp

    app.mount("/", NoCacheStatic(directory=FRONTEND_DIR), name="frontend")
    return app
