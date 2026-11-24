"""FastAPI app: core routes (M1) + detection routes (M2) + fix routes (M3) + the static UI.

M2 and M3 never edit this file: their routers are picked up here if their modules exist.
"""

from __future__ import annotations

import importlib
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .routes_core import router as core_router

STATIC = Path(__file__).parent / "static"


def create_app() -> FastAPI:
    app = FastAPI(title="Supply Chain Guardian", docs_url="/api/docs", redoc_url=None)
    app.include_router(core_router)
    for mod in ("routes_detect", "routes_fix"):
        try:
            m = importlib.import_module(f"guardian.api.{mod}")
        except ModuleNotFoundError as e:
            if e.name != f"guardian.api.{mod}":
                raise
            continue
        if getattr(m, "router", None) is not None:
            app.include_router(m.router)

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


app = create_app()
