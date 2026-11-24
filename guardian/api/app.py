"""FastAPI app: workspace routes + approval routes + the static UI (guardian/api/static/).

Start with `python -m guardian ui` (http://127.0.0.1:8080).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .routes_approval import router as approval_router
from .routes_workspaces import router as workspace_router

STATIC = Path(__file__).parent / "static"


def create_app() -> FastAPI:
    app = FastAPI(title="Supply Chain Guardian", docs_url="/api/docs", redoc_url=None)
    app.include_router(workspace_router)
    app.include_router(approval_router)

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


app = create_app()
