"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, scheduler
from .api import routes_asm, routes_core, routes_darkweb, routes_intel, routes_phishing
from .api.common import require_api_key
from .config import get_settings
from .db import create_all

WEB_DIR = Path(__file__).resolve().parent / "web"

DESCRIPTION = """
ThreatWatch is a standalone external threat-intelligence platform.

* **Dark web monitoring** - leaked credentials, infostealer logs, ransomware leak sites, pastes.
* **Threat intelligence feed** - normalised, de-duplicated, scored IOCs mapped to MITRE ATT&CK; STIX 2.1 / JSON / CSV export and a TAXII 2.1 server.
* **Anti-phishing** - look-alike domain detection and URL analysis.
* **Attack surface management** - sub-domains, services, certificates, risk report.

Authentication: when `TW_API_KEY` is configured, send it as `X-API-Key` (or `Authorization: Bearer`).
"""


def create_app(*, start_scheduler: bool | None = None) -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level.upper(),
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    run_scheduler = settings.scheduler_enabled if start_scheduler is None else start_scheduler

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        create_all()
        scheduler.recover_interrupted()
        stop = asyncio.Event()
        task = asyncio.create_task(scheduler.run_forever(stop)) if run_scheduler else None
        yield
        stop.set()
        if task:
            await asyncio.wait([task], timeout=5)

    app = FastAPI(title="ThreatWatch API", version=__version__, description=DESCRIPTION, lifespan=lifespan,
                  docs_url="/api/docs", redoc_url="/api/redoc", openapi_url="/api/openapi.json")

    auth = [Depends(require_api_key)]
    for r in (routes_core.router, routes_darkweb.router, routes_intel.router, routes_phishing.router, routes_asm.router):
        app.include_router(r, prefix="/api/v1", dependencies=auth)
    app.include_router(routes_intel.taxii, dependencies=auth)

    @app.get("/api/health", tags=["meta"])
    def health():
        return {"status": "ok", "version": __version__}

    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(WEB_DIR / "index.html")

    return app


app = create_app()
