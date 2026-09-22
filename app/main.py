"""SSL-Checker web service.

A small FastAPI app that exposes ``POST /api/check`` for querying the SSL/TLS
state of an arbitrary ``host:port``, plus a static web UI at ``/``.
"""

from __future__ import annotations

import re
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

from .checker import check

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="SSL Checker",
    description="Inspect the SSL/TLS details of any host:port.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class CheckRequest(BaseModel):
    host: str
    port: int = 443

    @field_validator("host")
    @classmethod
    def _clean_host(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("host is required")
        # Tolerate pasted URLs like "https://example.com/path?x=1".
        v = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", v)
        v = v.split("/")[0].split("@")[-1].split(":")[0]
        if not v:
            raise ValueError("host is required")
        return v

    @field_validator("port")
    @classmethod
    def _valid_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("port must be between 1 and 65535")
        return v


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/check")
def check_endpoint(req: CheckRequest) -> dict:
    """Blocking endpoint — FastAPI runs it in a threadpool automatically."""
    try:
        return check(req.host, req.port)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


app.mount("/", StaticFiles(directory=str(BASE_DIR / "static"), html=True), name="static")
