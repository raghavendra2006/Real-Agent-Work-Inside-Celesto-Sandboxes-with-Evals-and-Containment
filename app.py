"""Suspicious Package Detonator — FastAPI control-plane API.

Serves:
- GET  /health            → 200 {"status":"ok"}
- GET  /api/runs           → JSON array of all runs
- POST /api/runs           → Create/update a run record
- GET  /reports/*          → Static report files
"""

from __future__ import annotations

import json
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import psycopg
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://celesto:celesto@ledger:5432/celesto")
API_PORT = int(os.getenv("API_PORT", "8080"))
REPORTS_DIR = Path(__file__).resolve().parent / "reports"

VALID_STATES = frozenset({
    "created", "ready", "running", "succeeded", "failed", "deleted",
    "mid_task_failure", "resumed", "rolled_back", "fresh_start",
})
SANDBOX_NAME_RE = re.compile(r"^sbx-[a-z0-9]{8,}$")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class RunCreate(BaseModel):
    run_id: str
    sandbox_name: str
    problem_id: str = "package-detonation"
    state: str = "created"
    execution_target: str = "celesto_sandbox"
    boot_to_ready_s: float | None = None
    wall_clock_s: float | None = None
    cost_usd: float | None = None
    verdict: str | None = None

    @field_validator("execution_target")
    @classmethod
    def check_execution_target(cls, v: str) -> str:
        if v != "celesto_sandbox":
            raise ValueError("execution_target must be 'celesto_sandbox'")
        return v

    @field_validator("state")
    @classmethod
    def check_state(cls, v: str) -> str:
        if v not in VALID_STATES:
            raise ValueError(f"state must be one of {sorted(VALID_STATES)}")
        return v

    @field_validator("sandbox_name")
    @classmethod
    def check_sandbox_name(cls, v: str) -> str:
        if not SANDBOX_NAME_RE.match(v):
            raise ValueError("sandbox_name must match ^sbx-[a-z0-9]{8,}$")
        return v


class RunResponse(BaseModel):
    id: int | None = None
    run_id: str
    sandbox_name: str
    problem_id: str
    state: str
    execution_target: str
    boot_to_ready_s: float | None = None
    wall_clock_s: float | None = None
    cost_usd: float | None = None
    verdict: str | None = None


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_conn() -> psycopg.Connection:
    return psycopg.connect(DATABASE_URL)


def db_get_all_runs() -> list[dict[str, Any]]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, run_id, sandbox_name, problem_id, state, execution_target, "
                "boot_to_ready_s, wall_clock_s, cost_usd, verdict FROM runs ORDER BY id"
            )
            cols = [desc[0] for desc in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]


def db_upsert_run(data: RunCreate) -> dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO runs (run_id, sandbox_name, problem_id, state, execution_target,
                                  boot_to_ready_s, wall_clock_s, cost_usd, verdict)
                VALUES (%(run_id)s, %(sandbox_name)s, %(problem_id)s, %(state)s,
                        %(execution_target)s, %(boot_to_ready_s)s, %(wall_clock_s)s,
                        %(cost_usd)s, %(verdict)s)
                ON CONFLICT (run_id) DO UPDATE SET
                    state = EXCLUDED.state,
                    boot_to_ready_s = COALESCE(EXCLUDED.boot_to_ready_s, runs.boot_to_ready_s),
                    wall_clock_s = COALESCE(EXCLUDED.wall_clock_s, runs.wall_clock_s),
                    cost_usd = COALESCE(EXCLUDED.cost_usd, runs.cost_usd),
                    verdict = COALESCE(EXCLUDED.verdict, runs.verdict),
                    updated_at = NOW()
                RETURNING id, run_id, sandbox_name, problem_id, state, execution_target,
                          boot_to_ready_s, wall_clock_s, cost_usd, verdict
                """,
                data.model_dump(),
            )
            cols = [desc[0] for desc in cur.description]
            row = cur.fetchone()
            conn.commit()
            return dict(zip(cols, row))


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure reports directory exists
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title="Suspicious Package Detonator",
    description="Control plane for sandboxed package analysis",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/runs")
async def list_runs():
    try:
        runs = db_get_all_runs()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database unavailable: {e}")
    return runs


@app.post("/api/runs", status_code=201)
async def create_run(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # Validate
    try:
        data = RunCreate(**body)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        result = db_upsert_run(data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    return JSONResponse(content=result, status_code=201)


@app.get("/reports/{file_path:path}")
async def serve_report(file_path: str):
    """Serve report files statically."""
    target = (REPORTS_DIR / file_path).resolve()
    # Prevent path traversal
    if not str(target).startswith(str(REPORTS_DIR.resolve())):
        raise HTTPException(status_code=403, detail="Forbidden")
    if not target.is_file():
        raise HTTPException(status_code=404, detail=f"Report not found: {file_path}")
    # Determine media type
    suffix = target.suffix.lower()
    media_types = {
        ".json": "application/json",
        ".jsonl": "application/x-ndjson",
        ".md": "text/markdown",
        ".log": "text/plain",
        ".txt": "text/plain",
    }
    return FileResponse(target, media_type=media_types.get(suffix, "application/octet-stream"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=API_PORT, reload=False)
