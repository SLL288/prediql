"""AutoSec-Lab-pattern dashboard for PrediQL.

Read-only over run artifacts (`runs.py`), a reliability aggregate (`overlap.py`),
and a live launcher that streams over SSE (`live.py`). The control surface (live
launch/stop) is separable: a static snapshot can serve only the read routes.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

import live
import overlap
import runs
import security
from config import frontend_dist

@asynccontextmanager
async def lifespan(_: FastAPI):
    """Reattach launch records on startup — nothing in memory is load-bearing."""
    live.recover()
    yield


app = FastAPI(title="PrediQL Lab", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

_MEDIA = {"html": "text/html", "sarif": "application/json",
          "csv": "text/csv", "md": "text/markdown", "json": "application/json"}


# -- read routes ------------------------------------------------------------


@app.get("/api/health")
def health() -> dict:
    return {"ok": True}


@app.get("/api/stats")
def get_stats() -> dict:
    return runs.stats()


@app.get("/api/runs")
def get_runs() -> list:
    return runs.list_runs()


@app.get("/api/runs/{run_id}")
def get_run(run_id: str) -> dict:
    detail = runs.get_run(run_id)
    if detail is None:
        raise HTTPException(404, f"no such run: {run_id}")
    return detail


@app.get("/api/runs/{run_id}/findings/{finding_id}")
def get_finding(run_id: str, finding_id: str) -> dict:
    finding = runs.get_finding(run_id, finding_id)
    if finding is None:
        raise HTTPException(404, "no such finding")
    return finding


@app.delete("/api/runs/{run_id}")
def delete_run(run_id: str) -> dict:
    """Delete a run directory. Refuses a run that is still active."""
    if live.is_run_active(run_id):
        raise HTTPException(409, "run is still active; stop it first")
    result = runs.delete_run(run_id)
    if not result["deleted"]:
        raise HTTPException(404, result["reason"])
    return result


@app.post("/api/runs/{run_id}/stop")
def stop_run(run_id: str) -> dict:
    """Stop the live launch producing this run, if any."""
    return live.stop_run(run_id)


@app.get("/api/runs/{run_id}/http-calls")
def get_http_calls(run_id: str, limit: int = 1000) -> list:
    """Query->server exchanges (empty when the run has no coverage step)."""
    return runs.http_calls(run_id, limit)


@app.get("/api/runs/{run_id}/llm-calls")
def get_llm_calls(run_id: str, limit: int = 500) -> list:
    """Per-call LLM log for a run (empty when the run used no LLM)."""
    return runs.llm_calls(run_id, limit)


@app.get("/api/runs/{run_id}/report/{name}")
def get_report(run_id: str, name: str) -> Response:
    path = runs.report_path(run_id, name)
    if path is None:
        raise HTTPException(404, "no such report file")
    ext = name.rsplit(".", 1)[-1]
    return FileResponse(path, media_type=_MEDIA.get(ext, "application/octet-stream"))


@app.post("/api/fuzz4all/launch")
def fuzz4all_launch(payload: dict) -> dict:
    """Launch the Fuzz4All-style GraphQL baseline; stream via /api/live/{id}/stream."""
    try:
        return live.launch_fuzz4all(payload)
    except KeyError as exc:
        raise HTTPException(400, f"missing field: {exc}")


@app.get("/api/security/summary")
def get_security_summary() -> dict:
    """Detection study (RQ3): P/R/F1, FP rate and per-class breakdown per backbone."""
    return security.summary()


@app.get("/api/coverage/matrix")
def get_coverage_matrix() -> dict:
    """Coverage comparison: ablation arms across every API and model, one table."""
    import coverage
    return coverage.matrix()


@app.get("/api/analysis/targets")
def get_targets() -> list:
    """Distinct targets with a completed run, for the reliability picker."""
    return overlap.targets_with_runs()


@app.get("/api/analysis/overlap")
def get_overlap(target: str, ablation: str | None = None) -> Response:
    result = overlap.overlap_for_target(target, ablation)
    if not result.get("ready"):
        # 409: the sweep is incomplete, so the aggregate cannot be computed yet.
        return JSONResponse(result, status_code=409)
    return JSONResponse(result)


# -- live control -----------------------------------------------------------


@app.get("/api/live/options")
def live_options() -> dict:
    return live.options()


@app.get("/api/live/credentials")
def live_credentials(model: str) -> dict:
    """What a `vendor:model` needs in `.env`, and whether it is already set.

    Keys are never sent *to* the API — a credential in a launch request would end
    up in the subprocess's argv, readable by any local `ps`. The dashboard only
    asks which variables are configured and names the missing ones.
    """
    return live.credentials_for(model)


@app.post("/api/live/launch")
async def live_launch(request: Request) -> dict:
    """Start a run, or a sequential batch of `trials` replicates."""
    payload = await request.json()
    try:
        return live.launch(payload)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/live/launches")
def live_launches(limit: int = 50) -> list:
    return live.list_launches(limit)


@app.get("/api/live/{launch_id}/stream")
async def live_stream(launch_id: str) -> StreamingResponse:
    return StreamingResponse(live.stream(launch_id), media_type="text/event-stream")


@app.post("/api/live/{launch_id}/stop")
def live_stop(launch_id: str) -> dict:
    return live.stop(launch_id)


@app.delete("/api/live/{launch_id}")
def live_delete(launch_id: str) -> dict:
    """Remove a launch from the queue (stop it first if it is running)."""
    result = live.delete_launch(launch_id)
    if not result["deleted"]:
        raise HTTPException(409, result["reason"])
    return result


# -- static SPA (served when built) -----------------------------------------

_dist = frontend_dist()
if _dist.exists():
    app.mount("/assets", StaticFiles(directory=_dist / "assets"), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str) -> FileResponse:
        # Serve a real file if it exists, else the SPA entry (client routing).
        candidate = _dist / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_dist / "index.html")
