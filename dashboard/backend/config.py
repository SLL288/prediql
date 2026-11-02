"""Dashboard backend configuration.

The backend is read-only over the pipeline's run artifacts plus a live launcher.
The runs root is resolved from ``PREDIQL_RUNS_ROOT`` (default ``runs/`` beside the
repo), so the dashboard and the CLI agree on where runs live.
"""

from __future__ import annotations

import os
from pathlib import Path

# Repo root is two levels up from this file (dashboard/backend/config.py).
REPO_ROOT = Path(__file__).resolve().parents[2]


def runs_root() -> Path:
    """Directory holding ``<run_id>/`` run artifacts."""
    return Path(os.environ.get("PREDIQL_RUNS_ROOT", REPO_ROOT / "runs"))


def frontend_dist() -> Path:
    """Built SPA, served when present (single-process deployment)."""
    return Path(__file__).resolve().parent.parent / "frontend" / "dist"
