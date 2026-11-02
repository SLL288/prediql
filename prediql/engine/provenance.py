"""Provenance: which code produced a run.

A run's numbers are only citable if they can be traced back to the exact engine
code that produced them. ``code_version()`` names that code — the git commit,
plus a digest of any uncommitted change under ``prediql/`` — and it is part of
the run identity, so a code change lands in a new run directory instead of
silently overwriting (or resuming on top of) results from older code.

Stdlib only, like the rest of the engine. Outside a git checkout every value
degrades to ``"unknown"`` rather than failing the run.
"""

from __future__ import annotations

import hashlib
import platform
import subprocess
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
CODE_DIR = "prediql"
"""Only engine code decides a run's behaviour; scripts, docs, truth files and
the dashboard do not, so editing them must not fork the run identity."""

PACKAGES = ("graphql-core", "httpx", "pyyaml")


def _git(*args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", *args], cwd=REPO, capture_output=True, check=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.decode("utf-8", "replace")


def _state() -> tuple[str, tuple[str, ...], str]:
    """(commit, dirty files under prediql/, digest of those changes).

    Not cached: the dashboard is long-lived and must see the same version the
    CLI child it launches will compute."""
    commit = (_git("rev-parse", "HEAD") or "").strip() or "unknown"
    status = _git("status", "--porcelain", "--untracked-files=all", "--", CODE_DIR) or ""
    dirty = tuple(
        sorted(line[3:].strip() for line in status.splitlines()
               if line.strip() and not line.rstrip().endswith(".pyc"))
    )
    if not dirty:
        return commit, (), ""
    digest = hashlib.sha256((_git("diff", "HEAD", "--", CODE_DIR) or "").encode())
    for rel in dirty:  # untracked files are absent from `git diff`
        path = REPO / rel
        if path.is_file():
            digest.update(rel.encode())
            digest.update(path.read_bytes())
    return commit, dirty, digest.hexdigest()


def code_version() -> str:
    """``<commit12>`` for a clean tree, ``<commit12>+dirty.<digest8>`` otherwise."""
    commit, dirty, digest = _state()
    base = commit[:12]
    return f"{base}+dirty.{digest[:8]}" if dirty else base


def is_dirty() -> bool:
    return bool(_state()[1])


def collect() -> dict[str, Any]:
    """Everything needed to reproduce the run's environment, secret-free."""
    commit, dirty, _ = _state()
    packages: dict[str, str] = {}
    for name in PACKAGES:
        try:
            packages[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            packages[name] = "absent"
    return {
        "code_version": code_version(),
        "commit": commit,
        "dirty": bool(dirty),
        "dirty_files": list(dirty),
        "python": sys.version.split()[0],
        "platform": platform.platform(terse=True),
        "packages": packages,
    }


def file_sha256(path: Path | str) -> str | None:
    """Content hash of a file (e.g. a ground-truth file at scoring time)."""
    try:
        return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None
