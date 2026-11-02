"""Append-only run journal.

``journal.jsonl`` is the source of truth for a run: ``state.json`` is only a
materialised index that can always be rebuilt from it. Nothing in memory is
load-bearing, so a killed CLI or a restarted dashboard backend loses no progress
(the same contract autosec's ``live.recover()`` relies on).

Every write is a single ``json.dumps`` line followed by ``flush()``, so a process
killed mid-run leaves a readable journal whose last line is either complete or
absent — never half-parsed.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any


class Event(StrEnum):
    """Journal event kinds."""

    RUN_START = "run_start"
    STEP_START = "step_start"
    STEP_PROGRESS = "step_progress"
    STEP_FINISH = "step_finish"
    STEP_SKIP = "step_skip"
    STEP_INVALIDATE = "step_invalidate"
    RUN_FINISH = "run_finish"


class Outcome(StrEnum):
    """Terminal state of a step."""

    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class CompletedStep:
    """What resume needs to know about a step that already ran."""

    step: str
    fingerprint: str
    produces: tuple[str, ...]
    outcome: Outcome


class Journal:
    """Append-only JSONL writer/reader for one run directory."""

    FILENAME = "journal.jsonl"

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.run_dir / self.FILENAME
        self._lock = threading.Lock()
        self._seq = self._last_seq()

    def _last_seq(self) -> int:
        """Continue numbering across restarts so sequence is monotonic."""
        seq = 0
        for event in self.events():
            seq = max(seq, int(event.get("seq", 0)))
        return seq

    # -- writing ----------------------------------------------------------

    def append(self, event: Event | str, **fields: Any) -> dict[str, Any]:
        """Append one event and return the record as written."""
        with self._lock:
            self._seq += 1
            record = {"seq": self._seq, "ts": _now(), "event": str(event), **fields}
            with self.path.open("a", encoding="utf-8") as handle:
                # Heal a torn tail: a process killed mid-write leaves a partial
                # line with no newline, and appending onto it would corrupt this
                # record too. Start a fresh line instead.
                if self._ends_mid_line():
                    handle.write("\n")
                handle.write(json.dumps(record, default=str) + "\n")
                handle.flush()
            return record

    def _ends_mid_line(self) -> bool:
        """True when the journal's last byte is not a newline."""
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return False
        if size == 0:
            return False
        with self.path.open("rb") as handle:
            handle.seek(-1, 2)
            return handle.read(1) != b"\n"

    # -- reading ----------------------------------------------------------

    def events(self) -> Iterator[dict[str, Any]]:
        """Yield every well-formed event in order.

        A truncated final line (killed mid-write) is skipped rather than raising:
        a torn tail must not make an otherwise good journal unreadable.
        """
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    def completed(self) -> dict[str, CompletedStep]:
        """Map step name -> its most recent successful completion.

        Later records win, so a re-run of a step supersedes its earlier entry.
        A step that was invalidated after finishing is dropped, which is what
        makes cascade re-runs correct across a resume.
        """
        done: dict[str, CompletedStep] = {}
        for event in self.events():
            kind = event.get("event")
            step = event.get("step")
            if not step:
                continue
            if kind == Event.STEP_FINISH and event.get("outcome") == Outcome.OK:
                done[step] = CompletedStep(
                    step=step,
                    fingerprint=str(event.get("fingerprint", "")),
                    produces=tuple(event.get("produces", ())),
                    outcome=Outcome.OK,
                )
            elif kind == Event.STEP_INVALIDATE:
                done.pop(step, None)
            elif kind == Event.STEP_FINISH and event.get("outcome") == Outcome.FAILED:
                done.pop(step, None)
        return done
