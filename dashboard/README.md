# PrediQL Lab

An observability + control dashboard over the pipeline's on-disk run artifacts:
list and inspect runs, watch a live run stream stage by stage, compare runs, and
read the cross-LLM reliability overlap. Read-only over `runs/`, plus a live
launcher that shells out to `predql run`.

```
dashboard/
  backend/   FastAPI — read-only over runs/, reliability overlap, live launcher (SSE)
  frontend/  Vite + React + TypeScript + Tailwind SPA
```

## Run it

```bash
./dashboard/dev.sh                 # build the UI + serve everything on :8000
# or hot-reload dev (two processes):
cd dashboard/backend && uvicorn app:app --reload --port 8000
cd dashboard/frontend && npm run dev        # :5173, proxies /api -> :8000
```

Point it at a runs directory with `PREDIQL_RUNS_ROOT=/path/to/runs` (defaults to
`runs/` at the repo root — the same place `predql run` writes).

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/stats` | aggregate KPIs |
| GET | `/api/runs` | run summaries |
| GET | `/api/runs/{id}` | full detail (step rail, coverage, findings, score, cost) |
| GET | `/api/runs/{id}/findings/{fid}` | one finding + witness |
| GET | `/api/runs/{id}/report/{name}` | a report file (html/sarif/csv/md) |
| GET | `/api/analysis/targets` | targets with completed runs + model counts (reliability picker) |
| GET | `/api/analysis/overlap?target=` | cross-LLM overlap (409 until the sweep is complete) |
| GET | `/api/live/options` | modes, families, model catalog, per-vendor key status |
| GET | `/api/live/credentials?model=` | which `.env` variables a `vendor:model` needs, and whether they are set |
| POST | `/api/live/launch` | spawn a run, or a **models × trials sweep** (`generators: [...]`, `trials: N`) — runs sequentially, one run directory per point |
| GET | `/api/live/{id}/stream` | SSE: launch + journal frames until done |
| GET | `/api/live/launches?limit=` | launch history (disk-durable across restarts) |
| POST | `/api/live/{id}/stop` | stop a running launch |

**Pages.** Experiments (KPIs + run list) · Run detail (step rail, coverage,
findings with witness/chain/judge, report links) · Live (launcher + SSE stream +
stop) · Compare (A/B table) · Reliability (cross-LLM overlap).

The backend never mutates run artifacts. The live launcher is the only control
surface; a static snapshot can serve just the read routes.

### Two things the launcher is careful about

- **The child's stdout is drained continuously.** A pipe holds ~64 KB, so a run
  that prints more than that would block forever on an unread pipe — and every
  real run does. A reader thread drains it into a bounded ring buffer that
  doubles as the log the UI shows when a run fails before writing a journal.
- **Launch records are disk-durable** (`<runs_root>/.launches/`) and reloaded by
  `live.recover()` on startup, so a backend restart keeps the history.

SSE events are `launched` · `journal` · `done` · `failed`. Note `failed` rather
than `error`: `EventSource` reserves `error` for its own transport events, which
carry no `data` and must never be JSON-parsed.
