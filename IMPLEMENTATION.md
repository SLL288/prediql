# Implementation status

Code for the design in [`docs/`](docs/). This file tracks **what is built and
validated** versus what is still specification. Milestones follow
[`docs/08-implementation-plan.md`](docs/08-implementation-plan.md).

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest tests/ -q          # 201 tests
.venv/bin/python -m prediql.cli steps        # list steps and modes
.venv/bin/python -m prediql.cli run --target <url> --mode coverage --rounds 2 --requests 4
.venv/bin/python -m prediql.cli show <run_id>
```

## Status

| Milestone | State | Evidence |
|---|---|---|
| **M0 — Skeleton & contracts** | **done** | 13 engine tests: plan resolution, resume, cascade invalidation, crash verdicts, two runs in one process |
| **M1 — Providers & generation** | **mostly done** | Provider gateway + role routing + cache (17 tests); heuristic generator; **LLM generator not yet wired into `cover`** |
| M2 — Security + oracle | not started | `probe`/`adjudicate` steps unimplemented |
| **M3 — Scoring + ground truth** | **done** | `score` step; ground-truth load/validate/certify; P/R/F1 with negative contracts + coverage-conditioned recall; partial scoring; 18 new tests |
| **M4 — Chains (IDOR/UAF)** | **done** | `plan_chains` + `execute_chains`; disclosure oracle; 12 new tests incl. a public-read false-positive guard |
| **M5 — Reporting + dashboard** | **done** | report step (HTML/SARIF/CSV/MD) + LLM judge (live-verified); FastAPI backend + React/Vite/Tailwind SPA (8 backend tests, frontend builds clean) |
| **M6 — GraphQL depth** | **done** | LLM action-label resolver, ensemble judging, large-schema prioritization — all live-verified with Z.ai. No REST: this is a GraphQL fuzzer. |

## Layout

```
prediql/
  engine/          orchestration — stdlib only, no third-party imports
    config.py        immutable RunConfig (replaces v1's mutable Config singleton)
    context.py       RunContext + on-disk ArtifactStore
    stepgraph.py     Step, registry, MODES, resolve(), cascade invalidation
    orchestrator.py  the driver: resume, journal, per-step verdicts
    journal.py       append-only JSONL, crash-safe
    budget.py        BudgetLedger + the context-compression ladder
    limiter.py       three independent concurrency semaphores
    steps/           one module per step
  model/           schema, response-grounded coverage, dependency graph, objects bucket
  generation/      Thompson bandit, query builder, candidate generators
  providers/       Provider interface, OpenAI-compatible, echo, cache, role router
  targets/         GraphQL HTTP adapter, replay adapter, success oracle
tests/
  unit/            per-module tests
  golden/          end-to-end runs against a recorded API (no network)
```

## What the design documents claim, and where it is enforced

| Requirement | Implementation | Test |
|---|---|---|
| No mutable globals; runs share a process | `RunConfig` frozen, `RunContext` threaded | `test_two_runs_share_a_process_without_sharing_state` |
| Resumable at step granularity | journal + fingerprint skip | `test_resume_skips_completed_steps` |
| Re-running a step re-runs its dependents | `dependents()` + `--force-step` | `test_force_step_reruns_dependents_even_when_output_identical` |
| Coverage first, then security, same run | `run_id` excludes mode | `test_run_id_is_stable_across_modes_so_steps_compose` |
| Response-grounded coverage | `model/coverage.py` | `test_requested_but_null_field_is_not_covered` |
| Reward is not "HTTP 200" | `targets/base.is_success` + `cover` | `test_errored_operation_is_not_counted_as_covered` |
| Hierarchical bandit prior | `generation/bandit.py` | `test_hierarchical_prior_warm_starts_an_unseen_operation` |
| Any provider, routed per role | `providers/router.py` | `test_each_role_reaches_its_own_provider` |
| Budget compresses rather than truncates | `budget.CompressionLevel` ladder | `test_budget_pressure_raises_the_compression_level` |
| Identical prompts never paid for twice | `providers/cache.py` | `test_cache_persists_across_router_instances` |

## Measured result: the heuristic baseline

Live run against `countries.trevorblades.com/graphql`, `--mode coverage --rounds 3
--requests 4 --depth 3`, **zero LLM calls**. Three defects were found *by running it*,
and each is now a regression test:

| Fix | Operation coverage | Field coverage |
|---|---|---|
| initial | 3/6 (50%) | 11.2% |
| schema-guided bucket + return-type argument rule | 4/6 (67%) | 12.9% |
| exact-before-fuzzy resolution; omit unfillable optional args | **6/6 (100%)** | **16.8%** |

The three defects were real and would have skewed any evaluation built on them:

1. **The objects bucket filed resources under the response key** (`continents`)
   rather than the schema type (`Continent`), so every type-keyed lookup missed.
   This would also have broken chain synthesis in M4.
2. **Argument resolution used fuzzy name matching before exact matching**, so
   `code` on an operation returning `Continent` matched `Country` by edit
   distance and fed a country code to a continent lookup.
3. **Optional `INPUT_OBJECT` arguments received scalar placeholders**, which is
   always a type error and failed the whole document. Unfillable optional
   arguments are now omitted.

This matters for the paper: 100% operation coverage on Countries with **no model
in the loop** is the honest baseline the LLM generator must be measured against.
GraphQLer reports the same 100% on this API, so the non-LLM arm is at parity
before any LLM contribution is claimed — which is exactly the comparison
the evaluation requires.

## Blockers found by audit, and fixed

A step-by-step review after the first pass found four blockers. All are fixed and
regression-tested; none remain open.

**1. Destructive operations were not gated (safety).** `allow_destructive` was
declared in `RunConfig` and documented in docs/01 §8, but no step read it —
`cover` issued `deleteCountry(countryId: "CA")` using an id *harvested from a
real earlier response*. Against a live API that deletes real data. `cover` now
requires the dependency graph and refuses any operation labelled `DELETE` unless
`--allow-destructive` is set, recording `destructive_blocked` per operation. The
gate is part of the run identity, so a safe run and a destructive one never share
a run directory.

**2. Input objects and enums were unreachable.** `from_introspection` read only
`fields`, so `INPUT_OBJECT` members (`inputFields`) and `ENUM` members
(`enumValues`) were dropped. Every mutation taking an input object or enum was
therefore unconstructible — which would have blocked M2 and M4 entirely, since
DVGA's injection surface is mutation-shaped. Both are now captured and rendered
(`createPaste(input: {content: "test"})`, `setMode(mode: PUBLIC)`).

**3. Fan-out failures were invisible.** `Limiter.map` collects exceptions
(`return_exceptions=True`) but no caller inspected the result, so an exception
while covering one operation made it look merely unreachable — a generator bug
was indistinguishable from an unresponsive API. `cover` and `validate` now record
per-unit errors and surface them in the artifact and the journal.

**4. The coverage denominator exploded.** `reachable_paths` materialised every
depth-bounded path, growing as `fan-out ^ depth`: 10.7M paths for a 100-type
schema at depth 5, and PokeAPI (~2,000 object types, 459 operations) is far
worse. Two changes: the denominator is now an exact memoised count
(`count_reachable_paths`, O(types x depth)) with membership tested per covered
path, and — more importantly — stress-testing showed the path *ratio* is the
wrong metric at scale (2 / 61,333,180 is not a useful number). Coverage now
reports three metrics, each with its denominator:

| Metric | Denominator | Use |
|---|---|---|
| `operation_coverage` | operations | GraphQLer-comparable reachability |
| `element_coverage` | distinct `Type.field` pairs | **scale-stable**; quote this on large schemas |
| `field_path_coverage` | depth-bounded paths | informative on small schemas; always reported with its depth |

On the live Countries API: 100% operation coverage, **71.4% element coverage
(25/35 `Type.field` pairs)**, 16.78% field-path coverage at depth 3.

## M2 — security scanning (done)

The iterative security core (docs/02 §3, docs/04 §4). Three layers, each tested
independently and then end-to-end:

- **Probe families** (`security/families/`) — one plugin per vulnerability class,
  each with an applicability predicate (most families skip most operations), seed
  payloads, and an evidence-directed `refine()`. Shipped: SQL injection,
  OS-command injection, path traversal, reflected XSS, introspection/field
  suggestion, and query-complexity DoS. `--families sqli` runs one in isolation,
  which is both the isolated-run mode and the RQ3 ablation.
- **The evidence oracle** (`oracle/evidence.py`) — confirmation is deterministic
  and differential, never an LLM opinion. A finding is `confirmed` only when a
  sentinel appears, a latency delta holds against the `validate` baseline, or a
  controlled difference shows. Reflection and error signatures are *signals* that
  drive refinement, never confirmations — which is what stops a read-only API
  from manufacturing findings.
- **The iterative loop** (`security/loop.py`) — per (operation, family), bounded
  and evidence-directed: seed → observe → confirm or refine, stopping on a
  confirmation, two quiet rounds, a round cap, or the payload budget. Every stop
  reason and every payload is recorded as a `ProbeResult`, so the dashboard can
  show the full fuzzing trace and reasoning.

`probe` and `adjudicate` are separate steps on purpose: `probe` gathers evidence,
`adjudicate` classifies it into ranked findings (one file per issue). So a run
can be re-adjudicated — with a different potential-policy or an LLM judge on the
residual (M4/M6) — without re-issuing a request.

### Findings validated by running it

Three refinements were driven by real runs, and each is a regression test:

1. **Sentinel vs marker.** A path-traversal probe must confirm on *file content*
   (`root:x:0:0`), not on the traversal string being echoed. The oracle separates
   the confirming `sentinel` from the reflection `marker`, and OS-command uses a
   *computed* sentinel (`echo $((91273*7))` → `638911`) so a server that merely
   echoes the input can never fake execution. This is exactly GraphQLer's
   documented path-traversal gap, closed.
2. **DoS is a signal, not a confirmation.** A live read-only run "confirmed" DoS
   on three endpoints — but that was a **measurement artifact**: three 50-alias
   queries running concurrently contended for the server and inflated each
   other's latency. Black-box timing under concurrent probing cannot distinguish
   a missing complexity limit from load, so DoS now yields a `potential` finding
   reporting the measured amplification factor, never a confirmation. Honest, not
   overclaimed (reviewer 40A-W7).
3. **The anti-'2,130 findings' invariant holds live.** `--mode security` against
   the read-only Countries API confirms **zero** injections; the only output is a
   `potential` DoS for triage. On a hand-written vulnerable API, SQLi (via
   time-based refinement), OS-command, and path-traversal are all confirmed with
   reproducible witnesses.

## M3 — scoring vs ground truth (done)

The `gtpov` pattern ported to GraphQL (docs/03). A target's ground truth is a
versioned YAML file — a header plus one contract per operation, vulnerable or
known-clean — that `score` compares findings against:

- **Negative contracts** make a false positive a *counted* number, not one
  inferred by exclusion (v1 could not do this). A confirmed finding on a
  `vulnerable: false` operation is an FP.
- **Coverage-conditioned recall** separates "never reached the operation" (a
  coverage gap) from "reached it and missed the bug" (a real miss).
- **Two matrices** — confirmed-only and confirmed+potential — quantify the
  precision cost of trusting potential findings, the direct answer to v1's
  "2,130 findings" problem.
- **Partial scoring** (`--operations a,b`) scores a chosen subset with the
  denominator stated, so "9/10, not forced 9/15" is honest.
- **Certification** content-hashes the contracts; editing after certifying
  breaks the seal (`certified -> unsealed`), so a badge cannot outlive its labels.
- **Non-gating**: a missing or malformed truth file yields a `null` score with a
  reason, never a crash. `score` reads only on-disk artifacts, so
  `predql score --run <id> --truth <file>` re-scores a finished run with no
  target and no LLM — the ground-truth iteration loop, verified to issue zero new
  requests.

A certified DVGA-style ground-truth file ships under `templates/ground_truth/`.

## M1 — LLM generation, live (done)

The gateway from the first pass is now wired end to end. Three supported
providers — **anthropic, openrouter, zai** — share one OpenAI-compatible class,
differing only in base URL, and authenticate with a single general
`LLM_API_KEY` (`.env`, gitignored; `.env.example` documents it). The provider is
chosen per role in the run config, not by which key is set.

`LLMGenerator` builds a cache-friendly prompt (stable operation schema in the
cached prefix, volatile RAG/round context last), requests structured output,
validates every returned document with a real parser, and falls back to the
heuristic builder on a dead round. Every call meters through the router into the
budget ledger by construction.

**Live-verified** against Z.ai `glm-5.3-flash` on the Countries API: `--mode
coverage --provider generator=zai:glm-5.3-flash` reached 6/6 operations (71.4%
element coverage) in 7 calls / 6,381 tokens. The model produced values the
heuristic never would — `country(code: "AD")`, `language(code: "af")` — real ISO
codes, and a resume reused the response cache for free. Run it with:

```bash
predql run --target <url> --mode coverage \
  --provider generator=zai:glm-5.3-flash --budget-tokens 200000
```

## M4 — chains: IDOR & UAF (done)

The capability v1 could not express at all (docs/02 §4), built on the graph +
objects bucket + identities that were already in place:

- **`plan_chains`** synthesizes chains from graph edges — never label matching. An
  IDOR chain exists only where a CREATE that produces an object is linked to a
  READ that consumes its id; a UAF chain only where the (create, object, delete,
  read) quadruple is present. Chains whose preconditions are unmet are returned
  **blocked** with the reason (`needs_identities`, `needs_destructive`), so they
  surface as coverage gaps rather than vanishing.
- **`execute_chains`** runs a chain step by step, carrying the created resource's
  id forward: IDOR runs CREATE under the primary identity and READ under the
  secondary; UAF runs create → delete → post-delete read under the primary.
- **The disclosure oracle** confirms only when the response **returns the
  specific tracked resource** — not merely a 200. That distinction is what stops
  a public listing (a read that succeeds but returns an unrelated resource) from
  being mis-scored as IDOR — the myNotes/myOrders false positive the paper flags,
  guarded by a test.

Chain findings flow through the same `adjudicate` → `findings` → `score` path as
single-operation findings, with a `chain` field recording the steps and their
identities.

### Validated by a stateful mock

The golden test runs a note service with a real access-control bug (any identity
reads any note) and a real phantom-resource bug (a deleted note stays readable).
IDOR and UAF are both **confirmed** with reproducible witnesses; a **secure**
variant of the same service — owner enforcement plus real deletion — confirms
**neither**, which is the differential the whole oracle rests on. Destructive
steps are gated: a UAF chain run without `--allow-destructive` never issues the
DELETE.

## M5 — reports & the LLM judge (report step done)

`full` mode now runs introspect → … → adjudicate → score → **report** in one shot.

**The `report` step** (`reporting/`) writes four formats to `runs/<id>/report/`,
each from the same findings:
- **`index.html`** — self-contained, offline, theme-aware. An executive summary,
  a severity bar, then one expandable card per finding: the class in plain
  language, why it matters, the exact request(s) that prove it, the response that
  confirms it, the chain steps for IDOR/UAF, the LLM judge's second opinion, and
  the reproduction command. A finding is understandable without reading the code.
- **`findings.sarif`** — SARIF 2.1.0: one rule per class, one result per finding,
  chains rendered as codeFlows. Loads into GitHub code scanning / VS Code as-is.
- **`findings.csv`** — one row per finding.
- **`summary.md`** — the RESULTS.md-style table (coverage, findings, P/R/F1,
  token cost), backed by findings rather than raw counts.

`report` reads only on-disk artifacts, so `report` mode re-renders a finished run
with no target and no LLM.

**The LLM judge** (`security/judge.py`) is the "use an LLM to verify" layer, done
right: the deterministic oracle is authoritative for *confirmed* findings and is
never second-guessed; the judge reviews only the **potential** residual and its
verdict is recorded *alongside* the oracle's, for triage, never as a gate. The
target's response is framed to the judge as untrusted data, never instructions.

**Live-verified with Z.ai `glm-5.3-flash`** on a vulnerable mock: 3 confirmed
injections (oracle, not judged), 7 potentials each reviewed by the judge — all
correctly called "not real" at 0.95 confidence, with genuinely sharp reasoning
(it noticed an OS-command sentinel `$((91273*7))` "appears unexpanded (no
'638911')", distinguishing reflection from execution). One reasoning-model
gotcha found and fixed: `glm-5.3-flash` spends completion tokens thinking before
emitting JSON, so a 300-token cap returned empty content — the judge and
generator budgets were raised to 1200/1500.

## M5 — dashboard (done)

The AutoSec-Lab-pattern UI over the pipeline's run artifacts (docs/05).

**Backend** (`dashboard/backend/`, FastAPI) is read-only over `runs/` plus a live
launcher:
- run summaries, full run detail (step rail, coverage, findings, score, cost),
  per-finding witness, and the four report files served directly;
- **cross-LLM overlap** (`/api/analysis/overlap`) — the reliability aggregate
  that returns **409 until every model has a completed run** for the target, then
  computes pairwise Jaccard over *confirmed* findings, the consensus core, and
  per-finding "found by k/N models" (singletons = likely hallucinations);
- a **live launcher** that shells out to `predql run` and streams the run's
  journal as Server-Sent-Events (deterministic run-dir discovery, no handshake).

**Frontend** (`dashboard/frontend/`, Vite + React + TS + Tailwind): Overview
(KPIs + run list), Run detail (animated step rail, coverage, expandable
finding cards with witness + chain + LLM-judge verdict, report links), Live
(launcher + SSE stream), Compare (baseline-vs-LLM / cross-model A/B table).

`./dashboard/dev.sh` builds the SPA and serves everything on one port.

### Two things the tests caught

- **A path-traversal bug.** `report_path("../manifest.json")` first passed my
  check because the resolved path still sat inside the *run* directory — it only
  escaped the *report* subdir. Fixed to validate against the report dir with
  `Path.relative_to`, and confirmed the URL-encoded `..%2f` variant serves the
  SPA index (Starlette normalizes it before routing), never the artifact.
- The backend read layer is fully testable over a synthetic `runs/` tree (8
  tests), exactly autosec's fixture-driven posture — no live subprocess needed.

## M6 — GraphQL depth: the action-label resolver (done)

GraphQL gives mutations no explicit CRUD semantics, so PrediQL labels them by a
name+verb heuristic and returns UNKNOWN when the name carries no recognized verb.
A missing or wrong label **suppresses a chain** — a missed CREATE kills an IDOR
chain, a missed DELETE kills a UAF chain — so `compile` now hands the *ambiguous
subset only* to the `resolver`-role LLM, in one batched call, using each
operation's name, description, arguments, and return type (introspection now
fetches field descriptions for this). Operations the model still can't classify
stay UNKNOWN; a provider-free run is unchanged and deterministic.

**Live-verified with Z.ai `glm-5.3-flash`**: on a schema of deliberately
verbless mutations it labeled `archivePost` → DELETE, `sunsetAccount` → DELETE,
and `bumpPost` → UPDATE — all correct semantic reads of the descriptions that the
verb-prefix heuristic could never make. A test confirms the payoff: a resolved
DELETE label unlocks a UAF chain the heuristic would have suppressed.

### Scope correction: this is a GraphQL fuzzer, not a general API tool

An earlier draft mis-read the brief's "cover every other API, not only DVGA" as
protocol-generality and planned a REST/OpenAPI adapter. That was wrong: the brief
meant *any GraphQL target, not just the DVGA benchmark* — which the native
graph-from-introspection already delivers. The REST adapter is dropped; the docs
(R15, P11, M6) and code comments were corrected to say "any GraphQL endpoint".
The `TargetAdapter` seam remains, but only as GraphQL transport (live HTTP vs the
replay adapter used for deterministic tests).

### Ensemble judging (done)

`--judge-samples N` runs the judge K times in parallel per potential finding and
reports the *distribution* rather than one draw: a majority verdict, the **median**
confidence, an **agreement** fraction, and the confidence **spread**. The shown
rationale is the **medoid** — the sample nearest the median — so the prose always
matches a real, internally consistent sample. This is the honest answer to
reviewer 40A-W5 (no reproducibility controls on a doubly-stochastic system): the
LLM's variance is measured and reported instead of hidden.

**Live with Z.ai `glm-5.3-flash` (×3)**: all 7 potentials on the vulnerable mock
came back `0/3 say real, agreement 1.0`. One of them is the case that justifies
the feature — **agreement 1.0 with a confidence spread of 0.9**: three samples
agreed on the verdict while disagreeing wildly (0.05–0.95) on how sure they were.
A single-shot judge would have printed one of those numbers as though it were
reliable. 21 calls / 16,037 tokens, on the potential residual only — confirmed
findings are still never sent to the judge.

### Large-schema prioritization (done)

`cover` no longer walks the schema in declaration order. `prioritize()` ranks
operations by **shape diversity** — round-robin across (action, return-type)
buckets, cheapest-first within a bucket — and `--max-operations N` caps the
attempt count. On a big API most operations are near-duplicates of a few shapes,
so schema order spends the budget on a long tail before reaching anything new
(v1 took ~80 h on PokeAPI's 459 operations). Deselected operations are recorded
with `stop_reason: not_selected`, never silently dropped.

**Live on Countries with `--max-operations 3`**: it selected `continents`,
`countries`, `languages` — three *distinct* return types — and deferred their
singular near-duplicate variants (`continent`, `country`, `language`), reaching
3/3 coverage on the capped set. A unit test asserts the core claim directly: under
a cap, prioritized order covers strictly more distinct return types than schema
order.

### Dashboard fixes

An audit of the dashboard found four real bugs, all fixed and regression-tested
(28 backend tests):

1. **A subprocess pipe deadlock — the serious one.** The launcher opened the
   child's stdout as a `PIPE` and never read it. A pipe holds ~64 KB, so any run
   printing more than that blocked forever on its next write; every real run
   does. Confirmed by reproducing it (a child writing 512 KB hung indefinitely).
   Fixed with a reader thread that drains stdout into a bounded ring buffer,
   which also became the log the UI shows when a run dies before writing a
   journal. A test now launches a child that writes 800 KB and asserts it exits.
2. **An operator-precedence bug in the live stream view.** `a ?? b != null ? x : y`
   parses as `(a ?? (b != null)) ? x : y`, so the stream printed
   `covered=undefined` instead of the step note. Replaced with an explicit
   per-event formatter.
3. **`EventSource` error handling.** The client listened for a named `error`
   event and JSON-parsed it — but `error` is reserved by `EventSource` for
   transport failures, which carry no `data`. The server now emits `failed`, and
   the client uses `onerror` only for disconnects.
4. **Launch history lost on restart** (in-memory only) and `sys.path` grown on
   every call. Launches are now disk-durable under `<runs_root>/.launches/` and
   reloaded by `live.recover()` via a lifespan handler (also migrated off the
   deprecated `on_event`).

Also added what the docs described but the UI lacked: a **Reliability page**
(cross-LLM overlap — Jaccard matrix, consensus core, and per-finding
"found by k/N models" with singletons flagged), a **Stop** button, and launcher
controls for `--max-operations` and `--judge-samples`.

Verified end to end by launching a **real** run through the dashboard against the
live Countries API: 13 journal frames streamed, child exited 0, stdout drained,
and the run appeared in the read API.

## Known gaps

- `cover` uses the heuristic generator; the LLM generator exists as an interface
  but is not yet implemented, so no run yet spends tokens.
- All six pipeline modes and the dashboard are implemented and tested. The
  ground-truth editor and per-run delete are not yet exposed in the UI (the read
  and launch surfaces are).
- All six milestones (M0–M6) are implemented and tested. Remaining work is
  breadth, not capability: the dashboard has no ground-truth editor or per-run
  delete, and the parity gate against v1's `RESULTS.md` corpus (docs/08 §3) has
  not been run.
- This is a GraphQL fuzzer; there is no REST/OpenAPI adapter and none is planned.
- DoS confirmation would need isolated, repeated timing measurement; today it is
  a potential with the amplification factor reported.
- The LLM judge for the ambiguous (potential) residual is not yet wired;
  `adjudicate` is deterministic-only for now.
- No dashboard.
- Optional arguments are supplied only from observed values; an operation whose
  reachability depends on guessing an optional filter stays uncovered. That is
  the gap the LLM generator is meant to close, and it is deliberately left open
  so the improvement is measurable.
