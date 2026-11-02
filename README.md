# PrediQL

An **iterative, evidence-grounded LLM fuzzer for GraphQL APIs.** It introspects a
live endpoint, builds a typed dependency graph, drives coverage with an LLM,
probes for vulnerabilities in an evidence-directed loop, synthesizes IDOR/UAF
chains, judges the ambiguous residual with an LLM, scores against a certified
ground-truth file, and renders reports — with a dashboard to launch, watch, and
compare runs.

Every confirmed finding is backed by a **deterministic evidence oracle** and a
**reproducible witness**; no finding rests on an LLM's assertion.

- **Dashboard:** [`dashboard/README.md`](dashboard/README.md)
- **Experiment results (anonymized view-only):** [OSF](https://osf.io/3fk8r/overview?view_only=1c8025e3e9ea46deaa0df4585a335441)
  — every run reported in the paper (811 runs: coverage, ablation, detection, and baselines)

---

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"          # engine + test deps

# a coverage run against any GraphQL endpoint (no LLM, deterministic)
.venv/bin/python -m prediql.cli run --target https://countries.trevorblades.com/graphql --mode coverage

# full pipeline with a real LLM generator + LLM judge, scored against ground truth
.venv/bin/python -m prediql.cli run \
  --target http://localhost:5013/graphql --alias dvga --mode full \
  --provider generator=zai:glm-5.3-flash --provider judge=zai:glm-5.3-flash \
  --truth templates/ground_truth/examples/dvga/dvga.yaml \
  --budget-usd 2

.venv/bin/python -m prediql.cli show <run_id>     # summarize a finished run
```

For LLM providers, put one key in `.env` (see [LLM providers](#llm-providers--models)).

---

## Directory structure

```
PrediQL2/
├── README.md                  ← you are here
├── pyproject.toml             engine package + `predql` console script
├── .env                       LLM_API_KEY (gitignored — never committed)
├── .env.example               the variable name, committable
│
├── prediql/                  the engine (stdlib-only core; deps only at the edges)
│   ├── cli.py                 command-line entry point
│   ├── runner.py              assembles a run: wires target + providers into a context
│   ├── engine/                orchestration — no third-party imports
│   │   ├── config.py          immutable RunConfig (target, alias, trial, strategy, budgets)
│   │   ├── context.py         RunContext + on-disk artifact store
│   │   ├── stepgraph.py       Step, registry, MODES, resolve(), cascade invalidation
│   │   ├── orchestrator.py    the driver: resume, journal, per-step verdicts
│   │   ├── journal.py         append-only journal.jsonl, crash-safe
│   │   ├── budget.py          BudgetLedger + the context-compression ladder
│   │   ├── limiter.py         three concurrency semaphores (http / llm / cpu)
│   │   └── steps/             one module per step (introspect … report)
│   ├── model/                 schema, response-grounded coverage, dependency graph, objects bucket
│   ├── generation/            Thompson bandit, query builder, generators, prioritizer, LLM resolver
│   ├── providers/             provider gateway, catalog (models.json), router, cache, .env loader
│   ├── security/              probe families, iterative loop, chains, LLM judge
│   ├── oracle/                deterministic evidence oracle + witness
│   ├── scoring/               class registry, ground-truth loader, P/R/F1 scorer, findings model
│   ├── reporting/             HTML / SARIF / CSV / summary renderers
│   └── targets/               GraphQL HTTP adapter + replay adapter (for tests)
│
├── templates/
│   ├── contracts/operation_contract.yaml       blank per-operation ground-truth template
│   └── ground_truth/
│       └── examples/dvga/dvga.yaml             a worked DVGA example
│
├── dashboard/
│   ├── dev.sh                 build the UI + serve everything on :8000
│   ├── backend/               FastAPI — read-only over runs/ + live launcher (SSE)
│   └── frontend/              Vite + React + TS + Tailwind SPA
│
├── tests/                     engine tests (unit/ + golden/)  — 201 tests
│
└── runs/                      ← RUN RESULTS ARE STORED HERE (gitignored)
    └── <run_id>/              one directory per run (see below)
```

---

## Where results are stored

Every run writes one directory under **`runs/`** (override with `--runs-root` or
`PREDIQL_RUNS_ROOT`). It is gitignored — a run can be large and contains nested
data.

The run directory name is **`<alias>__t<trial>__<hash>`**:

- **alias** — the friendly name (`--alias`, or the URL-derived slug by default),
  so runs are readable and every trial of one target groups under one name;
- **trial** — the replicate index (`--trial`, or `--trials N` for a batch), so
  running the same configuration three times gives three independent directories
  (`dvga__t1__…`, `dvga__t2__…`, `dvga__t3__…`) — the repeated trials the paper
  reports;
- **hash** — a fingerprint of the target + strategy + providers, so a genuinely
  different experiment never collides, while different *modes* of the same trial
  reuse the same directory (coverage → then security continues the same run).

```
runs/<run_id>/
├── manifest.json          target, alias, trial, mode, providers, plan, config hash
├── journal.jsonl          append-only step log — the source of truth for resume
├── state.json             artifact index (rebuilt from the journal)
├── artifacts/             one JSON per artifact: schema, graph, coverage, bucket,
│                          baseline, bandit, chains, probe_results, findings, score
├── findings/<id>.json     one file per finding, each with its reproducible witness
├── report/                index.html · findings.sarif · findings.csv · summary.md
├── score.md               human-readable P/R/F1 vs ground truth
└── llm_cache/             content-addressed LLM response cache (an identical prompt
                           is never paid for twice, within or across runs)
```

Inspect a run: `predql show <run_id>` (coverage + findings summary), or open
`runs/<run_id>/report/index.html`, or browse it in the dashboard.

---

## Ground-truth data — where to put it

Ground truth is how findings become **defensible numbers** (precision / recall /
F1). It is a versioned YAML file per target, checked in.

1. **Copy the template.** Start from
   [`templates/contracts/operation_contract.yaml`](templates/contracts/operation_contract.yaml)
   (every field documented) and the worked
   [`templates/ground_truth/examples/dvga/dvga.yaml`](templates/ground_truth/examples/dvga/dvga.yaml).

2. **Write one file per target** — a `target:` header plus one `contract` per
   operation you have a labelled opinion about, **vulnerable or known-clean**.
   Put it wherever you like (e.g. `templates/ground_truth/<slug>.yaml`); you pass
   the path explicitly.

   ```yaml
   target: { name: DVGA, slug: dvga }
   contracts:
     - operation: pastes
       vulnerable: true
       classes: [{ id: sql_injection, evidence_kind: sentinel }]
     - operation: systemHealth
       vulnerable: false          # NEGATIVE ground truth → counts false positives honestly
   ```

3. **Certify it** (stamps a content hash; editing after invalidates the seal):

   ```bash
   predql truth certify --truth templates/ground_truth/dvga.yaml
   ```

4. **Score against it** — during a run (`--truth …` enables the `score` step) or
   re-score a finished run with no target and no LLM:

   ```bash
   predql score <run_id> --truth templates/ground_truth/dvga.yaml
   predql score <run_id> --truth dvga.yaml --operations pastes,createPaste   # partial
   ```

Scoring reports two confusion matrices (confirmed-only, and confirmed+potential),
**coverage-conditioned recall** (a miss on an operation you never reached is a
coverage gap, not a detection miss), and a per-class breakdown.

---

## Running the dashboard

```bash
./dashboard/dev.sh                 # builds the UI + serves on http://localhost:8000
```

or hot-reload development (two processes):

```bash
cd dashboard/backend && uvicorn app:app --reload --port 8000
cd dashboard/frontend && npm install && npm run dev     # :5173, proxies /api → :8000
```

Point it at a runs directory with `PREDIQL_RUNS_ROOT=/path/to/runs` (defaults to
`runs/` at the repo root — where the CLI writes).

**Pages:** Experiments (KPIs + run list) · Run detail (step rail, coverage,
findings with witness/chain/judge, report links) · **Live** (launch a run and
watch it stream, with a Stop button) · Compare (baseline-vs-LLM / cross-model
A/B) · **Reliability** (cross-LLM overlap — the "does the detector measure the
API or the model?" aggregate).

**From the Live page you set** the target URL, an **alias**, the number of
**trials**, mode, rounds, requests-per-operation, max-operations, judge-samples,
the **judge model**, and the **generator sweep**.

### Running multiple models, across providers, in one launch

The generator selector is a **multi-select**: tick any number of models from any
vendors — plus `heuristic` (the zero-cost, no-LLM baseline, which belongs *in*
the sweep as the arm every LLM is measured against) — and the launcher runs the
full **models × trials** matrix.

```
3 models × 3 trials = 9 runs
```

Every point gets **its own run directory** (the provider map is part of a run's
identity), and they execute **sequentially** — concurrent runs contend for the
same target and distort the per-operation latency baselines the timing oracles
depend on. The Live page shows the sweep as a grid of `model · trial` chips and
streams whichever run is currently executing.

A **custom model** can join the sweep: expand "add a custom model", type
`vendor:model-slug` and its two prices, and add it — the price travels with it so
cost is still computed.

Once the sweep finishes, the **Reliability** page becomes available for that
target: it needs every model to have a completed run before it will compute
cross-model overlap (it returns `409` until then, rather than reporting a
partial answer).

The same sweep from the CLI is one run per invocation:

```bash
for m in zai:glm-5.3-flash anthropic:claude-haiku-4-5-20251001 heuristic; do
  for t in 1 2 3; do
    predql run --target "$URL" --alias dvga --mode full --trial "$t" \
      ${m:+--provider generator=$m}
  done
done
```

---

## LLM providers & models

Three hosted vendors share one OpenAI-compatible contract: **anthropic**,
**openrouter**, **zai** (plus local **ollama**, and **echo** for tests). One
general key authenticates all of them — the vendor is chosen per role, not by
which key is set.

Keys resolve **per vendor, with a shared fallback** — one key is enough for a
single vendor, but a cross-vendor sweep needs a key each, since a token for one
provider is not valid at another's endpoint:

```bash
# .env  (gitignored; read from the repo root regardless of your working directory)
ZAI_API_KEY=…            # name a key after the vendor it belongs to
ANTHROPIC_API_KEY=…
OPENROUTER_API_KEY=…
LLM_API_KEY=…            # optional shared fallback for vendors without their own
```

Resolution order per vendor: `<VENDOR>_API_KEY` → `LLM_API_KEY`. Prefer the
vendor-specific name: a key parked in the generic slot is offered to *every*
vendor, and one provider's token cannot authenticate at another's endpoint. The
dashboard's model list shows a **"no key"** badge and warns before launching a
sweep containing a vendor it cannot authenticate.

### Custom models and their keys

A model absent from the catalog is used by its `vendor:slug` ref:

- **at a known vendor** (e.g. `openrouter:some/new-model`) — nothing extra to do;
  it uses that vendor's key. Supply the price with `--model-price`, or in the
  dashboard's "add a custom model" panel.
- **at a new vendor** — declare its OpenAI-compatible endpoint and key in `.env`:

  ```bash
  ACME_BASE_URL=https://api.acme.example/v1
  ACME_API_KEY=…
  ```

  then use `acme:model-slug`. The dashboard checks these live and names exactly
  which variables are missing.

**Keys are never entered in the dashboard.** A credential submitted through the
UI would be passed to the run subprocess as a command-line argument, where any
local `ps` can read it. The dashboard only reports *which* variables are set and
names the missing ones; the secret stays in `.env`.

Models are catalogued in [`prediql/providers/models.json`](prediql/providers/models.json)
— **edit it freely**, it is data, not code:

| ref (`vendor:slug`) | model | $/1M in | $/1M out |
|---|---|--:|--:|
| `anthropic:claude-haiku-4-5-20251001` | Claude Haiku 4.5 | 1.00 | 5.00 |
| `openrouter:google/gemini-3.1-flash-lite` | Gemini 3.1 Flash Lite | 0.10 | 0.40 |
| `openrouter:deepseek/deepseek-v4-flash-lite` | DeepSeek v4 Flash Lite | 0.07 | 0.28 |
| `openrouter:openai/gpt-5.4-nano` | GPT-5.4 nano | 0.15 | 0.60 |
| `openrouter:meta-llama/llama-3.3-8b-instruct` | Llama 3.3 8B | 0.02 | 0.05 |
| `openrouter:qwen/qwen3-8b` | Qwen3 8B | 0.03 | 0.09 |
| `zai:glm-5.3-flash` | GLM 5.3 Flash | 0.10 | 0.30 |

Token counts are always exact; the price only affects the reported USD, so a
stale price misreports cost without affecting any result. Verify slugs and rates
against each provider's current list before relying on the cost figures. A model
absent from the catalog still runs — supply its price:

```bash
predql run --target … --provider generator=openrouter/some-new-model \
           --model-price openrouter/some-new-model=0.20,0.80
```

**Roles** (each routed to its own model): `generator` (coverage — cheap/fast),
`judge` (triages the potential residual — a stronger model), `resolver`
(disambiguates UNKNOWN mutation action labels — the ambiguous subset only).

---

## CLI reference

### `predql run` — execute a run

| Flag | Default | Meaning |
|---|---|---|
| `--target URL` | (required) | GraphQL endpoint |
| `--alias NAME` | URL slug | friendly name for the run directory |
| `--trial N` | 1 | replicate index |
| `--trials N` | — | run replicates 1..N sequentially (repeated trials) |
| `--mode M` | coverage | `coverage` · `security` · `chains` · `score` · `report` · `full` |
| `--steps a,b` | — | explicit step list (overrides the mode) |
| `--force-step S` | — | re-run S and its dependents even if unchanged |
| `--rounds N` | 3 | coverage rounds per operation |
| `--requests N` | 10 | HTTP requests per operation per round |
| `--depth D` | 5 | depth bound for the field-coverage denominator |
| `--max-operations N` | all | cap operations covered (large schemas; diverse sample first) |
| `--seed N` | 42 | RNG seed (Thompson bandit) |
| `--arms …` | — | ablation arms, e.g. `+HierMAB,+SmartRAG` |
| `--judge-samples N` | 1 | LLM-judge samples per potential (>1 = ensemble) |
| `--provider ROLE=VENDOR:MODEL` | — | provider per role (repeatable) |
| `--api-key KEY` | `.env` | override `LLM_API_KEY` |
| `--model-price V:M=IN,OUT` | catalog | price for a model absent from the catalog |
| `--identity name[:role][='Header: value']` | anon | auth profile (repeatable; ≥2 enables IDOR) |
| `--allow-destructive` | off | permit DELETE mutations (UAF chains) |
| `--budget-usd F` / `--budget-tokens N` | ∞ | spend cap (compresses context, never truncates) |
| `--max-http N` / `--max-llm N` | 8 / 4 | concurrency |
| `--request-timeout S` / `--delay-ms N` | 120 / 1 | per-request politeness |
| `--truth FILE` | — | ground-truth YAML (enables the `score` step) |
| `--json` | — | emit the report as JSON |

### Other commands

```bash
predql show <run_id> [--artifact KEY]        # summarize a run, or dump one artifact
predql score <run_id> --truth FILE [--operations a,b]   # (re)score a finished run
predql report <run_id> --format html,sarif,csv          # (re)render reports
predql truth certify --truth FILE            # stamp a ground-truth file
predql steps [--mode M]                      # list steps and modes
predql run --target URL --mode compile       # introspect + graph only, for inspection
```

### Modes

| Mode | Steps | For |
|---|---|---|
| `coverage` | introspect → compile → seed_identities → cover → validate | reachability + baselines |
| `security` | … → probe → adjudicate | single-operation vulnerability probing |
| `chains` | … → plan_chains → execute_chains → adjudicate | IDOR / UAF |
| `score` | score | (re)score a finished run against ground truth |
| `report` | report | (re)render a finished run's findings |
| `full` | introspect → … → score → report | everything |

`coverage` first, then `security` on the same target and strategy **continues the
same run directory** — a mode is which steps run now, not a different
investigation. `score` and `report` read only on-disk artifacts, so they need no
target and no LLM.

---

## Testing

```bash
.venv/bin/python -m pytest tests/ -q                       # engine — 201 tests
cd dashboard/backend && python -m pytest tests/ -q         # dashboard backend — 34 tests
cd dashboard/frontend && npm run build                     # frontend type-checks + builds
```

The security logic is regression-testable offline: golden tests run the full
pipeline against a recorded/replay target with LLM calls stubbed, so
`cover`/`probe`/`adjudicate`/chains are deterministic in CI with no network.

---

## License / authorship

Research prototype.
