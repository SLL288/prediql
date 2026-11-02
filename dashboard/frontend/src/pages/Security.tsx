import { Fragment } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Card, pct, useAsync } from "../lib";
import type { SecComparison, SecMatrix, SecModel, SecRow, SecuritySummary } from "../types";

/** A precision/recall value coloured by how good it is. */
function metricTone(v: number | null): string {
  if (v == null) return "text-faint";
  if (v >= 0.9) return "text-pass";
  if (v >= 0.6) return "text-med";
  return "text-fail";
}

/** False-positive rate: lower is better, so the scale is inverted. */
function fprTone(v: number | null): string {
  if (v == null) return "text-faint";
  if (v <= 0.05) return "text-pass";
  if (v <= 0.25) return "text-med";
  return "text-fail";
}

function Cell({ value, tone }: { value: number | null; tone: string }) {
  return <td className={`px-3 py-1.5 text-right font-mono text-[13px] ${tone}`}>{value == null ? "—" : value.toFixed(2)}</td>;
}

function Confusion({ m }: { m: SecMatrix }) {
  return (
    <span className="font-mono text-[11px] text-dim">
      <span className="text-pass">{m.tp}</span>/
      <span className={m.fp ? "text-fail" : ""}>{m.fp}</span>/
      <span className={m.fn ? "text-med" : ""}>{m.fn}</span>/
      <span>{m.tn}</span>
    </span>
  );
}

function matrixCells(m: SecMatrix) {
  return (
    <>
      <td className="px-3 py-1.5 text-right"><Confusion m={m} /></td>
      <Cell value={m.precision} tone={metricTone(m.precision)} />
      <Cell value={m.recall} tone={metricTone(m.recall)} />
      <Cell value={m.f1} tone={metricTone(m.f1)} />
      <td className={`px-3 py-1.5 text-right font-mono text-[13px] ${fprTone(m.fp_rate)}`}>
        {m.fp_rate == null ? "—" : pct(m.fp_rate)}
      </td>
    </>
  );
}

function ModelTable({ model }: { model: SecModel }) {
  return (
    <Card>
      <div className="mb-3 flex items-baseline justify-between gap-3">
        <h3 className="font-mono text-sm font-semibold text-accent">{model.model}</h3>
        <span className="text-xs text-faint">
          {model.rows.length} run{model.rows.length === 1 ? "" : "s"}
        </span>
      </div>
      <div className="-mx-1 overflow-x-auto">
        <table className="w-full min-w-[640px] border-collapse text-sm">
          <thead>
            <tr className="border-b border-hairline text-left">
              <th className="px-3 py-1.5 font-medium text-faint">app</th>
              <th className="px-3 py-1.5 text-right font-medium text-faint" title="true / false positive / false negative / true negative">
                TP/FP/FN/TN
              </th>
              <th className="px-3 py-1.5 text-right font-medium text-faint">P</th>
              <th className="px-3 py-1.5 text-right font-medium text-faint">R</th>
              <th className="px-3 py-1.5 text-right font-medium text-faint">F1</th>
              <th className="px-3 py-1.5 text-right font-medium text-faint" title="false-positive rate on labelled negatives">
                FP rate
              </th>
              <th className="px-3 py-1.5 text-right font-medium text-faint" title="with confirmed + potential findings">
                +pot P/R
              </th>
            </tr>
          </thead>
          <tbody>
            {model.rows.map((row) => (
              <Row key={row.run_id} row={row} />
            ))}
            <tr className="border-t-2 border-hairline-strong font-medium">
              <td className="px-3 py-1.5 text-faint">pooled</td>
              {matrixCells(model.aggregate)}
              <td className="px-3 py-1.5 text-right text-faint">—</td>
            </tr>
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function Row({ row }: { row: SecRow }) {
  const ph = row.post_hoc_labels.length > 0;
  return (
    <>
      <tr className="border-b border-hairline/60">
        <td className="px-3 py-1.5">
          <Link to={`/runs/${row.run_id}`} className="font-medium text-txt hover:text-accent">
            {row.app}
          </Link>
          {row.trial > 1 && <span className="ml-1 text-xs text-faint">t{row.trial}</span>}
          {row.certification !== "certified" && (
            <span className="ml-2 text-xs text-med" title="truth file not certified against the live schema">
              uncertified
            </span>
          )}
        </td>
        {matrixCells(row.confirmed)}
        <td className="px-3 py-1.5 text-right font-mono text-[12px] text-faint">
          {pct(row.with_potential.precision)}/{pct(row.with_potential.recall)}
        </td>
      </tr>
      {ph && row.without_post_hoc && (
        <tr className="border-b border-hairline/60 bg-elevated/40">
          <td className="px-3 py-1 pl-6 text-xs text-faint" title={row.post_hoc_labels.join(", ")}>
            ↳ before {row.post_hoc_labels.length} post-hoc label
            {row.post_hoc_labels.length === 1 ? "" : "s"}
          </td>
          {matrixCells(row.without_post_hoc)}
          <td className="px-3 py-1 text-right text-faint">—</td>
        </tr>
      )}
    </>
  );
}

function ComparisonTable({ c }: { c: SecComparison }) {
  const tools = [
    { name: "PrediQL", data: c.prediql },
    { name: "GraphQLer", data: c.graphqler },
  ];
  return (
    <Card>
      <div className="mb-1 flex items-baseline justify-between gap-3">
        <h3 className="font-mono text-sm font-semibold text-accent">PrediQL vs GraphQLer</h3>
        <span className="text-xs text-faint">same apps · same ground truth</span>
      </div>
      <p className="mb-3 max-w-3xl text-xs text-dim">{c.note}</p>
      <div className="-mx-1 overflow-x-auto">
        <table className="w-full min-w-[640px] border-collapse text-sm">
          <thead>
            <tr className="border-b border-hairline text-left">
              <th className="px-3 py-1.5 font-medium text-faint">tool / app</th>
              <th className="px-3 py-1.5 text-right font-medium text-faint" title="true / false positive / false negative / true negative">TP/FP/FN/TN</th>
              <th className="px-3 py-1.5 text-right font-medium text-faint">P</th>
              <th className="px-3 py-1.5 text-right font-medium text-faint">R</th>
              <th className="px-3 py-1.5 text-right font-medium text-faint">F1</th>
              <th className="px-3 py-1.5 text-right font-medium text-faint" title="false-positive rate on labelled negatives">FP rate</th>
            </tr>
          </thead>
          <tbody>
            {tools.map((t) => (
              <Fragment key={t.name}>
                {c.scored_apps.map((app) => {
                  const m = t.data.apps[app];
                  if (!m) return null;
                  return (
                    <tr key={`${t.name}-${app}`} className="border-b border-hairline/60">
                      <td className="px-3 py-1.5 text-dim">
                        <span className="text-faint">{t.name}</span> · {app}
                      </td>
                      {matrixCells(m)}
                    </tr>
                  );
                })}
                <tr key={`${t.name}-pooled`} className="border-t-2 border-hairline-strong font-medium">
                  <td className="px-3 py-1.5">{t.name} <span className="text-faint">pooled</span></td>
                  {matrixCells(t.data.aggregate)}
                </tr>
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-xs text-dim">
        GraphQLer's findings are its own confirmed detections (it has no potential tier). Scored on
        the identical operations and labels as PrediQL, so precision/recall/FP are directly
        comparable. GraphQLer's false positives are mostly IDOR/XSS/path alerts on operations that
        are not actually vulnerable (e.g. <span className="font-mono text-[11px]">myNotes::idor</span>).
      </p>
    </Card>
  );
}

export function Security() {
  const summary = useAsync<SecuritySummary>(() => api.securitySummary(), []);
  const data = summary.data;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Detection results (RQ3)</h2>
        <p className="mt-1 max-w-3xl text-sm text-dim">
          Confirmed findings scored against each app's certified ground truth: precision, recall,
          F1, and the false-positive rate on the labelled negatives. The confusion counts read
          <span className="font-mono text-xs"> TP/FP/FN/TN</span>. The detector is deterministic, so
          all evidence is oracle-confirmed; the <span className="font-mono text-xs">+pot</span>{" "}
          column shows what trusting the potential (LLM-judged) residual would cost.
        </p>
      </div>

      {summary.loading && <p className="text-faint">loading…</p>}
      {summary.error && <p className="text-fail">{summary.error}</p>}
      {data && data.run_count === 0 && (
        <Card>
          <p className="text-faint">
            No scored security runs yet. Launch one with a <span className="font-mono text-xs">--truth</span>{" "}
            file, or run <span className="font-mono text-xs">scripts/run_security_benchmark.sh</span>.
          </p>
        </Card>
      )}

      {data && data.any_post_hoc && (
        <Card className="border-med/40">
          <div className="eyebrow mb-1 text-med">held-out disclosure</div>
          <p className="text-sm text-dim">
            Some ground-truth files carry <strong>post-hoc</strong> labels — classes added after a
            run's output was seen, each verified in the target's own source (see{" "}
            <span className="font-mono text-xs">truth/CHANGELOG.md</span>). Every affected row shows
            a second line with the metrics as they stood <em>before</em> those labels, so a label
            can never quietly turn a false positive into a true positive.
          </p>
        </Card>
      )}

      {data?.models.map((model) => (
        <ModelTable key={model.model} model={model} />
      ))}

      {data?.comparison && (
        <div>
          <h2 className="mb-1 text-lg font-semibold">Baseline comparison</h2>
          <p className="mb-3 max-w-3xl text-sm text-dim">
            PrediQL against GraphQLer on the identical purpose-built apps and ground truth.
            Both tools' confirmed detections run through the same scorer.
          </p>
          <ComparisonTable c={data.comparison} />
        </div>
      )}

      {data && data.models.length > 0 && (
        <Card>
          <div className="eyebrow mb-2">reading the table</div>
          <ul className="space-y-1 text-sm text-dim">
            <li><span className="text-pass">TP</span>: a confirmed finding on a labelled-vulnerable cell.</li>
            <li><span className="text-fail">FP</span>: a confirmed finding on a labelled-clean cell. A finding on an <em>unlabelled</em> operation is reported on the run page, not counted here.</li>
            <li><span className="text-med">FN</span>: a labelled vulnerability the run did not confirm. Coverage-conditioned recall separates "never reached" from "reached and missed".</li>
            <li>FP rate is undefined (—) for an app with no labelled negatives.</li>
          </ul>
        </Card>
      )}
    </div>
  );
}
