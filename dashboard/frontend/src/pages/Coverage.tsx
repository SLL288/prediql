import { useState } from "react";
import { api } from "../api";
import { Card, useAsync } from "../lib";
import type { CoverageMatrix, CovCell, CovMetric, CovRank } from "../types";

const METRICS: { key: CovMetric; label: string; hint: string }[] = [
  { key: "element", label: "Element", hint: "distinct Type.field reached" },
  { key: "operation", label: "Operation", hint: "operations with ≥1 valid response" },
  { key: "field_path", label: "Field-path", hint: "depth-bounded field paths reached" },
];

/** Coverage value coloured by how high it is. */
function tone(v: number | null | undefined): string {
  if (v == null) return "text-faint";
  if (v >= 0.7) return "text-pass";
  if (v >= 0.4) return "text-med";
  return "text-fail";
}
function fmt(v: number | null | undefined): string {
  return v == null ? "—" : (v * 100).toFixed(1);
}
function rankVal(r: CovRank, m: CovMetric): number | null {
  return m === "element" ? r.mean_element : m === "operation" ? r.mean_operation : r.mean_field_path;
}

function MetricToggle({ metric, onChange }: { metric: CovMetric; onChange: (m: CovMetric) => void }) {
  return (
    <div className="inline-flex rounded-md border border-hairline p-0.5">
      {METRICS.map((m) => (
        <button
          key={m.key}
          onClick={() => onChange(m.key)}
          title={m.hint}
          className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
            metric === m.key ? "bg-elevated text-txt" : "text-dim hover:text-txt"
          }`}
        >
          {m.label}
        </button>
      ))}
    </div>
  );
}

function ApiTable({ apiName, models, arms, armLabels, cells, metric }: {
  apiName: string;
  models: string[];
  arms: string[];
  armLabels: Record<string, string>;
  cells: Record<string, Record<string, CovCell>>;
  metric: CovMetric;
}) {
  const rows = models.filter((m) => cells[m] && Object.keys(cells[m]).length);
  if (!rows.length) return null;
  return (
    <Card>
      <h3 className="mb-3 font-mono text-sm font-semibold text-accent">{apiName}</h3>
      <div className="-mx-1 overflow-x-auto">
        <table className="w-full min-w-[640px] border-collapse text-sm">
          <thead>
            <tr className="border-b border-hairline text-left">
              <th className="px-3 py-1.5 font-medium text-faint">model</th>
              {arms.map((a) => (
                <th key={a} className="px-3 py-1.5 text-right font-medium text-faint" title={armLabels[a]}>
                  {a}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((m) => {
              const best = arms
                .map((a) => cells[m][a]?.[metric] ?? -1)
                .reduce((mx, v) => Math.max(mx, v), -1);
              return (
                <tr key={m} className="border-b border-hairline/60">
                  <td className="px-3 py-1.5 font-mono text-[12px] text-dim">{m}</td>
                  {arms.map((a) => {
                    const c = cells[m][a];
                    const v = c?.[metric];
                    const isBest = c && v != null && v === best && best >= 0;
                    return (
                      <td key={a} className={`px-3 py-1.5 text-right font-mono text-[13px] ${tone(v)} ${isBest ? "font-semibold" : ""}`}>
                        {c ? (
                          <span title={`element ${fmt(c.element)}% · op ${fmt(c.operation)}% · field-path ${fmt(c.field_path)}% · ${c.trials} trial${c.trials === 1 ? "" : "s"}`}>
                            {fmt(v)}
                            {c.trials > 1 && <span className="ml-1 text-[10px] text-faint">×{c.trials}</span>}
                          </span>
                        ) : (
                          <span className="text-faint">{"—"}</span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function Coverage() {
  const q = useAsync<CoverageMatrix>(() => api.coverageMatrix(), []);
  const [metric, setMetric] = useState<CovMetric>("element");
  const d = q.data;
  const metricLabel = METRICS.find((m) => m.key === metric)!.label.toLowerCase();

  const ranking = d
    ? [...d.ranking].sort((a, b) => (rankVal(b, metric) ?? -1) - (rankVal(a, metric) ?? -1))
    : [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">Coverage &amp; ablation matrix</h2>
          <p className="mt-1 max-w-3xl text-sm text-dim">
            {metricLabel} coverage (%) per API, model and ablation arm, averaged over trials. Arms:{" "}
            <span className="font-mono text-xs">full</span> (bandit + value reuse),{" "}
            <span className="font-mono text-xs">no-bandit</span> (+RandomArm),{" "}
            <span className="font-mono text-xs">no-bucket</span> (+NoBucket), and the{" "}
            <span className="font-mono text-xs">fuzz4all</span> baseline. <span className="font-mono text-xs">×n</span>{" "}
            marks trials averaged; the highest arm per row is bold.
          </p>
        </div>
        <MetricToggle metric={metric} onChange={setMetric} />
      </div>

      {q.loading && <p className="text-faint">loading…</p>}
      {q.error && <p className="text-fail">{q.error}</p>}

      {d && ranking.length > 0 && (
        <Card>
          <div className="eyebrow mb-2">best model — mean {metricLabel} coverage on the full arm</div>
          <div className="-mx-1 overflow-x-auto">
            <table className="w-full min-w-[420px] border-collapse text-sm">
              <thead>
                <tr className="border-b border-hairline text-left">
                  <th className="px-3 py-1.5 font-medium text-faint">#</th>
                  <th className="px-3 py-1.5 font-medium text-faint">model</th>
                  <th className="px-3 py-1.5 text-right font-medium text-faint">mean {metricLabel}</th>
                  <th className="px-3 py-1.5 text-right font-medium text-faint" title="APIs with a full-arm run so far">APIs</th>
                </tr>
              </thead>
              <tbody>
                {ranking.map((r, i) => (
                  <tr key={r.model} className={`border-b border-hairline/60 ${i === 0 ? "font-semibold" : ""}`}>
                    <td className="px-3 py-1.5 text-faint">{i + 1}</td>
                    <td className="px-3 py-1.5 font-mono text-[12px]">{r.model}</td>
                    <td className={`px-3 py-1.5 text-right font-mono ${tone(rankVal(r, metric))}`}>{fmt(rankVal(r, metric))}</td>
                    <td className="px-3 py-1.5 text-right font-mono text-faint">{r.apis}/{d.apps.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-2 text-xs text-dim">
            Best by {metricLabel}: <span className="font-mono">{ranking[0]?.model}</span>. The APIs column shows how
            many of {d.apps.length} have completed — the ranking firms up as the campaign finishes.
          </p>
        </Card>
      )}

      {d && d.apps.map((a) => (
        <ApiTable
          key={a}
          apiName={a}
          models={d.models}
          arms={d.arms}
          armLabels={d.arm_labels}
          cells={d.cells[a] || {}}
          metric={metric}
        />
      ))}
    </div>
  );
}
