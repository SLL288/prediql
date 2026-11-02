import { useMemo, useState } from "react";
import { api } from "../api";
import { Card, pct, useAsync } from "../lib";
import { Toggle } from "../components/Toggle";
import type { RunSummary } from "../types";

// Baseline tools, in the order the paper reports them; PrediQL is appended as
// the system column.
const TOOLS = ["zap", "burp", "evomaster", "graphqler", "fuzz4all"] as const;
const TOOL_LABEL: Record<string, string> = {
  zap: "ZAP", burp: "Burp", evomaster: "EvoMaster", graphqler: "GraphQLer", fuzz4all: "Fuzz4All",
};

const METRICS = [
  { value: "operation_coverage", label: "operation", old: true },
  { value: "element_coverage", label: "element", old: false },
  { value: "field_path_coverage", label: "field-path", old: false },
] as const;
type MetricKey = (typeof METRICS)[number]["value"];

const ABLATION_ORDER = ["base", "scl", "aqg", "full"];
const ablationRank = (a: string) => {
  const i = ABLATION_ORDER.indexOf(a);
  return i === -1 ? ABLATION_ORDER.length : i;
};
const modelOf = (r: RunSummary) => r.providers?.generator?.split(":").pop() ?? "heuristic";
const metricVal = (r: RunSummary, m: MetricKey): number | null =>
  (r[m] ?? null) as number | null;

export function Baselines() {
  const runs = useAsync<RunSummary[]>(() => api.runs(), []);
  const all = runs.data ?? [];

  const [metric, setMetric] = useState<MetricKey>("operation_coverage");
  const [ablation, setAblation] = useState("full");

  const baselines = useMemo(() => all.filter((r) => r.kind === "baseline"), [all]);
  const system = useMemo(() => all.filter((r) => r.kind !== "baseline"), [all]);

  // Rows = APIs present in either the baselines or the PrediQL runs.
  const apis = useMemo(() => {
    const s = new Set<string>();
    baselines.forEach((r) => s.add(r.alias || r.target));
    system.forEach((r) => s.add(r.api || r.alias || r.target));
    return [...s].sort();
  }, [baselines, system]);

  const ablations = useMemo(
    () => Array.from(new Set(system.map((r) => r.ablation || "").filter(Boolean)))
      .sort((a, b) => ablationRank(a) - ablationRank(b)),
    [system],
  );

  // PrediQL cell: the best model for this API+ablation on the chosen metric.
  function prediqlCell(apiName: string): { v: number | null; model: string | null } {
    const cands = system.filter(
      (r) => (r.api || r.alias) === apiName && (r.ablation || "") === ablation,
    );
    let best: { v: number; model: string } | null = null;
    for (const r of cands) {
      const v = metricVal(r, metric);
      if (v === null) continue;
      if (!best || v > best.v) best = { v, model: modelOf(r) };
    }
    return best ? { v: best.v, model: best.model } : { v: null, model: null };
  }

  function baselineCell(apiName: string, tool: string): { v: number | null; failed: boolean } {
    // A baseline may have several runs (GraphQLer: run_1..N); take the best, as
    // the PrediQL column takes the best model.
    const rs = baselines.filter((x) => (x.alias || x.target) === apiName && modelOf(x) === tool);
    if (!rs.length) return { v: null, failed: false };
    const vals = rs.map((r) => metricVal(r, metric)).filter((v): v is number => v !== null);
    if (!vals.length) {
      const failed = metric === "operation_coverage" && rs.some((r) => r.operation_coverage === null);
      return { v: null, failed };
    }
    return { v: Math.max(...vals), failed: false };
  }

  const hasGraphqler = baselines.some((r) => modelOf(r) === "graphqler");

  const activeMetric = METRICS.find((m) => m.value === metric)!;
  const newMetricNoBaseline = !activeMetric.old; // baselines have no response-grounded data

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-txt">Baselines</h2>
        <p className="mt-1 max-w-3xl text-sm text-dim">
          PrediQL against ZAP, Burp, EvoMaster and GraphQLer, per API. The <strong>operation</strong> metric is the
          node coverage reported in prior work; <strong>element</strong> and <strong>field-path</strong> are the
          response-grounded metrics computed identically for every tool — available for PrediQL now, and for a
          baseline once its queries are replayed through the same target (see note below).
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2 text-xs text-dim">
          metric
          <Toggle
            options={METRICS.map((m) => ({ value: m.value, label: m.label }))}
            value={metric} onChange={(v) => setMetric(v as MetricKey)} fill={false} />
        </div>
        {ablations.length > 0 && (
          <div className="flex items-center gap-2 text-xs text-dim">
            PrediQL mode
            <Toggle options={ablations.map((a) => ({ value: a, label: a }))}
              value={ablation} onChange={setAblation} fill={false} />
          </div>
        )}
      </div>

      <Card className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-hairline text-left">
              <th className="py-2 pr-4 eyebrow">API</th>
              {TOOLS.map((t) => <th key={t} className="py-2 pr-4 eyebrow">{TOOL_LABEL[t]}</th>)}
              <th className="py-2 pr-4 eyebrow text-accent">PrediQL · {ablation}</th>
            </tr>
          </thead>
          <tbody className="tabular-nums">
            {apis.map((apiName) => {
              const cells = TOOLS.map((t) => baselineCell(apiName, t));
              const pq = prediqlCell(apiName);
              const nums = [...cells.map((c) => c.v), pq.v].filter((v): v is number => v !== null);
              const best = nums.length ? Math.max(...nums) : null;
              const mark = (v: number | null) =>
                v !== null && best !== null && v === best && nums.length > 1;
              return (
                <tr key={apiName} className="border-t border-hairline">
                  <td className="py-2 pr-4 font-mono text-[12px] text-dim">{apiName}</td>
                  {cells.map((c, i) => (
                    <td key={TOOLS[i]} className={`py-2 pr-4 ${mark(c.v) ? "font-semibold text-pass" : "text-txt"}`}>
                      {c.failed ? <span className="text-faint">FAILED</span>
                        : c.v === null ? <span className="text-faint" title="needs a logged run">—</span>
                        : pct(c.v)}
                    </td>
                  ))}
                  <td className={`py-2 pr-4 ${mark(pq.v) ? "font-semibold text-pass" : "text-accent"}`}
                      title={pq.model ? `best model: ${pq.model}` : undefined}>
                    {pq.v === null ? <span className="text-faint">—</span> : pct(pq.v)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Card>

      {hasGraphqler && (
        <Card>
          <div className="font-semibold text-txt">Reading the GraphQLer column</div>
          <p className="mt-1 max-w-3xl text-sm text-dim">
            GraphQLer's cells are computed from its Zenodo artifact's saved responses through the <em>same</em> coverage
            code as PrediQL (best over its 5–10 runs per API). Our metric is <strong>response-grounded</strong>: an
            operation counts only if a field returns non-null data, so GraphQLer's own report (which counts any 200,
            including a null/empty body, as “covered”) reads higher. Where GraphQLer shows element 0, no query returned
            real data — only introspection did — but for different reasons, worth separating:
          </p>
          <ul className="mt-2 max-w-3xl list-disc space-y-1 pl-5 text-sm text-dim">
            <li><strong>tcgdex</strong>: zero transport errors — GraphQLer reached every operation but every query
              returned <code>null</code>/<code>[]</code>, i.e. it could not synthesise argument values that match real
              records. A genuine capability gap (what PrediQL's retrieval addresses), not a confound.</li>
            <li><strong>rickandmorty</strong>: 270/309 responses were <code>500 Internal Server Error</code> from the
              public API at capture time — a measurement confound, not a fair reflection of GraphQLer.</li>
            <li><strong>countries</strong>: mostly rate-limit / depth-limit errors plus null/empty — also confounded.</li>
          </ul>
          <p className="mt-2 max-w-3xl text-sm text-dim">
            The clean, unconfounded baselines are <strong>user-wallet</strong> (self-hosted; GraphQLer element ≈ 0.84)
            and <strong>graphqlzero</strong> (≈ 0.58), where GraphQLer ran without transport errors.
          </p>
        </Card>
      )}
      {newMetricNoBaseline && !hasGraphqler && (
        <Card className="border-med">
          <div className="font-semibold text-med">Baseline {activeMetric.label} coverage is not computed yet</div>
          <p className="mt-1 max-w-3xl text-sm text-dim">
            The {activeMetric.label} metric is grounded in response contents, which a published percentage does not
            carry. Run the tool with response logging and fold the responses through the same coverage model the
            PrediQL runs use. Fuzz4All needs a GraphQL target adapter first. Until then these cells read “—”.
          </p>
        </Card>
      )}
      {!newMetricNoBaseline && (
        <p className="text-xs text-faint">
          ZAP, EvoMaster and GraphQLer are computed from the GraphQLer Zenodo artifact's saved responses, in the same
          metric as PrediQL (best over each tool's runs). Burp is not in that archive, so it shows operation coverage
          from an earlier operation-level run only; EvoMaster has no PokeAPI run (it failed there), shown “—”.
        </p>
      )}
    </div>
  );
}
