import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Card, pct, useAsync } from "../lib";
import { Toggle } from "../components/Toggle";
import type { RunSummary } from "../types";

// The metrics that make a model/config A-B legible, with a hint at which
// direction is "better" so a column can be highlighted.
const METRICS: { label: string; get: (r: RunSummary) => string; num: (r: RunSummary) => number; better: "high" | "low" }[] = [
  { label: "op coverage", get: (r) => pct(r.operation_coverage), num: (r) => r.operation_coverage ?? 0, better: "high" },
  { label: "element coverage", get: (r) => pct(r.element_coverage), num: (r) => r.element_coverage ?? 0, better: "high" },
  { label: "confirmed", get: (r) => String(r.confirmed), num: (r) => r.confirmed, better: "high" },
  { label: "potential", get: (r) => String(r.potential), num: (r) => r.potential, better: "low" },
  { label: "precision", get: (r) => pct(r.precision), num: (r) => r.precision ?? 0, better: "high" },
  { label: "recall", get: (r) => pct(r.recall), num: (r) => r.recall ?? 0, better: "high" },
  { label: "tokens", get: (r) => r.tokens.toLocaleString(), num: (r) => r.tokens, better: "low" },
  { label: "cost", get: (r) => `$${r.usd}`, num: (r) => r.usd, better: "low" },
];

// The ablation ladder reads BASE -> SCL -> AQG -> full; sort and present it so.
const ABLATION_ORDER = ["base", "scl", "aqg", "full"];
const ablationRank = (a: string) => {
  const i = ABLATION_ORDER.indexOf(a);
  return i === -1 ? ABLATION_ORDER.length : i;
};
const uniq = (xs: string[]) => Array.from(new Set(xs.filter(Boolean)));
const model = (r: RunSummary) => r.providers?.generator?.split(":").pop() ?? "heuristic";

export function Compare() {
  const runs = useAsync<RunSummary[]>(() => api.runs(), []);
  const all = runs.data ?? [];

  const [apiF, setApiF] = useState("all");
  const [modelF, setModelF] = useState("all");
  const [ablF, setAblF] = useState("all");
  const [selected, setSelected] = useState<string[]>([]);

  const apis = useMemo(() => uniq(all.map((r) => r.api || r.alias || r.target)).sort(), [all]);
  const models = useMemo(() => uniq(all.map(model)).sort(), [all]);
  const ablations = useMemo(
    () => uniq(all.map((r) => r.ablation || "")).sort((a, b) => ablationRank(a) - ablationRank(b)),
    [all],
  );

  const shown = useMemo(
    () =>
      all
        .filter((r) => apiF === "all" || (r.api || r.alias || r.target) === apiF)
        .filter((r) => modelF === "all" || model(r) === modelF)
        .filter((r) => ablF === "all" || (r.ablation || "") === ablF)
        .sort(
          (a, b) =>
            (a.api || a.alias).localeCompare(b.api || b.alias) ||
            ablationRank(a.ablation || "") - ablationRank(b.ablation || "") ||
            model(a).localeCompare(model(b)),
        ),
    [all, apiF, modelF, ablF],
  );

  const toggle = (id: string) =>
    setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));
  const selectShown = () => setSelected(shown.map((r) => r.run_id));
  const clear = () => setSelected([]);
  const chosen = all.filter((r) => selected.includes(r.run_id));

  // A column reads "model · ablation"; the API is the shared axis shown once.
  const colLabel = (r: RunSummary) =>
    `${model(r)}${r.ablation ? ` · ${r.ablation}` : ""} · t${r.trial}`;

  const ablOptions = [{ value: "all", label: "all" }, ...ablations.map((a) => ({ value: a, label: a || "—" }))];

  return (
    <div className="grid gap-6 lg:grid-cols-[320px_1fr]">
      <div>
        <h2 className="mb-1 text-lg font-semibold text-txt">Compare</h2>
        <p className="mb-3 text-sm text-dim">
          Facet by API, model and ablation, then pick runs — built for the BASE→SCL→AQG→full ablation and cross-model A/B.
        </p>

        <div className="mb-3 space-y-2 rounded-lg border border-hairline bg-surface p-3">
          <label className="block">
            <span className="eyebrow mb-1 block">API</span>
            <select value={apiF} onChange={(e) => setApiF(e.target.value)} className="field w-full">
              <option value="all">all APIs</option>
              {apis.map((a) => <option key={a} value={a}>{a}</option>)}
            </select>
          </label>
          <label className="block">
            <span className="eyebrow mb-1 block">model</span>
            <select value={modelF} onChange={(e) => setModelF(e.target.value)} className="field w-full">
              <option value="all">all models</option>
              {models.map((m) => <option key={m} value={m}>{m}</option>)}
            </select>
          </label>
          {ablations.length > 0 && (
            <div>
              <span className="eyebrow mb-1 block">ablation</span>
              <Toggle options={ablOptions} value={ablF} onChange={setAblF} fill={false} />
            </div>
          )}
          <div className="flex items-center justify-between pt-1 text-[12px]">
            <span className="text-faint">{shown.length} shown · {selected.length} picked</span>
            <span className="flex gap-2">
              <button onClick={selectShown} className="text-accent hover:underline" disabled={!shown.length}>select shown</button>
              <button onClick={clear} className="text-dim hover:underline" disabled={!selected.length}>clear</button>
            </span>
          </div>
        </div>

        <div className="max-h-[56vh] space-y-1 overflow-y-auto rounded-lg border border-hairline bg-surface p-2">
          {shown.map((r) => (
            <label key={r.run_id}
              className={`flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm ${
                selected.includes(r.run_id) ? "bg-elevated" : "hover:bg-elevated"}`}>
              <input type="checkbox" checked={selected.includes(r.run_id)} onChange={() => toggle(r.run_id)} />
              <span className="min-w-0 truncate">
                <span className="font-mono text-[11px] text-dim">{r.api || r.alias || r.target}</span>{" "}
                {r.ablation && <span className="rounded bg-elevated px-1 font-mono text-[10px] text-accent">{r.ablation}</span>}{" "}
                <span className="text-faint">· {model(r)}</span>
              </span>
            </label>
          ))}
          {!shown.length && <p className="px-2 py-3 text-sm text-faint">No runs match these facets.</p>}
        </div>
      </div>

      {chosen.length < 2 ? (
        <Card className="flex items-center justify-center">
          <p className="text-faint">Select at least two runs to compare.</p>
        </Card>
      ) : (
        <Card className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-hairline text-left">
                <th className="py-2 pr-4 eyebrow">metric</th>
                {chosen.map((r) => (
                  <th key={r.run_id} className="py-2 pr-4">
                    <Link to={`/runs/${r.run_id}`} className="font-mono text-[12px] text-accent hover:underline">
                      {colLabel(r)}
                    </Link>
                    <div className="font-mono text-[10px] font-normal text-faint">{r.api || r.alias}</div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="tabular-nums">
              {METRICS.map((m) => {
                const nums = chosen.map(m.num);
                const best = m.better === "high" ? Math.max(...nums) : Math.min(...nums);
                const distinct = new Set(nums).size > 1;
                return (
                  <tr key={m.label} className="border-t border-hairline">
                    <td className="py-2 pr-4 text-dim">{m.label}</td>
                    {chosen.map((r, i) => (
                      <td key={r.run_id}
                        className={`py-2 pr-4 ${distinct && nums[i] === best ? "font-semibold text-pass" : "text-txt"}`}>
                        {m.get(r)}
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
