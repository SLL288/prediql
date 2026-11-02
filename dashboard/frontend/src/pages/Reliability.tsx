import { useState } from "react";
import { api } from "../api";
import { Card, useAsync } from "../lib";
import { Toggle } from "../components/Toggle";
import type { Overlap, OverlapTarget } from "../types";

const ABLATION_ORDER = ["base", "scl", "aqg", "full"];
const ablationRank = (a: string) => {
  const i = ABLATION_ORDER.indexOf(a);
  return i === -1 ? ABLATION_ORDER.length : i;
};

/** Colour a Jaccard cell: agreement is good, divergence is a warning. */
function cellTone(v: number): string {
  if (v >= 0.8) return "text-pass";
  if (v >= 0.5) return "text-med";
  return "text-fail";
}

export function Reliability() {
  const targets = useAsync<OverlapTarget[]>(() => api.overlapTargets(), []);
  const [selected, setSelected] = useState<string | null>(null);
  const [abl, setAbl] = useState("all");
  const overlap = useAsync<Overlap | null>(
    () => (selected ? api.overlap(selected, abl) : Promise.resolve(null)),
    [selected, abl]
  );
  const o = overlap.data;

  const pick = (target: string) => { setSelected(target); setAbl("all"); };
  const selectedAblations = (targets.data?.find((t) => t.target === selected)?.ablations ?? [])
    .slice()
    .sort((a, b) => ablationRank(a) - ablationRank(b));
  const ablOptions = [
    { value: "all", label: "all modes" },
    ...selectedAblations.map((a) => ({ value: a, label: a })),
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Cross-LLM reliability</h2>
        <p className="mt-1 max-w-2xl text-sm text-dim">
          Does the detector measure the <em>API</em> or the <em>model</em>? This compares the
          <strong> confirmed</strong> findings each model produced for the same target. High overlap
          means the findings are a property of the API; low overlap means they track the model.
          It needs the whole sweep — every model must have a completed run before it can be computed.
        </p>
      </div>

      <Card>
        <div className="eyebrow mb-2">target</div>
        {targets.loading && <p className="text-faint">loading…</p>}
        {targets.data?.length === 0 && (
          <p className="text-faint">No completed security runs yet.</p>
        )}
        <div className="flex flex-wrap gap-2">
          {targets.data?.map((t) => (
            <button key={t.target} onClick={() => pick(t.target)}
              className={`btn ${selected === t.target ? "!border-accent !text-accent" : ""}`}>
              {t.target}
              <span className={`ml-2 text-xs ${t.ready ? "text-pass" : "text-faint"}`}>
                {t.models.length} model{t.models.length === 1 ? "" : "s"}
                {t.ready ? "" : " · sweep incomplete"}
              </span>
            </button>
          ))}
        </div>
        {selected && selectedAblations.length > 0 && (
          <div className="mt-3">
            <div className="eyebrow mb-1">ablation</div>
            <Toggle options={ablOptions} value={abl} onChange={setAbl} fill={false} />
            <p className="mt-1 text-xs text-faint">
              Scope the cross-model agreement to one ablation, or compare across all modes.
            </p>
          </div>
        )}
      </Card>

      {selected && overlap.loading && <p className="text-faint">computing…</p>}

      {o && !o.ready && (
        <Card className="border-med">
          <div className="font-semibold text-med">Sweep incomplete</div>
          <p className="mt-1 text-sm text-dim">{o.reason}</p>
          <p className="mt-2 text-sm text-dim">
            Models with a completed run: {o.models.join(", ") || "none"}. Overlap is an aggregate
            over the whole sweep, so it stays disabled until at least two models have finished.
          </p>
        </Card>
      )}

      {o && o.ready && (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Card>
              <div className="eyebrow">mean pairwise Jaccard</div>
              <div className={`text-2xl font-bold ${cellTone(o.mean_pairwise_jaccard ?? 0)}`}>
                {(o.mean_pairwise_jaccard ?? 0).toFixed(2)}
              </div>
            </Card>
            <Card>
              <div className="eyebrow">models</div>
              <div className="text-2xl font-bold">{o.n_models}</div>
            </Card>
            <Card>
              <div className="eyebrow">consensus findings</div>
              <div className="text-2xl font-bold text-pass">{o.consensus?.length ?? 0}</div>
              <div className="text-xs text-dim">found by every model</div>
            </Card>
            <Card>
              <div className="eyebrow">union</div>
              <div className="text-2xl font-bold">{o.union?.length ?? 0}</div>
              <div className="text-xs text-dim">distinct findings</div>
            </Card>
          </div>

          <Card className="overflow-x-auto">
            <div className="eyebrow mb-2">pairwise Jaccard</div>
            <table className="text-sm">
              <thead>
                <tr className="text-left text-xs text-faint">
                  <th className="py-1 pr-4"></th>
                  {o.models.map((m) => <th key={m} className="py-1 pr-4 font-mono">{m}</th>)}
                </tr>
              </thead>
              <tbody className="tabular-nums">
                {o.models.map((a) => (
                  <tr key={a} className="border-t border-hairline">
                    <td className="py-1 pr-4 font-mono text-xs text-dim">{a}</td>
                    {o.models.map((b) => {
                      const v = o.matrix?.[a]?.[b] ?? 0;
                      return (
                        <td key={b} className={`py-1 pr-4 ${a === b ? "text-faint" : cellTone(v)}`}>
                          {v.toFixed(2)}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>

          <Card>
            <div className="eyebrow mb-2">
              per finding — how many models found it
            </div>
            <p className="mb-3 text-sm text-dim">
              A finding only one model reports is the likely hallucination; the consensus core is
              what a reliable detector should converge on.
            </p>
            <div className="space-y-1">
              {Object.entries(o.found_by ?? {})
                .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
                .map(([key, count]) => {
                  const unanimous = count === o.n_models;
                  const singleton = count === 1;
                  return (
                    <div key={key} className="flex items-center gap-3 text-sm">
                      <span className={`w-14 font-mono text-xs ${
                        unanimous ? "text-pass" : singleton ? "text-fail" : "text-med"}`}>
                        {count}/{o.n_models}
                      </span>
                      <code className="text-xs">{key}</code>
                      {singleton && <span className="text-xs text-fail">singleton</span>}
                    </div>
                  );
                })}
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
