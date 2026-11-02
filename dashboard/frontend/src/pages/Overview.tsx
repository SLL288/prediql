import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Card, pct, statusTone, useAsync } from "../lib";
import { Toggle } from "../components/Toggle";
import type { RunSummary, Stats } from "../types";

const ABLATION_ORDER = ["base", "scl", "aqg", "full"];
const ablationRank = (a: string) => {
  const i = ABLATION_ORDER.indexOf(a);
  return i === -1 ? ABLATION_ORDER.length : i;
};
const uniq = (xs: string[]) => Array.from(new Set(xs.filter(Boolean)));
const modelOf = (r: RunSummary) => r.providers?.generator?.split(":").pop() ?? "heuristic";
const apiOf = (r: RunSummary) => r.api || r.alias || r.target;

function Kpi({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <Card>
      <div className="eyebrow">{label}</div>
      <div className="mt-1 text-2xl font-bold tabular-nums text-txt">{value}</div>
      {sub && <div className="text-xs text-dim">{sub}</div>}
    </Card>
  );
}

function RunRow({ r, onChanged }: { r: RunSummary; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [confirmDel, setConfirmDel] = useState(false);
  const active = r.active || r.status === "running";

  const stop = async () => {
    setBusy(true);
    try { await api.stopRun(r.run_id); onChanged(); } finally { setBusy(false); }
  };
  const del = async () => {
    setBusy(true);
    try { await api.deleteRun(r.run_id); onChanged(); }
    catch (e) { alert(String(e)); } finally { setBusy(false); setConfirmDel(false); }
  };

  return (
    <div className="flex items-center gap-3 rounded-lg border border-hairline bg-surface px-4 py-2.5
                    transition-colors hover:border-hairline-strong">
      <Link to={`/runs/${r.run_id}`} className="flex min-w-0 flex-1 items-center gap-3">
        <span className={`w-16 shrink-0 text-xs font-semibold ${statusTone(r.status)}`}>
          {r.status}{active && <span className="animate-pulse"> ●</span>}
        </span>
        <span className="chip shrink-0">t{r.trial}</span>
        {r.ablation
          ? <span className="chip shrink-0 !text-accent">{r.ablation}</span>
          : <span className="chip shrink-0">{r.mode}</span>}
        <span className="shrink-0 truncate font-mono text-[11px] text-dim">
          {modelOf(r)}
        </span>
        <span className="ml-auto flex shrink-0 items-center gap-4 text-sm tabular-nums">
          <span title="operation coverage" className="text-dim">{pct(r.operation_coverage)}</span>
          <span className="text-fail" title="confirmed">{r.confirmed}c</span>
          {r.potential > 0 && <span className="text-med">{r.potential}p</span>}
          <span className="text-faint">{r.tokens.toLocaleString()} tok</span>
        </span>
      </Link>
      <div className="flex shrink-0 items-center gap-1.5">
        {active
          ? <button onClick={stop} disabled={busy} className="btn-danger !px-2 !py-1 !text-[11px]">stop</button>
          : confirmDel
          ? <>
              <button onClick={del} disabled={busy} className="btn-danger !px-2 !py-1 !text-[11px]">confirm</button>
              <button onClick={() => setConfirmDel(false)} className="btn !px-2 !py-1 !text-[11px]">×</button>
            </>
          : <button onClick={() => setConfirmDel(true)} className="btn !px-2 !py-1 !text-[11px]">delete</button>}
      </div>
    </div>
  );
}

// Group runs by API (ablation variants, models and trials of one API belong
// together — how repeated trials and the ablation read). Within a
// group, order by the BASE->SCL->AQG->full ladder, then model.
function group(runs: RunSummary[]): [string, RunSummary[]][] {
  const by = new Map<string, RunSummary[]>();
  for (const r of runs) {
    const key = apiOf(r);
    (by.get(key) ?? by.set(key, []).get(key)!).push(r);
  }
  for (const rs of by.values()) {
    rs.sort((a, b) =>
      ablationRank(a.ablation || "") - ablationRank(b.ablation || "") ||
      modelOf(a).localeCompare(modelOf(b)) ||
      a.trial - b.trial);
  }
  return [...by.entries()].sort((a, b) =>
    (b[1][0].started_at ?? "").localeCompare(a[1][0].started_at ?? ""));
}

export function Overview() {
  const stats = useAsync<Stats>(() => api.stats(), []);
  const [nonce, setNonce] = useState(0);
  const runs = useAsync<RunSummary[]>(() => api.runs(), [nonce]);
  const refresh = () => setNonce((n) => n + 1);
  const all = runs.data ?? [];

  // Auto-refresh so runs launched outside the dashboard (e.g. the campaign
  // driver) appear and advance live, without a manual reload.
  const [auto, setAuto] = useState(true);
  useEffect(() => {
    if (!auto) return;
    const id = setInterval(() => setNonce((n) => n + 1), 5000);
    return () => clearInterval(id);
  }, [auto]);
  const activeCount = all.filter((r) => r.active || r.status === "running").length;

  const [modelF, setModelF] = useState("all");
  const [ablF, setAblF] = useState("all");
  const models = useMemo(() => uniq(all.map(modelOf)).sort(), [all]);
  const ablations = useMemo(
    () => uniq(all.map((r) => r.ablation || "")).sort((a, b) => ablationRank(a) - ablationRank(b)),
    [all],
  );
  const filtered = all
    .filter((r) => modelF === "all" || modelOf(r) === modelF)
    .filter((r) => ablF === "all" || (r.ablation || "") === ablF);
  const grouped = group(filtered);
  const ablOptions = [{ value: "all", label: "all" }, ...ablations.map((a) => ({ value: a, label: a || "—" }))];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Kpi label="runs" value={String(stats.data?.runs ?? "—")} sub={`${stats.data?.completed ?? 0} completed`} />
        <Kpi label="confirmed findings" value={String(stats.data?.confirmed_findings ?? "—")} />
        <Kpi label="targets" value={String(stats.data?.targets ?? "—")} />
        <Kpi label="tokens" value={(stats.data?.total_tokens ?? 0).toLocaleString()} sub={`$${stats.data?.total_usd ?? 0}`} />
      </div>

      <div>
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <h2 className="text-lg font-semibold text-txt">Runs</h2>
          <button onClick={refresh} className="btn !px-2 !py-1 !text-xs">refresh</button>
          <button
            onClick={() => setAuto((a) => !a)}
            className={`btn !px-2 !py-1 !text-xs ${auto ? "!text-pass" : "!text-faint"}`}
            title="auto-refresh every 5s"
          >
            {auto ? "live ●" : "live ○"}
          </button>
          {activeCount > 0 && (
            <span className="text-xs text-dim">{activeCount} running</span>
          )}
          {ablations.length > 0 && (
            <div className="ml-auto flex flex-wrap items-center gap-3">
              <label className="flex items-center gap-1.5 text-xs text-dim">
                model
                <select value={modelF} onChange={(e) => setModelF(e.target.value)} className="field !py-1 !text-xs">
                  <option value="all">all</option>
                  {models.map((m) => <option key={m} value={m}>{m}</option>)}
                </select>
              </label>
              <div className="flex items-center gap-1.5 text-xs text-dim">
                ablation
                <Toggle options={ablOptions} value={ablF} onChange={setAblF} fill={false} />
              </div>
            </div>
          )}
        </div>
        {runs.loading && <p className="text-faint">loading…</p>}
        {runs.error && <p className="text-fail">{runs.error}</p>}
        {runs.data?.length === 0 && (
          <Card><p className="text-faint">No runs yet. Launch one from the <Link className="text-accent" to="/live">Live</Link> page.</p></Card>
        )}
        <div className="space-y-5">
          {grouped.map(([key, group]) => (
            <div key={key}>
              <div className="mb-1.5 flex items-baseline gap-2">
                <span className="font-mono text-[13px] font-semibold text-txt">{key}</span>
                <span className="text-xs text-faint">
                  {group.length} run{group.length === 1 ? "" : "s"}
                  {group.some((r) => r.active || r.status === "running") && " · active"}
                </span>
                {group.length >= 2 && (
                  <Link to="/compare" className="ml-auto text-xs text-accent">compare →</Link>
                )}
              </div>
              <div className="space-y-1.5">
                {group.map((r) => <RunRow key={r.run_id} r={r} onChanged={refresh} />)}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
