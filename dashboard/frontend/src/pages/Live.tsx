import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { Card, useAsync } from "../lib";
import { CUSTOM, ModelPicker } from "../components/ModelPicker";
import { ModelSweep } from "../components/ModelSweep";
import { Toggle } from "../components/Toggle";
import { LaunchQueue } from "../components/LaunchQueue";
import { Progress, type ProgressData } from "../components/Progress";
import type { LaunchRecord } from "../types";
import type { LaunchOptions } from "../types";

interface Frame {
  kind: string;
  text: string;
}

/** Last path segment of a `vendor:model` ref, tolerating a missing value.
 *  An older backend omits `model` from its launch records, and a UI must not
 *  white-screen because one optional field is absent. */
function shortModel(ref?: string): string {
  return (ref ?? "heuristic").split(":").pop() || "heuristic";
}

/** One journal event rendered as a readable line. */
function describe(kind: string, data: any): string {
  if (kind === "launched") return `launched → run ${data.run_id}`;
  if (kind === "done") return `done (exit ${data.exit_code ?? 0})`;
  if (kind === "failed") {
    const log = Array.isArray(data.log) ? `\n  ${data.log.join("\n  ")}` : "";
    return `FAILED: ${data.message}${log}`;
  }
  // journal events
  switch (data.event) {
    case "run_start":
      return `run start · plan: ${(data.plan ?? []).join(" → ")}`;
    case "step_start":
      return `  ▸ ${data.step}`;
    case "step_progress":
      // Parenthesised deliberately: `a ?? b != null ? x : y` binds as
      // `(a ?? (b != null)) ? x : y`, which silently prints the wrong branch.
      if (data.covered != null) return `      covered ${data.covered}/${data.total ?? "?"}`;
      if (data.error) return `      error: ${data.error}`;
      return `      …`;
    case "step_finish":
      return `  ${data.outcome === "ok" ? "✓" : "✗"} ${data.step} ${
        data.seconds != null ? `${Number(data.seconds).toFixed(1)}s` : ""
      } ${data.note ?? ""}`.trimEnd();
    case "step_skip":
      return `  – ${data.step} (unchanged)`;
    case "run_finish":
      return `run finish · ${data.reason}`;
    default:
      return `  ${data.event ?? ""}`;
  }
}

export function Live() {
  const opts = useAsync<LaunchOptions>(() => api.liveOptions(), []);
  const [target, setTarget] = useState("https://countries.trevorblades.com/graphql");
  const [mode, setMode] = useState("coverage");
  const [rounds, setRounds] = useState(2);
  const [requests, setRequests] = useState(4);
  const [maxOps, setMaxOps] = useState<string>("");
  const [judgeSamples, setJudgeSamples] = useState(1);
  const [alias, setAlias] = useState("");
  const [trials, setTrials] = useState(1);
  const [generators, setGenerators] = useState<string[]>(["heuristic"]);
  const [judge, setJudge] = useState("heuristic");
  const [genCustom, setGenCustom] = useState("");
  const [genIn, setGenIn] = useState("");
  const [genOut, setGenOut] = useState("");
  const [judgeCustom, setJudgeCustom] = useState("");
  const [judgeIn, setJudgeIn] = useState("");
  const [judgeOut, setJudgeOut] = useState("");
  const [batch, setBatch] = useState<{ trial: number; run_id: string; model?: string }[]>([]);
  const [frames, setFrames] = useState<Frame[]>([]);
  const [steps, setSteps] = useState<{ name: string; ok: boolean; seconds: number | null }[]>([]);
  const [progress, setProgress] = useState<ProgressData | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [launchId, setLaunchId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [launches, setLaunches] = useState<LaunchRecord[]>([]);
  const esRef = useRef<EventSource | null>(null);
  const nav = useNavigate();

  useEffect(() => () => esRef.current?.close(), []);

  // Poll the server's launch list. The stream is client state and is lost on a
  // refresh, but the runs keep going — this is how the page finds them again.
  useEffect(() => {
    let alive = true;
    const tick = () =>
      api.launches().then((l) => alive && setLaunches(l)).catch(() => {});
    tick();
    const id = setInterval(tick, 2000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  function close() {
    esRef.current?.close();
    esRef.current = null;
    setBusy(false);
  }

  /** Open the SSE stream for a launch (new, or one already in flight). */
  function attach(launchId: string, runIdForLaunch?: string) {
    esRef.current?.close();
    setLaunchId(launchId);
    if (runIdForLaunch) setRunId(runIdForLaunch);
    setBusy(true);

    const es = new EventSource(`/api/live/${launchId}/stream`);
    esRef.current = es;

    const onNamed = (kind: string) => (e: MessageEvent) => {
      const data = JSON.parse(e.data);
      setFrames((f) => [...f, { kind, text: describe(kind, data) }]);
      if (kind === "launched" && data.run_id) setRunId(data.run_id);
      if (kind === "journal" && data.event === "step_finish") {
        setSteps((s) => [...s, { name: data.step, ok: data.outcome === "ok", seconds: data.seconds }]);
      }
      if (kind === "journal" && data.event === "step_progress") setProgress(data);
      if (kind === "done" || kind === "failed") close();
    };

    es.addEventListener("launched", onNamed("launched"));
    es.addEventListener("journal", onNamed("journal"));
    es.addEventListener("failed", onNamed("failed"));
    es.addEventListener("done", onNamed("done"));

    // EventSource's own `error` is a transport event with no `.data` — it must
    // never be JSON-parsed. The server reports run failures as `failed`.
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) {
        setFrames((f) => [...f, { kind: "failed", text: "stream disconnected" }]);
        close();
      }
    };
  }

  function reattach(launchId: string) {
    const record = launches.find((l) => l.launch_id === launchId);
    setFrames([{ kind: "launched", text: `reattached to ${launchId}` }]);
    setSteps([]);
    attach(launchId, record?.run_id);
  }

  async function stopLaunch(id: string) {
    try { await api.stop(id); } catch { /* reported by the poll */ }
  }

  async function removeLaunch(id: string) {
    if (id === launchId) close();
    try { await api.deleteLaunch(id); } catch { /* reported by the poll */ }
    setLaunches((ls) => ls.filter((l) => l.launch_id !== id));
  }

  async function launch() {
    setBusy(true);
    setFrames([]);
    setSteps([]);
    setProgress(null);
    setRunId(null);
    try {
      // A "custom" selection resolves to the typed vendor:model, and carries its
      // own price because the catalog has no entry for it.
      const judgeRef = judge === CUSTOM ? judgeCustom.trim() : judge;
      const prices: Record<string, [number, number]> = {};
      // A custom generator in the sweep carries its own price.
      if (genCustom.trim() && generators.includes(genCustom.trim())) {
        prices[genCustom.trim()] = [Number(genIn) || 0, Number(genOut) || 0];
      }
      if (judge === CUSTOM && judgeRef) prices[judgeRef] = [Number(judgeIn) || 0, Number(judgeOut) || 0];

      const res = await api.launch({
        target, alias, mode, rounds, requests, trials,
        generators, judge: judgeRef,
        model_prices: prices,
        max_operations: maxOps ? Number(maxOps) : null,
        judge_samples: judgeSamples,
      });
      const primary = res.primary ?? res;
      setBatch((res.launches ?? [primary]).map((l: any) => ({ trial: l.trial, run_id: l.run_id })));
      attach(primary.launch_id, primary.run_id);
    } catch (err) {
      setFrames([{ kind: "failed", text: `launch failed: ${String(err)}` }]);
      setBusy(false);
    }
  }

  async function stop() {
    if (!launchId) return;
    await stopLaunch(launchId);
    setFrames((f) => [...f, { kind: "failed", text: "stop requested" }]);
  }


  return (
    <div className="grid gap-6 md:grid-cols-[330px_1fr]">
      <Card>
        <h2 className="mb-3 font-semibold">Launch a run</h2>

        <label className="label">target URL</label>
        <input value={target} onChange={(e) => setTarget(e.target.value)}
          placeholder="https://host/graphql" className="field mb-3" />

        <div className="mb-3 grid grid-cols-2 gap-2">
          <div>
            <label className="label">alias</label>
            <input value={alias} onChange={(e) => setAlias(e.target.value)}
              placeholder="from URL" className="field" />
          </div>
          <div>
            <label className="label">trials</label>
            <input type="number" min={1} max={10} value={trials}
              onChange={(e) => setTrials(+e.target.value)} className="field" />
          </div>
        </div>

        <div className="mb-3">
          <label className="label">mode</label>
          <Toggle
            options={(opts.data?.modes ?? []).map((m) => ({ value: m, label: m }))}
            value={mode} onChange={setMode} />
        </div>

        <div className="mb-3 grid grid-cols-2 gap-2">
          <div>
            <label className="label">rounds</label>
            <input type="number" min={1} value={rounds}
              onChange={(e) => setRounds(+e.target.value)} className="field" />
          </div>
          <div>
            <label className="label">requests/op</label>
            <input type="number" min={1} value={requests}
              onChange={(e) => setRequests(+e.target.value)} className="field" />
          </div>
        </div>

        <div className="mb-3 grid grid-cols-2 gap-2">
          <div>
            <label className="label">max operations</label>
            <input type="number" min={1} placeholder="all" value={maxOps}
              onChange={(e) => setMaxOps(e.target.value)} className="field" />
          </div>
          <div>
            <label className="label">judge samples</label>
            <input type="number" min={1} max={5} value={judgeSamples}
              onChange={(e) => setJudgeSamples(+e.target.value)} className="field" />
          </div>
        </div>

        <ModelSweep
          models={opts.data?.models ?? []} selected={generators} trials={trials}
          keys={opts.data?.keys ?? {}}
          onToggle={(ref) => setGenerators((g) =>
            g.includes(ref) ? g.filter((x) => x !== ref) : [...g, ref])}
          customRef={genCustom} onCustomRef={setGenCustom}
          priceIn={genIn} onPriceIn={setGenIn} priceOut={genOut} onPriceOut={setGenOut} />

        <ModelPicker label="judge (potentials only)" noneLabel="none"
          models={opts.data?.models ?? []} value={judge} onChange={setJudge}
          customRef={judgeCustom} onCustomRef={setJudgeCustom}
          priceIn={judgeIn} onPriceIn={setJudgeIn} priceOut={judgeOut} onPriceOut={setJudgeOut} />

        <div className="flex gap-2">
          <button onClick={launch} disabled={busy} className="btn-primary flex-1">
            {busy ? "running…" : "Launch"}
          </button>
          <button onClick={stop} disabled={!busy} className="btn-danger">Stop</button>
        </div>
      </Card>

      <div className="space-y-4">
        <LaunchQueue launches={launches} currentId={launchId}
          onAttach={reattach} onStop={stopLaunch} onDelete={removeLaunch} />
        {progress && (
          <Card><Progress p={progress} running={busy} /></Card>
        )}
        {batch.length > 1 && (
          <Card>
            <div className="eyebrow mb-2">
              sweep — {batch.length} runs, sequential, one directory each
            </div>
            <div className="flex flex-wrap gap-2">
              {batch.map((b) => (
                <span key={b.run_id}
                  className={`rounded border px-2 py-1 text-xs ${
                    b.run_id === runId ? "border-accent text-accent" : "border-hairline text-dim"}`}>
                  <span className="font-mono">{shortModel(b.model)}</span>
                  <span className="text-faint"> · t{b.trial}</span>
                </span>
              ))}
            </div>
          </Card>
        )}
        {steps.length > 0 && (
          <Card>
            <div className="eyebrow mb-2">workflow</div>
            <div className="flex flex-wrap gap-2">
              {steps.map((s, i) => (
                <span key={i}
                  className={`rounded border px-2 py-1 text-xs ${
                    s.ok ? "border-pass text-pass" : "border-fail text-fail"}`}>
                  {s.name}{s.seconds != null ? ` ${s.seconds.toFixed(1)}s` : ""}
                </span>
              ))}
            </div>
          </Card>
        )}
        <Card>
          <div className="mb-2 flex items-center gap-2">
            <span className="text-xs uppercase text-faint">stream</span>
            {runId && !busy && (
              <button onClick={() => nav(`/runs/${runId}`)} className="btn ml-auto !text-accent">
                open run →
              </button>
            )}
          </div>
          <pre className="pre max-h-[460px]">
{frames.length > 0
  ? frames.map((f) => f.text).join("\n")
  : launches.some((l) => l.alive)
  ? "Runs are in progress — click \u201Cattach\u201D above to watch one."
  : "Launch a run to watch it progress."}
          </pre>
        </Card>
      </div>
    </div>
  );
}
