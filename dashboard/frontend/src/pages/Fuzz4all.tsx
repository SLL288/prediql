import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Card, useAsync } from "../lib";
import type { LaunchOptions } from "../types";

// The APIs PrediQL/GraphQLer were evaluated on — offered as presets so a
// Fuzz4All baseline can be launched against the same targets in one click.
const PRESETS: { alias: string; target: string }[] = [
  { alias: "countries", target: "https://countries.trevorblades.com/graphql" },
  { alias: "rickandmorty", target: "https://rickandmortyapi.com/graphql" },
  { alias: "graphqlzero", target: "https://graphqlzero.almansi.me/api" },
  { alias: "tcgdex", target: "https://api.tcgdex.net/v2/graphql" },
  { alias: "ehri", target: "https://portal.ehri-project.eu/api/graphql" },
  { alias: "pokeapi", target: "https://beta.pokeapi.co/graphql/v1beta" },
];

type Frame = { kind: string; text: string };

export function Fuzz4all() {
  const opts = useAsync<LaunchOptions>(() => api.liveOptions(), []);
  const [alias, setAlias] = useState("countries");
  const [target, setTarget] = useState(PRESETS[0].target);
  const [model, setModel] = useState("");
  const [budget, setBudget] = useState(20);
  const [busy, setBusy] = useState(false);
  const [frames, setFrames] = useState<Frame[]>([]);
  const [runId, setRunId] = useState<string | null>(null);
  const esRef = useRef<EventSource | null>(null);

  // Default the model to the first hosted catalog entry once options load.
  useEffect(() => {
    if (!model && opts.data?.models?.length) setModel(opts.data.models[0].ref);
  }, [opts.data, model]);
  useEffect(() => () => esRef.current?.close(), []);

  function preset(a: string) {
    const p = PRESETS.find((x) => x.alias === a);
    if (p) { setAlias(p.alias); setTarget(p.target); }
  }

  async function launch() {
    setBusy(true); setFrames([]); setRunId(null);
    esRef.current?.close();
    try {
      const { launch_id, run_id } = await api.launchFuzz4all({ target, alias, model, budget });
      setRunId(run_id);
      setFrames([{ kind: "launched", text: `fuzz4all → ${run_id}` }]);
      const es = new EventSource(`/api/live/${launch_id}/stream`);
      esRef.current = es;
      es.onmessage = (e) => {
        try {
          const d = JSON.parse(e.data);
          const kind = d.event ?? "tick";
          let text = kind;
          if (kind === "step_progress")
            text = `round ${d.round}/${d.total_rounds} · ${d.covered}/${d.total} ops · ${d.requests} sent`;
          else if (kind === "step_finish") text = d.note ?? "cover done";
          else if (kind === "run_finish") { text = `finished: ${d.reason}`; es.close(); setBusy(false); }
          setFrames((f) => [...f, { kind, text }]);
        } catch { /* non-JSON keepalive */ }
      };
      es.addEventListener("error", () => {
        if (es.readyState === EventSource.CLOSED) {
          setFrames((f) => [...f, { kind: "failed", text: "stream disconnected" }]);
          setBusy(false);
        }
      });
    } catch (err) {
      setFrames([{ kind: "failed", text: String(err) }]);
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-txt">Fuzz4All baseline</h2>
        <p className="mt-1 max-w-3xl text-sm text-dim">
          A Fuzz4All-style LLM fuzzer adapted to GraphQL — autoprompt from the schema, then generate / mutate /
          combine query batches, with <em>no</em> retrieval, bandit, or coverage feedback (those are PrediQL's).
          Coverage is measured by the same model, so the run lands on the <Link to="/baselines" className="text-accent">Baselines</Link> page
          as <code>baseline:fuzz4all</code>. Needs the LLM key in <code>.env</code> and a reachable endpoint.
        </p>
      </div>

      <Card className="grid gap-4 sm:grid-cols-2">
        <label className="block">
          <span className="eyebrow mb-1 block">preset API</span>
          <select value={alias} onChange={(e) => preset(e.target.value)} className="field w-full">
            {PRESETS.map((p) => <option key={p.alias} value={p.alias}>{p.alias}</option>)}
          </select>
        </label>
        <label className="block">
          <span className="eyebrow mb-1 block">model</span>
          <select value={model} onChange={(e) => setModel(e.target.value)} className="field w-full">
            {opts.data?.models?.map((m) => <option key={m.ref} value={m.ref}>{m.ref}</option>)}
          </select>
        </label>
        <label className="block sm:col-span-2">
          <span className="eyebrow mb-1 block">target endpoint</span>
          <input value={target} onChange={(e) => setTarget(e.target.value)} className="field w-full font-mono text-[12px]" />
        </label>
        <label className="block">
          <span className="eyebrow mb-1 block">alias (run name)</span>
          <input value={alias} onChange={(e) => setAlias(e.target.value)} className="field w-full" />
        </label>
        <label className="block">
          <span className="eyebrow mb-1 block">budget (LLM calls)</span>
          <input type="number" min={1} max={200} value={budget}
            onChange={(e) => setBudget(Math.max(1, Number(e.target.value) || 1))} className="field w-full" />
        </label>
        <div className="sm:col-span-2 flex items-center gap-3">
          <button onClick={launch} disabled={busy || !model} className="btn-primary">
            {busy ? "running…" : "Launch Fuzz4All run"}
          </button>
          {runId && <Link to={`/runs/${runId}`} className="text-sm text-accent">open run →</Link>}
        </div>
      </Card>

      {frames.length > 0 && (
        <Card>
          <div className="eyebrow mb-2">live</div>
          <div className="max-h-[50vh] space-y-0.5 overflow-y-auto font-mono text-[12px]">
            {frames.map((f, i) => (
              <div key={i} className={f.kind === "failed" ? "text-fail" : "text-dim"}>
                <span className="text-faint">{f.kind}</span> {f.text}
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
