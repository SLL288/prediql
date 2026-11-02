import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api";
import { Card, pct, sevColor, statusTone, useAsync, SEV_ORDER } from "../lib";
import type { Finding, HttpCall, LlmCall, OperationState, RunDetail as RunDetailT } from "../types";
import { Progress } from "../components/Progress";

function StepRail({ steps }: { steps: RunDetailT["steps"] }) {
  return (
    <div className="flex flex-wrap items-stretch gap-2">
      {steps.map((s) => (
        <div key={s.name}
          className={`min-w-[110px] rounded-lg border px-3 py-2 ${
            s.status === "running" ? "border-accent animate-pulse" : "border-hairline"}`}>
          <div className={`text-[10px] font-mono ${statusTone(s.status)}`}>{s.status}</div>
          <div className="text-sm font-semibold text-txt">{s.name}</div>
          {s.seconds != null && <div className="text-[10px] text-faint">{s.seconds.toFixed(1)}s</div>}
        </div>
      ))}
    </div>
  );
}

// ── Operations: per-node status + the good sample query ──────────────────
function Operations({ operations }: { operations: Record<string, OperationState> }) {
  const rows = Object.entries(operations).sort(
    (a, b) => Number(b[1].covered) - Number(a[1].covered) || a[0].localeCompare(b[0])
  );
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="eyebrow text-left">
            <th className="py-2 pr-4">operation</th>
            <th className="py-2 pr-4">status</th>
            <th className="py-2 pr-4 text-right">reqs</th>
            <th className="py-2 pr-4">stop reason</th>
            <th className="py-2">good sample</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([name, st]) => (
            <tr key={name} className="border-t border-hairline align-top">
              <td className="py-2 pr-4 font-mono text-[13px] text-txt">{name}</td>
              <td className="py-2 pr-4">
                <span className={st.covered ? "text-pass" : "text-faint"}>
                  {st.covered ? "covered" : "—"}
                </span>
              </td>
              <td className="py-2 pr-4 text-right tabular-nums text-dim">{st.requests}</td>
              <td className="py-2 pr-4 font-mono text-[11px] text-dim">{st.stop_reason}</td>
              <td className="py-2">
                {st.known_good
                  ? <code className="code">{st.known_good}</code>
                  : st.error
                  ? <span className="text-[12px] text-fail">{st.error}</span>
                  : <span className="text-faint">—</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── LLM calls: the prompt/response trail per step ────────────────────────
function LlmCalls({ runId }: { runId: string }) {
  const { data, loading } = useAsync<LlmCall[]>(() => api.llmCalls(runId), [runId]);
  const [open, setOpen] = useState<number | null>(0);
  if (loading) return <p className="text-faint">loading…</p>;
  if (!data || data.length === 0)
    return <p className="text-faint">No LLM calls — this run used the heuristic generator (no model).</p>;

  return (
    <div className="space-y-1.5">
      {data.map((c, i) => (
        <div key={i} className="rounded-lg border border-hairline">
          <button onClick={() => setOpen(open === i ? null : i)}
            className="focusable flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] hover:bg-elevated">
            <span className="chip">{c.step}</span>
            <span className="font-mono text-[11px] text-dim">{c.role}</span>
            <span className="font-mono text-[11px] text-faint">{c.model}</span>
            {c.cached && <span className="text-[10px] text-accent">cached</span>}
            <span className="ml-auto font-mono text-[11px] tabular-nums text-faint">
              {c.prompt_tokens}→{c.completion_tokens} tok · ${c.usd} · {c.wall_seconds}s
            </span>
          </button>
          {open === i && (
            <div className="space-y-2 border-t border-hairline p-3">
              {c.prefix && (
                <div>
                  <div className="eyebrow mb-1">schema / prefix</div>
                  <pre className="pre">{c.prefix}</pre>
                </div>
              )}
              <div>
                <div className="eyebrow mb-1">prompt</div>
                <pre className="pre">{c.prompt}</pre>
              </div>
              <div>
                <div className="eyebrow mb-1">response</div>
                <pre className="pre !text-txt">{c.response}</pre>
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Requests: every generated query sent to the server, and the response ──
function Requests({ runId }: { runId: string }) {
  const { data, loading } = useAsync<HttpCall[]>(() => api.httpCalls(runId), [runId]);
  const [open, setOpen] = useState<number | null>(null);
  if (loading) return <p className="text-faint">loading…</p>;
  if (!data || data.length === 0)
    return <p className="text-faint">No server requests logged (coverage step has not run).</p>;

  // Group by operation so a node's attempts read together.
  const byOp = data.reduce<Record<string, { call: HttpCall; i: number }[]>>((acc, call, i) => {
    (acc[call.operation] ??= []).push({ call, i });
    return acc;
  }, {});

  return (
    <div className="space-y-4">
      {Object.entries(byOp).map(([op, items]) => (
        <div key={op}>
          <div className="mb-1.5 flex items-baseline gap-2">
            <span className="font-mono text-[13px] font-semibold text-txt">{op}</span>
            <span className="text-xs text-faint">
              {items.length} request{items.length === 1 ? "" : "s"} ·{" "}
              {items.filter((x) => x.call.success).length} ok
            </span>
          </div>
          <div className="space-y-1">
            {items.map(({ call, i }) => (
              <div key={i} className="rounded-lg border border-hairline">
                <button onClick={() => setOpen(open === i ? null : i)}
                  className="focusable flex w-full items-center gap-2 px-3 py-1.5 text-left text-[12px] hover:bg-elevated">
                  <span className={`w-10 shrink-0 font-mono text-[11px] ${
                    call.success ? "text-pass" : "text-fail"}`}>{call.status || "×"}</span>
                  <span className="chip shrink-0">{call.source}</span>
                  {call.new_coverage > 0 && (
                    <span className="shrink-0 text-[10px] text-accent">+{call.new_coverage} cov</span>
                  )}
                  <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-dim">{call.document}</code>
                  <span className="shrink-0 font-mono text-[11px] text-faint">{call.elapsed_ms}ms</span>
                </button>
                {open === i && (
                  <div className="space-y-2 border-t border-hairline p-3">
                    <div>
                      <div className="eyebrow mb-1">request · {call.identity}</div>
                      <pre className="pre">{call.document}</pre>
                    </div>
                    {call.data && (
                      <div>
                        <div className="eyebrow mb-1">response data</div>
                        <pre className="pre !text-txt">{call.data}</pre>
                      </div>
                    )}
                    {call.errors && (
                      <div>
                        <div className="eyebrow mb-1">errors</div>
                        <pre className="pre !text-fail">{call.errors}</pre>
                      </div>
                    )}
                    {call.error && <p className="text-[12px] text-fail">transport: {call.error}</p>}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function FindingCard({ f }: { f: Finding }) {
  const [open, setOpen] = useState(f.state === "confirmed");
  return (
    <Card className="!p-0 overflow-hidden">
      <button onClick={() => setOpen(!open)}
        className="focusable flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-elevated">
        <span className={`rounded px-2 py-0.5 text-[11px] font-bold uppercase text-white ${sevColor(f.severity)}`}>
          {f.severity}
        </span>
        <span className="font-semibold text-txt">{f.title ?? f.class}</span>
        <code className="code">{f.operation}</code>
        <span className={`ml-auto text-xs font-semibold ${f.state === "confirmed" ? "text-fail" : "text-med"}`}>
          {f.state}
        </span>
      </button>
      {open && (
        <div className="space-y-2 border-t border-hairline px-4 py-3 text-sm">
          {f.witness?.matched && (
            <div><span className="eyebrow mr-2 inline-block">evidence</span>{f.witness.matched}</div>
          )}
          {f.chain && (
            <div className="text-xs">
              <span className="eyebrow mr-2 inline-block">chain</span>
              {f.chain.map((s, i) => (
                <code key={i} className="code mr-1">{s.identity}:{s.operation}</code>
              ))}
            </div>
          )}
          {f.witness?.requests?.map((r, i) => (
            <div key={i}>
              <div className="eyebrow">{f.witness.requests!.length > 1 ? `step ${i + 1}` : "request"} · {r.identity}</div>
              <pre className="pre mt-1">{r.document}</pre>
            </div>
          ))}
          {f.judge_verdict && (
            <div className="rounded-lg border border-hairline p-2 text-xs">
              <span className="eyebrow mr-2 inline-block">LLM judge</span>
              <span className={f.judge_verdict.agrees ? "text-fail" : "text-pass"}>
                {f.judge_verdict.agrees ? "agrees (real)" : "disagrees (not real)"}
              </span>
              <span className="ml-2 text-faint">conf {f.judge_verdict.confidence}</span>
              <p className="mt-1 text-dim">{f.judge_verdict.rationale}</p>
            </div>
          )}
          {f.repro && (
            <div><span className="eyebrow mr-2 inline-block">reproduce</span><code className="code">{f.repro}</code></div>
          )}
        </div>
      )}
    </Card>
  );
}

export function RunDetail() {
  const { runId } = useParams();
  const [refreshKey, setRefreshKey] = useState(0);
  const { data, error, loading } = useAsync<RunDetailT>(() => api.run(runId!), [runId, refreshKey]);
  const [tab, setTab] = useState<"findings" | "operations" | "requests" | "llm">("findings");

  // Poll while the run is active so the progress bar, step rail, and budget
  // advance live. useAsync keeps the prior data during a refetch, so a poll
  // never flashes the page. Without this a running run freezes at its first
  // snapshot — the actual bug behind "the progress bar doesn't move".
  useEffect(() => {
    if (data?.status !== "running") return;
    const id = setInterval(() => setRefreshKey((k) => k + 1), 1500);
    return () => clearInterval(id);
  }, [data?.status]);

  if (loading && !data) return <p className="text-faint">loading…</p>;
  if (error && !data) return <p className="text-fail">{error}</p>;
  if (!data) return <p className="text-fail">not found</p>;

  const cov = data.coverage;
  const ops = cov?.operations ?? {};
  const findings = [...data.findings.findings].sort(
    (a, b) => (a.state === b.state ? 0 : a.state === "confirmed" ? -1 : 1) ||
      (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4)
  );
  const score = data.score?.confirmed;
  const running = data.status === "running";

  const TabBtn = ({ id, label, n }: { id: typeof tab; label: string; n?: number }) => (
    <button onClick={() => setTab(id)}
      className={`focusable rounded-lg border px-3 py-1.5 text-sm transition-colors ${
        tab === id ? "border-accent/60 bg-elevated font-medium text-txt"
                   : "border-hairline text-dim hover:text-txt"}`}>
      {label}{n != null && <span className="ml-1.5 text-faint">{n}</span>}
    </button>
  );

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-3">
          <span className={`text-sm font-semibold ${statusTone(data.status)}`}>
            {data.status}{running && <span className="ml-1 animate-pulse">●</span>}
          </span>
          <h1 className="text-lg font-semibold text-txt">{String(data.manifest.config.target)}</h1>
          <span className="chip">{String(data.manifest.config.mode)}</span>
          {String((data.manifest.config as any).alias) && (
            <span className="chip">{String((data.manifest.config as any).alias)} · t{String((data.manifest.config as any).trial ?? 1)}</span>
          )}
        </div>
        <div className="font-mono text-xs text-faint">{data.run_id}</div>
      </div>

      <Card>
        <div className="eyebrow mb-3">workflow{running && " · in progress"}</div>
        <StepRail steps={data.steps} />
        {data.progress && (
          <div className="mt-4 border-t border-hairline pt-3">
            <Progress p={data.progress} running={running} />
          </div>
        )}
      </Card>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {cov && <Card><div className="eyebrow">op coverage</div><div className="text-xl font-bold text-txt">{pct(cov.operation_coverage)}</div><div className="text-xs text-dim">{cov.operations_covered}/{cov.operations_total}</div></Card>}
        {cov && <Card><div className="eyebrow">element coverage</div><div className="text-xl font-bold text-txt">{pct(cov.element_coverage)}</div></Card>}
        <Card><div className="eyebrow">confirmed</div><div className="text-xl font-bold text-fail">{data.findings.confirmed}</div><div className="text-xs text-dim">{data.findings.potential} potential</div></Card>
        {score && <Card><div className="eyebrow">precision / recall</div><div className="text-xl font-bold text-txt">{pct(score.precision)} / {pct(score.recall)}</div><div className="text-xs text-dim">F1 {pct(score.f1)}</div></Card>}
        <Card><div className="eyebrow">tokens</div><div className="text-xl font-bold tabular-nums text-txt">{(data.budget.total_tokens ?? 0).toLocaleString()}</div><div className="text-xs text-dim">${data.budget.usd ?? 0} · {data.budget.calls ?? 0} calls</div></Card>
      </div>

      {data.reports.length > 0 && (
        <Card>
          <span className="eyebrow mr-3 inline-block">reports</span>
          {data.reports.map((r) => (
            <a key={r} href={api.reportUrl(data.run_id, r)} target="_blank" rel="noreferrer" className="mr-3 text-sm text-accent">{r}</a>
          ))}
        </Card>
      )}

      <div className="flex gap-2">
        <TabBtn id="findings" label="Findings" n={findings.length} />
        <TabBtn id="operations" label="Operations" n={Object.keys(ops).length} />
        <TabBtn id="requests" label="Requests" />
        <TabBtn id="llm" label="LLM calls" />
      </div>

      {tab === "findings" && (
        findings.length === 0
          ? <Card><p className="text-faint">No findings.</p></Card>
          : <div className="space-y-2">{findings.map((f) => <FindingCard key={f.id} f={f} />)}</div>
      )}
      {tab === "operations" && (
        Object.keys(ops).length === 0
          ? <Card><p className="text-faint">No per-operation data (coverage step has not run).</p></Card>
          : <Card><Operations operations={ops} /></Card>
      )}
      {tab === "requests" && <Card><Requests runId={data.run_id} /></Card>}
      {tab === "llm" && <Card><LlmCalls runId={data.run_id} /></Card>}
    </div>
  );
}
