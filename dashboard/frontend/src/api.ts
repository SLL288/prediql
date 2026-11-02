import type {
  CoverageMatrix,
  HttpCall,
  LaunchOptions,
  LaunchRecord,
  LlmCall,
  Overlap,
  OverlapTarget,
  RunDetail,
  RunSummary,
  SecuritySummary,
  Stats,
} from "./types";

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export const api = {
  stats: () => getJSON<Stats>("/api/stats"),
  runs: () => getJSON<RunSummary[]>("/api/runs"),
  securitySummary: () => getJSON<SecuritySummary>("/api/security/summary"),
  coverageMatrix: () => getJSON<CoverageMatrix>("/api/coverage/matrix"),
  run: (id: string) => getJSON<RunDetail>(`/api/runs/${id}`),
  llmCalls: (id: string) => getJSON<LlmCall[]>(`/api/runs/${id}/llm-calls`),
  httpCalls: (id: string) => getJSON<HttpCall[]>(`/api/runs/${id}/http-calls`),
  liveOptions: () => getJSON<LaunchOptions>("/api/live/options"),
  launch: async (payload: Record<string, unknown>) => {
    const res = await fetch("/api/live/launch", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },
  reportUrl: (id: string, name: string) => `/api/runs/${id}/report/${name}`,

  launchFuzz4all: async (payload: Record<string, unknown>) => {
    const res = await fetch("/api/fuzz4all/launch", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail ?? res.statusText);
    return res.json() as Promise<{ launch_id: string; run_id: string }>;
  },

  launches: () => getJSON<LaunchRecord[]>("/api/live/launches?limit=30"),

  stop: async (launchId: string) => {
    const res = await fetch(`/api/live/${launchId}/stop`, { method: "POST" });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  },

  deleteLaunch: async (launchId: string) => {
    const res = await fetch(`/api/live/${launchId}`, { method: "DELETE" });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail ?? res.statusText);
    return res.json();
  },

  stopRun: async (runId: string) => {
    const res = await fetch(`/api/runs/${runId}/stop`, { method: "POST" });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  },

  deleteRun: async (runId: string) => {
    const res = await fetch(`/api/runs/${runId}`, { method: "DELETE" });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail ?? res.statusText);
    return res.json();
  },

  overlapTargets: () => getJSON<OverlapTarget[]>("/api/analysis/targets"),

  /** What a custom model needs in .env. Keys are never sent to the API. */
  credentials: (model: string) =>
    getJSON<{ vendor: string; ready: boolean; requirements: Record<string, boolean>; missing?: string[] }>(
      `/api/live/credentials?model=${encodeURIComponent(model)}`),

  /** Overlap returns 409 until every model has a completed run for the target.
   *  An optional ablation scopes the sweep to one mode. */
  overlap: async (target: string, ablation?: string): Promise<Overlap> => {
    const q = new URLSearchParams({ target });
    if (ablation && ablation !== "all") q.set("ablation", ablation);
    const res = await fetch(`/api/analysis/overlap?${q.toString()}`);
    return res.json() as Promise<Overlap>;
  },
};
