import { useEffect, useState, type ReactNode } from "react";

export const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function pct(v: number | null | undefined): string {
  return v == null ? "—" : `${(v * 100).toFixed(1)}%`;
}

export function sevColor(sev: string): string {
  return { critical: "bg-crit", high: "bg-high", medium: "bg-med", low: "bg-low" }[sev] ?? "bg-med";
}

export function statusTone(status: string): string {
  if (status === "completed" || status === "pass") return "text-pass";
  if (status === "running") return "text-accent";
  if (status.startsWith("step_failed") || status === "fail") return "text-fail";
  return "text-faint";
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`panel p-4 ${className}`}>{children}</div>;
}

export function Chip({ children, tone = "" }: { children: ReactNode; tone?: string }) {
  return <span className={`chip ${tone}`}>{children}</span>;
}

/** Minimal data-fetching hook: {data, error, loading}. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [state, setState] = useState<{ data: T | null; error: string | null; loading: boolean }>({
    data: null,
    error: null,
    loading: true,
  });
  useEffect(() => {
    let alive = true;
    setState((s) => ({ ...s, loading: true }));
    fn()
      .then((d) => alive && setState({ data: d, error: null, loading: false }))
      .catch((e: Error) => alive && setState({ data: null, error: String(e), loading: false }));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return state;
}
