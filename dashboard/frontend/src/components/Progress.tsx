import type { ReactNode } from "react";

/**
 * Live run progress.
 *
 * Modelled on AutoSec's iterative-hardening panel: a segmented tracker (one cell
 * per round / per probe batch) makes "how far along" legible at a glance, the way
 * a single sliding bar cannot. Two loops drive it:
 *
 *  - coverage: one cell per fuzzing round, filled as rounds complete, the current
 *    round pulsing while the run is live;
 *  - security: a fill bar over the (operation x family) probe jobs, the analog of
 *    the hardening loop's per-round bypass hunts.
 *
 * Both share the budget readout — tokens/USD spent against the cap, with what
 * remains — so "how much is left" is always in view. The fields are disjoint, so
 * a completed full run shows both loops at once.
 */

export interface ProgressData {
  phase?: string;
  round?: number;
  total_rounds?: number;
  covered?: number;
  total?: number;
  requests?: number;
  tokens?: number;
  usd?: number;
  budget_tokens?: number | null;
  budget_usd?: number | null;
  consumed?: number;
  jobs_done?: number;
  jobs_total?: number;
  confirmed?: number;
  signals?: number;
}

const nf = (n: number) => n.toLocaleString();

/** A labelled fill bar with a value / max readout. */
function Bar({ label, value, max, right, tone = "bg-accent" }: {
  label: string; value: number; max?: number | null; right: string; tone?: string;
}) {
  const pct = max && max > 0 ? Math.min(100, (value / max) * 100) : value > 0 ? 100 : 0;
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between gap-2 text-[11px]">
        <span className="eyebrow">{label}</span>
        <span className="font-mono tabular-nums text-dim">{right}</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-elevated">
        <div className={`h-full rounded-full ${tone} transition-[width] duration-500`}
          style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

/** Segmented round tracker — one cell per round (the AutoSec hardening pattern). */
function RoundTracker({ round, total, running }: { round: number; total: number; running: boolean }) {
  const cells = Array.from({ length: total }, (_, i) => i + 1);
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between gap-2 text-[11px]">
        <span className="eyebrow">fuzzing rounds</span>
        <span className="font-mono tabular-nums text-dim">
          {Math.min(round, total)} / {total}{running && round <= total ? " · running" : ""}
        </span>
      </div>
      <div className="flex gap-1" aria-label={`${round} of ${total} rounds`}>
        {cells.map((n) => {
          const done = n < round;
          const current = n === round;
          return (
            <span key={n}
              className={`h-1.5 flex-1 rounded-full transition-colors ${
                done ? "bg-accent"
                : current ? (running ? "bg-accent/60 animate-pulse" : "bg-accent")
                : "bg-elevated"}`} />
          );
        })}
      </div>
    </div>
  );
}

export function Progress({ p, running = false }: { p: ProgressData; running?: boolean }) {
  const tokens = p.tokens ?? 0;
  const usd = p.usd ?? 0;
  const capTok = p.budget_tokens ?? null;
  const capUsd = p.budget_usd ?? null;
  const consumedPct = p.consumed != null ? Math.round(p.consumed * 100) : null;

  // Budget readout: prefer the token cap, fall back to the USD cap, else show
  // spend uncapped. "remaining" is what the reviewers asked to see.
  let budget: ReactNode;
  if (capTok != null) {
    budget = <Bar label="token budget" value={tokens} max={capTok}
      right={`${nf(tokens)} / ${nf(capTok)} · ${nf(Math.max(0, capTok - tokens))} left`}
      tone={consumedPct != null && consumedPct >= 90 ? "bg-high" : "bg-accent"} />;
  } else if (capUsd != null) {
    budget = <Bar label="usd budget" value={usd} max={capUsd}
      right={`$${usd} / $${capUsd} · $${Math.max(0, capUsd - usd).toFixed(4)} left`} />;
  } else {
    budget = <Bar label="spend" value={tokens} max={null}
      right={`${nf(tokens)} tok · $${usd}`} />;
  }

  const hasRounds = p.total_rounds != null && p.total_rounds > 0;
  const hasCoverage = p.total != null;
  const hasJobs = p.jobs_total != null && p.jobs_total > 0;

  return (
    <div className="space-y-3">
      {/* headline counters */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px]">
        {p.phase && (
          <span className="flex items-center gap-1.5">
            <span className={`h-1.5 w-1.5 rounded-full bg-accent ${running ? "animate-pulse" : ""}`} />
            <span className="font-mono uppercase tracking-wide text-dim">{p.phase}</span>
          </span>
        )}
        {p.requests != null && (
          <span className="text-faint">requests <span className="font-mono tabular-nums text-dim">{nf(p.requests)}</span></span>
        )}
        {hasJobs && (
          <>
            {p.confirmed != null && p.confirmed > 0 && (
              <span className="text-fail">confirmed <span className="font-mono tabular-nums">{p.confirmed}</span></span>
            )}
            {p.signals != null && p.signals > 0 && (
              <span className="text-med">signals <span className="font-mono tabular-nums">{p.signals}</span></span>
            )}
          </>
        )}
        {consumedPct != null && (
          <span className="ml-auto text-faint">budget <span className="font-mono tabular-nums text-dim">{consumedPct}%</span></span>
        )}
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        {hasRounds && (
          <RoundTracker round={p.round ?? 0} total={p.total_rounds!} running={running} />
        )}
        {hasCoverage && (
          <Bar label="operations covered" value={p.covered ?? 0} max={p.total}
            right={`${p.covered ?? 0} / ${p.total}`} tone="bg-pass" />
        )}
        {hasJobs && (
          <Bar label="security probes" value={p.jobs_done ?? 0} max={p.jobs_total}
            right={`${p.jobs_done ?? 0} / ${p.jobs_total}`} tone="bg-low" />
        )}
        {budget}
      </div>
    </div>
  );
}
