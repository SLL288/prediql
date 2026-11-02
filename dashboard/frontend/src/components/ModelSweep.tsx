import { useEffect, useState } from "react";
import { api } from "../api";
import type { ModelSpec } from "../types";

/**
 * Generator-model sweep selector.
 *
 * A toggle group rather than a list of checkboxes (the AutoSec Lab pattern):
 * each option is a pressable chip, grouped by vendor, showing its price and a
 * "no key" badge when that vendor cannot authenticate. The header carries the
 * live sweep size, so the cost of adding another model is visible at the moment
 * you add it.
 *
 * "heuristic" is a first-class member, not an absence — it is the zero-cost,
 * deterministic baseline every LLM arm should be measured against.
 */

interface Props {
  models: ModelSpec[];
  selected: string[];
  onToggle: (ref: string) => void;
  trials: number;
  keys?: Record<string, string>;
  customRef: string;
  onCustomRef: (v: string) => void;
  priceIn: string;
  onPriceIn: (v: string) => void;
  priceOut: string;
  onPriceOut: (v: string) => void;
}

function Option({
  label, sub, on, disabled, warn, onClick,
}: {
  label: string;
  sub?: string;
  on: boolean;
  disabled?: boolean;
  warn?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={on}
      onClick={onClick}
      title={warn ? "no API key configured for this vendor" : undefined}
      className={`focusable flex min-w-0 flex-col items-start rounded-lg border px-2.5 py-1.5
        text-left transition-colors ${
          on
            ? "border-accent/60 bg-elevated text-txt"
            : "border-hairline text-dim hover:border-hairline-strong hover:text-txt"
        } ${disabled ? "opacity-50" : ""}`}
    >
      <span className="flex w-full items-center gap-1.5">
        <span className="truncate text-[13px] font-medium">{label}</span>
        {warn && <span className="ml-auto shrink-0 text-[10px] font-semibold text-high">no key</span>}
      </span>
      {sub && <span className="font-mono text-[10px] text-faint">{sub}</span>}
    </button>
  );
}

export function ModelSweep({
  models, selected, onToggle, trials, keys = {},
  customRef, onCustomRef, priceIn, onPriceIn, priceOut, onPriceOut,
}: Props) {
  const byVendor = models.reduce<Record<string, ModelSpec[]>>((acc, m) => {
    (acc[m.vendor] ??= []).push(m);
    return acc;
  }, {});
  const runs = Math.max(selected.length, 1) * Math.max(trials, 1);
  const missing = [...new Set(
    selected
      .filter((r) => r && r !== "heuristic")
      .map((r) => r.split(":")[0])
      .filter(Boolean)
  )].filter((v) => keys[v] === "");

  // A custom model's credentials live in .env, never in the launch request: a key
  // sent here would end up in the run subprocess's argv, readable by ps.
  const [creds, setCreds] = useState<{ ready: boolean; missing?: string[] } | null>(null);
  useEffect(() => {
    const ref = customRef.trim();
    if (!ref.includes(":")) { setCreds(null); return; }
    let alive = true;
    api.credentials(ref).then((c) => alive && setCreds(c)).catch(() => alive && setCreds(null));
    return () => { alive = false; };
  }, [customRef]);

  const custom = customRef.trim();
  const customOn = Boolean(custom) && selected.includes(custom);

  return (
    <div className="mb-4">
      <div className="mb-1.5 flex items-baseline justify-between gap-2">
        <span className="eyebrow">generator models</span>
        <span className="font-mono text-[11px] text-dim">
          {selected.length || 1}×{trials} =&nbsp;
          <span className="font-semibold text-accent">{runs} run{runs === 1 ? "" : "s"}</span>
        </span>
      </div>

      <div className="space-y-2.5 rounded-lg border border-hairline bg-surface p-2.5">
        <Option
          label="heuristic"
          sub="no LLM · free · deterministic baseline"
          on={selected.includes("heuristic")}
          onClick={() => onToggle("heuristic")}
        />

        {Object.entries(byVendor).map(([vendor, list]) => (
          <div key={vendor}>
            <div className="mb-1 flex items-center gap-1.5">
              <span className="eyebrow">{vendor}</span>
              {keys[vendor] === "" && (
                <span className="text-[10px] text-high">key missing</span>
              )}
            </div>
            <div className="grid grid-cols-2 gap-1.5">
              {list.map((m) => (
                <Option
                  key={m.ref}
                  label={m.label}
                  sub={`$${m.price_in}/$${m.price_out} per 1M`}
                  on={selected.includes(m.ref)}
                  warn={keys[m.vendor] === ""}
                  onClick={() => onToggle(m.ref)}
                />
              ))}
            </div>
          </div>
        ))}
      </div>

      {missing.length > 0 && (
        <p className="mt-2 rounded-lg border border-high/40 bg-high/5 px-2.5 py-1.5 text-[11px] text-high">
          No API key for <strong>{missing.join(", ")}</strong>. Set{" "}
          {missing.map((v) => `${v.toUpperCase()}_API_KEY`).join(" / ")} (or the shared
          LLM_API_KEY) in <code>.env</code> — a token for one vendor is not valid at another.
        </p>
      )}

      <details className="mt-2 rounded-lg border border-hairline bg-surface">
        <summary className="focusable cursor-pointer select-none px-2.5 py-1.5 text-[12px] text-dim">
          custom model{customOn && <span className="ml-1.5 text-accent">· in sweep</span>}
        </summary>
        <div className="space-y-2 border-t border-hairline p-2.5">
          <div>
            <label className="label">vendor:model</label>
            <input value={customRef} onChange={(e) => onCustomRef(e.target.value)}
              placeholder="openrouter:org/model-slug" className="field font-mono text-[12px]" />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="label">$ / 1M in</label>
              <input type="number" step="0.01" min="0" value={priceIn}
                onChange={(e) => onPriceIn(e.target.value)} placeholder="0.00" className="field" />
            </div>
            <div>
              <label className="label">$ / 1M out</label>
              <input type="number" step="0.01" min="0" value={priceOut}
                onChange={(e) => onPriceOut(e.target.value)} placeholder="0.00" className="field" />
            </div>
          </div>

          {creds && (
            creds.ready
              ? <p className="text-[11px] text-pass">credentials configured ✓</p>
              : <p className="text-[11px] text-high">
                  Add to <code>.env</code>: {creds.missing?.join(", ")}
                </p>
          )}

          <button type="button" disabled={!custom.includes(":")}
            onClick={() => custom && onToggle(custom)}
            className={`w-full ${customOn ? "btn-danger" : "btn"}`}>
            {customOn ? "remove from sweep" : "add to sweep"}
          </button>

          <p className="text-[11px] text-faint">
            Token counts are always exact; the price only affects the reported USD.
            API keys are read from <code>.env</code> — never entered here, so they cannot
            leak into a process listing.
          </p>
        </div>
      </details>
    </div>
  );
}
