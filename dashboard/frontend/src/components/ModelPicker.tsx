import type { ModelSpec } from "../types";

export const CUSTOM = "__custom__";

/**
 * Model selector for one role.
 *
 * Choosing "custom" reveals a `vendor:model` field plus the two price inputs —
 * the catalog cannot know an arbitrary model's rate, and a wrong price would
 * silently misreport campaign cost, so it is asked for rather than guessed.
 */
export function ModelPicker({
  label, models, value, onChange,
  customRef, onCustomRef, priceIn, onPriceIn, priceOut, onPriceOut,
  noneLabel = "none",
}: {
  label: string;
  models: ModelSpec[];
  value: string;
  onChange: (v: string) => void;
  customRef: string;
  onCustomRef: (v: string) => void;
  priceIn: string;
  onPriceIn: (v: string) => void;
  priceOut: string;
  onPriceOut: (v: string) => void;
  noneLabel?: string;
}) {
  const selected = models.find((m) => m.ref === value);
  return (
    <div className="mb-3">
      <label className="label">{label}</label>
      <select value={value} onChange={(e) => onChange(e.target.value)} className="select">
        <option value="heuristic">{noneLabel}</option>
        {models.map((m) => (
          <option key={m.ref} value={m.ref}>
            {m.label} — {m.vendor}
          </option>
        ))}
        <option value={CUSTOM}>custom model…</option>
      </select>

      {selected && (
        <div className="mt-1 font-mono text-[11px] text-faint">
          {selected.slug} · ${selected.price_in}/${selected.price_out} per 1M
        </div>
      )}

      {value === CUSTOM && (
        <div className="mt-2 space-y-2 rounded border border-hairline p-2">
          <div>
            <label className="label">vendor:model</label>
            <input value={customRef} onChange={(e) => onCustomRef(e.target.value)}
              placeholder="openrouter/anthropic/zai : model-slug" className="field" />
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
          <p className="text-[11px] text-faint">
            Token counts are always exact; the price only affects the reported USD.
          </p>
        </div>
      )}
    </div>
  );
}
