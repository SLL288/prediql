/**
 * Segmented toggle group (the AutoSec Lab pattern).
 *
 * A pressable chip per option rather than a dropdown: the available choices and
 * the current one are both visible without opening anything, which matters on a
 * launcher where the selection *is* the experiment definition.
 */
export function Toggle<T extends string>({
  options, value, onChange, fill = true,
}: {
  options: { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
  fill?: boolean;
}) {
  return (
    <div className={`flex gap-1 ${fill ? "" : "flex-wrap"}`}>
      {options.map((o) => {
        const on = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            aria-pressed={on}
            onClick={() => onChange(o.value)}
            className={`focusable rounded-lg border px-2.5 py-1.5 text-[12px] transition-colors ${
              fill ? "flex-1" : ""
            } ${on
              ? "border-accent/60 bg-elevated font-medium text-txt"
              : "border-hairline text-dim hover:border-hairline-strong hover:text-txt"}`}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
