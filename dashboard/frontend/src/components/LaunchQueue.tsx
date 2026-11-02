import { Link } from "react-router-dom";
import type { LaunchRecord } from "../types";

/**
 * In-flight and recent launches.
 *
 * The Live page's stream is client state — it is lost on refresh or navigation,
 * while the runs themselves keep going in a subprocess. This panel is the way
 * back in: it lists what the server actually has, so a reload reattaches instead
 * of showing an empty launcher.
 */
export function LaunchQueue({
  launches, currentId, onAttach, onStop, onDelete,
}: {
  launches: LaunchRecord[];
  currentId: string | null;
  onAttach: (id: string) => void;
  onStop: (id: string) => void;
  onDelete: (id: string) => void;
}) {
  if (launches.length === 0) return null;

  const state = (l: LaunchRecord) =>
    l.alive ? "running" : l.queued ? "queued" : l.exit_code === 0 ? "done" : "failed";
  const tone: Record<string, string> = {
    running: "text-accent", queued: "text-faint", done: "text-pass", failed: "text-fail",
  };

  return (
    <div className="panel p-4">
      <div className="eyebrow mb-2">
        launches · {launches.filter((l) => l.alive).length} running
      </div>
      <div className="space-y-1">
        {launches.map((l) => {
          const s = state(l);
          return (
            <div key={l.launch_id}
              className={`flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-[12px] ${
                l.launch_id === currentId ? "border-accent/60 bg-elevated" : "border-hairline"}`}>
              <span className={`w-14 shrink-0 font-mono text-[11px] ${tone[s]}`}>{s}</span>
              <span className="truncate font-mono text-[11px] text-dim">
                {(l.model ?? "heuristic").split(":").pop()}
                {l.trials && l.trials > 1 ? ` · t${l.trial}` : ""}
              </span>
              <span className="ml-auto flex shrink-0 items-center gap-1.5">
                {l.alive && l.launch_id !== currentId && (
                  <button onClick={() => onAttach(l.launch_id)} className="btn !px-2 !py-0.5 !text-[11px]">
                    attach
                  </button>
                )}
                {l.alive && (
                  <button onClick={() => onStop(l.launch_id)} className="btn-danger !px-2 !py-0.5 !text-[11px]">
                    stop
                  </button>
                )}
                {!l.alive && !l.queued && (
                  <Link to={`/runs/${l.run_id}`} className="btn !px-2 !py-0.5 !text-[11px]">open</Link>
                )}
                {!l.alive && (
                  <button onClick={() => onDelete(l.launch_id)} title="remove from the queue"
                    className="btn-danger !px-2 !py-0.5 !text-[11px]">delete</button>
                )}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
