// Shapes returned by the PrediQL Lab API (see dashboard/backend).
import type { ProgressData } from "./components/Progress";

export interface RunSummary {
  run_id: string;
  target: string;
  alias: string;
  api?: string;
  ablation?: string;
  kind?: "system" | "baseline";
  trial: number;
  mode: string;
  field_path_coverage?: number | null;
  providers: Record<string, string>;
  started_at: string;
  status: string;
  active?: boolean;
  calls?: number;
  operation_coverage: number | null;
  element_coverage: number | null;
  confirmed: number;
  potential: number;
  precision: number | null;
  recall: number | null;
  tokens: number;
  usd: number;
}

export interface Step {
  name: string;
  status: "pass" | "fail" | "skipped" | "pending" | "running";
  seconds: number | null;
  note: string;
  metrics: Record<string, unknown>;
  error: string | null;
}

export interface Witness {
  requests?: { document: string; identity: string }[];
  matched?: string;
  response_excerpt?: string;
  latency_ms?: number | null;
}

export interface Finding {
  id: string;
  class: string;
  title?: string;
  severity: string;
  state: "confirmed" | "potential";
  operation: string;
  identity: string;
  evidence_kind: string;
  oracle_verdict: string;
  judge_verdict?: { agrees: boolean; confidence: number; rationale: string; model: string } | null;
  witness: Witness;
  chain?: { operation: string; identity: string; role: string }[] | null;
  repro?: string;
}

export interface RunDetail {
  run_id: string;
  manifest: { config: Record<string, unknown>; plan?: string[] };
  status: string;
  steps: Step[];
  coverage: (Record<string, number> & { operations?: Record<string, OperationState> }) | null;
  known_good: Record<string, string>;
  findings: { findings: Finding[]; confirmed: number; potential: number; by_class?: Record<string, { confirmed: number; potential: number }> };
  score: any;
  bandit: any;
  chains: any;
  budget: Record<string, number>;
  reports: string[];
  /** Latest live progress snapshot, merged across coverage + security ticks. */
  progress?: ProgressData | null;
}

export interface OperationState {
  covered: boolean;
  requests: number;
  rounds: number;
  stop_reason: string;
  known_good: string;
  error: string;
  arms_used: string[];
}

export interface HttpCall {
  operation: string;
  round: number;
  source: string;
  arm: string;
  identity: string;
  document: string;
  status: number;
  success: boolean;
  new_coverage: number;
  elapsed_ms: number;
  error: string | null;
  errors: string;
  data: string;
}

export interface LlmCall {
  ts: string;
  step: string;
  role: string;
  model: string;
  cached: boolean;
  prompt_tokens: number;
  completion_tokens: number;
  usd: number;
  wall_seconds: number;
  system: string;
  prefix: string;
  prompt: string;
  response: string;
}

export interface Stats {
  runs: number;
  completed: number;
  confirmed_findings: number;
  total_tokens: number;
  total_usd: number;
  targets: number;
}

export interface ModelSpec {
  ref: string;
  vendor: string;
  slug: string;
  label: string;
  price_in: number;
  price_out: number;
}

export interface LaunchOptions {
  modes: string[];
  families: string[];
  vendors: string[];
  models: ModelSpec[];
  /** vendor -> the env var its key comes from, or "" when unconfigured. */
  keys: Record<string, string>;
}

export interface OverlapTarget {
  target: string;
  models: string[];
  ready: boolean;
  ablations?: string[];
}

export interface Overlap {
  target: string;
  ready: boolean;
  models: string[];
  reason?: string;
  matrix?: Record<string, Record<string, number>>;
  mean_pairwise_jaccard?: number | null;
  union?: string[];
  consensus?: string[];
  found_by?: Record<string, number>;
  n_models?: number;
}

export interface LaunchRecord {
  launch_id: string;
  run_id: string;
  target: string;
  mode: string;
  model?: string;
  trial?: number;
  trials?: number;
  started_at: number;
  alive: boolean;
  queued?: boolean;
  exit_code: number | null;
  log_tail: string[];
}

export interface SecMatrix {
  tp: number; fp: number; fn: number; tn: number;
  precision: number | null; recall: number | null; f1: number | null;
  coverage_conditioned_recall: number | null;
  fp_rate: number | null;
}

export interface SecRow {
  run_id: string;
  app: string;
  model: string;
  trial: number;
  status: string;
  certification: string | null;
  code_version: string | null;
  truth_file?: { path: string; sha256: string | null } | null;
  confirmed: SecMatrix;
  with_potential: SecMatrix;
  without_post_hoc?: SecMatrix;
  post_hoc_labels: string[];
  unlabelled_confirmed: string[];
  by_class: Record<string, { tp: number; fp: number; fn: number }>;
  fn_cells: string[];
  fn_uncovered_cells: string[];
  confirmed_findings: number;
  potential_findings: number;
}

export interface SecModel {
  model: string;
  rows: SecRow[];
  aggregate: SecMatrix;
  has_post_hoc: boolean;
}

export interface SecToolScores {
  apps: Record<string, SecMatrix & { fp_cells?: string[]; fn_cells?: string[] }>;
  aggregate: SecMatrix;
}

export interface SecComparison {
  scored_apps: string[];
  note: string;
  graphqler: SecToolScores;
  prediql: SecToolScores;
}

export interface SecuritySummary {
  models: SecModel[];
  apps: string[];
  run_count: number;
  any_post_hoc: boolean;
  comparison: SecComparison | null;
}

export type CovMetric = "element" | "operation" | "field_path";
export interface CovCell {
  element: number | null;
  operation: number | null;
  field_path: number | null;
  trials: number;
}
export interface CovRank {
  model: string;
  mean_element: number | null;
  mean_operation: number | null;
  mean_field_path: number | null;
  apis: number;
}
export interface CoverageMatrix {
  apps: string[];
  models: string[];
  arms: string[];
  arm_labels: Record<string, string>;
  cells: Record<string, Record<string, Record<string, CovCell>>>;
  ranking: CovRank[];
  best_model: string | null;
}
