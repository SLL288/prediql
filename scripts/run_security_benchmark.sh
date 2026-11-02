#!/usr/bin/env bash
# Run the labeled security benchmark (S1) end-to-end and score it (S6).
#
# Prereqs:
#   1. An LLM key in .env (the cover stage generates queries). See README below.
#   2. The vulnerable apps running on the security profile (see security_benchmark/README.md):
#        docker compose --profile security up -d --build   # idor remapped to :8010
#   3. The apps must reach the OOB collaborator; on Docker Desktop/OrbStack that
#      is host.docker.internal (used below).
#
# Usage:  scripts/run_security_benchmark.sh [vendor:model]
#   e.g.  scripts/run_security_benchmark.sh zai:glm-5.3-flash
#         scripts/run_security_benchmark.sh openrouter:openai/gpt-5.4-nano
set -euo pipefail
MODEL="${1:-zai:glm-5.3-flash}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
PY="${PYTHON:-.venv/bin/python}"
OOB="host.docker.internal"

run() {  # slug  truth  url  [extra --identity ...]
  local slug="$1" truth="$2" url="$3"; shift 3
  echo "==================== $slug ($MODEL) ===================="
  # Truth files are certified once, at the freeze (see truth/CHANGELOG.md) —
  # never here: re-certifying before every run would reseal any label edit.
  "$PY" -m prediql.cli run --target "$url" --alias "$slug" --mode full --allow-destructive \
      --provider "generator=$MODEL" --truth "$truth" --oob-host "$OOB" "$@"
}

run injection    security_benchmark/truth/injection.yaml    http://127.0.0.1:4002/graphql
run idor         security_benchmark/truth/idor.yaml         http://127.0.0.1:8010/graphql \
     --identity "alice:user=Authorization: Bearer alice_token_abc123" \
     --identity "bob:user=Authorization: Bearer bob_token_xyz789"
run vvsm         security_benchmark/truth/vvsm.yaml         http://127.0.0.1:8001/graphql \
     --identity "alice:user=Authorization: Bearer alice_social_token"
run api-security security_benchmark/truth/api-security.yaml http://127.0.0.1:4004/graphql

echo
echo "Done. Each run's score.json holds precision/recall/F1, FP on the negatives,"
echo "and coverage-conditioned recall (confirmed-only and confirmed+potential)."
echo "View in the dashboard, or: $PY -m prediql.cli show <run_id>"
