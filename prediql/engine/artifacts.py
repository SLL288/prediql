"""Artifact keys.

Centralised so a step's ``requires``/``produces`` contract is checked against
constants rather than string literals — a typo becomes an import error instead of
an unsatisfiable plan discovered at run time.
"""

from __future__ import annotations

SCHEMA_RAW = "schema.raw"
SCHEMA = "schema.normalized"
GRAPH = "graph"
IDENTITIES = "identities.live"
COVERAGE = "coverage"
BUCKET = "bucket"
KNOWN_GOOD = "known_good"
BASELINE = "baseline"
BANDIT = "bandit"
CHAINS = "chains"
PROBE_RESULTS = "probe_results"
CHAIN_RESULTS = "chain_results"
FINDINGS = "findings"
SCORE = "score"
REPORT = "report"
