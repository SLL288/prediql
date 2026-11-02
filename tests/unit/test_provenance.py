"""Provenance: runs name the code that produced them, and labels that scored them."""

from __future__ import annotations

import json

import pytest

from prediql.engine import provenance
from prediql.engine.config import RunConfig
from prediql.engine.context import RunContext
from prediql.engine.steps.score import ScoreStep


def test_code_version_names_a_commit():
    version = provenance.code_version()
    commit = version.split("+", 1)[0]
    assert commit == "unknown" or len(commit) == 12
    assert ("+dirty." in version) == provenance.is_dirty()


def test_manifest_records_provenance(tmp_path):
    ctx = RunContext(RunConfig(target_url="https://x.test/graphql", code_version="abc"),
                     runs_root=tmp_path)
    ctx.write_manifest()
    manifest = json.loads((ctx.run_dir / "manifest.json").read_text())
    assert manifest["config"]["code_version"] == "abc"
    assert {"commit", "dirty", "python", "packages"} <= set(manifest["provenance"])


def test_editing_the_truth_file_invalidates_the_score(tmp_path):
    """A label edit must re-score; the path alone would leave a stale score."""
    truth = tmp_path / "truth.yaml"
    truth.write_text("contracts: []\n")
    ctx = RunContext(RunConfig(target_url="https://x.test/graphql", truth_path=str(truth)),
                     runs_root=tmp_path / "runs")
    before = ScoreStep().config_signature(ctx)
    truth.write_text("contracts: [{operation: x}]\n")
    assert ScoreStep().config_signature(ctx) != before


def test_attaching_to_a_run_keeps_its_manifest(tmp_path):
    """Re-scoring must reach the named run and never overwrite how it was produced."""
    original = RunContext(RunConfig(target_url="https://x.test/graphql", alias="dvga", trial=2),
                          runs_root=tmp_path)
    original.write_manifest({"plan": ["introspect"]})

    rescore = RunContext(RunConfig(target_url="https://x.test/graphql", mode="score"),
                         runs_root=tmp_path, run_id=original.run_id)
    assert rescore.run_dir == original.run_dir
    rescore.write_manifest({"plan": ["score"]})
    manifest = json.loads((original.run_dir / "manifest.json").read_text())
    assert manifest["config"]["alias"] == "dvga" and manifest["plan"] == ["introspect"]
    assert manifest["reprocessed"][0]["plan"] == ["score"]

    with pytest.raises(FileNotFoundError):
        RunContext(RunConfig(target_url="https://x.test/graphql"), runs_root=tmp_path,
                   run_id="no-such-run")
