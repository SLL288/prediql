"""Ground-truth scoring: TP/FP/FN/TN, negative contracts, coverage-conditioning."""

from __future__ import annotations

import textwrap

import pytest

from prediql.scoring.groundtruth import GroundTruthError, certify, load
from prediql.scoring.score import score

# --------------------------------------------------------------------------
# A small ground-truth file: two vulnerable ops, one negative.
# --------------------------------------------------------------------------

TRUTH_YAML = textwrap.dedent("""
    target:
      name: Demo
      slug: demo
      schema_fingerprint: "sha256:abc"
    contracts:
      - operation: search
        vulnerable: true
        classes:
          - id: sql_injection
            evidence_kind: latency
            origin: upstream
      - operation: readFile
        vulnerable: true
        classes:
          - id: path_traversal
            evidence_kind: sentinel
            origin: upstream
      - operation: health
        vulnerable: false
""")


@pytest.fixture
def truth(tmp_path):
    path = tmp_path / "demo.yaml"
    path.write_text(TRUTH_YAML, encoding="utf-8")
    return load(path)


def _finding(operation, class_id, state="confirmed"):
    return {"operation": operation, "class": class_id, "state": state}


# --------------------------------------------------------------------------
# Loading and validation
# --------------------------------------------------------------------------


def test_loads_contracts_and_resolves_aliases(truth):
    assert truth.vulnerable_operations() == {"search", "readFile"}
    assert truth.negative_operations() == {"health"}
    assert truth.contract_for("search").class_ids() == {"sql_injection"}


def test_unknown_class_id_is_a_loud_error(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(textwrap.dedent("""
        target: {slug: bad}
        contracts:
          - operation: x
            classes: [{id: not_a_real_class}]
    """), encoding="utf-8")
    with pytest.raises(GroundTruthError, match="unknown class"):
        load(path)


def test_missing_slug_is_rejected(tmp_path):
    path = tmp_path / "noslug.yaml"
    path.write_text("target: {name: x}\ncontracts: []", encoding="utf-8")
    with pytest.raises(GroundTruthError, match="slug is required"):
        load(path)


# --------------------------------------------------------------------------
# Perfect and imperfect detection
# --------------------------------------------------------------------------


def test_perfect_detection_scores_one(truth):
    findings = [_finding("search", "sql_injection"), _finding("readFile", "path_traversal")]
    result = score(findings, truth, covered_operations={"search", "readFile", "health"})
    m = result["confirmed"]
    assert (m["tp"], m["fp"], m["fn"]) == (2, 0, 0)
    assert m["precision"] == 1.0 and m["recall"] == 1.0 and m["f1"] == 1.0


def test_a_miss_is_a_false_negative(truth):
    findings = [_finding("search", "sql_injection")]  # readFile missed
    result = score(findings, truth, covered_operations={"search", "readFile", "health"})
    m = result["confirmed"]
    assert m["tp"] == 1 and m["fn"] == 1
    assert m["recall"] == 0.5
    assert "readFile::path_traversal" in m["fn_cells"]


def test_a_finding_on_a_negative_contract_is_a_false_positive(truth):
    """The whole point of negative ground truth (v1 could not count this)."""
    findings = [
        _finding("search", "sql_injection"),
        _finding("readFile", "path_traversal"),
        _finding("health", "sql_injection"),  # health is labelled clean
    ]
    result = score(findings, truth, covered_operations={"search", "readFile", "health"})
    m = result["confirmed"]
    assert m["fp"] == 1
    assert "health::sql_injection" in m["fp_cells"]
    assert m["precision"] == pytest.approx(2 / 3, abs=1e-3)


def test_wrong_class_on_a_vulnerable_operation_is_a_false_positive(truth):
    findings = [_finding("search", "os_command_injection")]  # search is SQLi, not oscmd
    result = score(findings, truth, covered_operations={"search"})
    m = result["confirmed"]
    assert m["fp"] == 1 and m["tp"] == 0
    assert m["fn"] >= 1  # the real sql_injection was still missed


# --------------------------------------------------------------------------
# Coverage-conditioned recall
# --------------------------------------------------------------------------


def test_uncovered_misses_do_not_count_against_conditioned_recall(truth):
    """readFile was never reached -> a coverage gap, not a detection miss."""
    findings = [_finding("search", "sql_injection")]
    result = score(findings, truth, covered_operations={"search"})  # readFile NOT covered
    m = result["confirmed"]
    assert m["recall"] == 0.5, "raw recall still counts the miss"
    assert m["coverage_conditioned_recall"] == 1.0, "but not when we never reached it"
    assert "readFile::path_traversal" in m["fn_uncovered_cells"]


# --------------------------------------------------------------------------
# Two matrices: the cost of trusting potentials
# --------------------------------------------------------------------------


def test_potentials_raise_recall_but_can_wreck_precision(truth):
    findings = [
        _finding("search", "sql_injection", state="confirmed"),
        _finding("readFile", "path_traversal", state="potential"),  # a lucky potential
        _finding("health", "os_command_injection", state="potential"),  # a bogus potential
    ]
    result = score(findings, truth, covered_operations={"search", "readFile", "health"})

    assert result["confirmed"]["tp"] == 1
    assert result["confirmed"]["fp"] == 0

    wp = result["with_potential"]
    assert wp["tp"] == 2, "the potential on readFile now counts as a hit"
    assert wp["fp"] == 1, "the bogus potential on health is now a false positive"
    assert wp["precision"] == pytest.approx(2 / 3, abs=1e-3)


# --------------------------------------------------------------------------
# Partial scoring
# --------------------------------------------------------------------------


def test_partial_scoring_restricts_the_denominator(truth):
    """Score only search: readFile's miss must not count (9/10, not 9/15)."""
    findings = [_finding("search", "sql_injection")]
    result = score(findings, truth, covered_operations={"search"},
                   only_operations={"search"})
    m = result["confirmed"]
    assert result["partial"] is True
    assert result["scored_operations"] == ["search"]
    assert m["tp"] == 1 and m["fn"] == 0
    assert m["recall"] == 1.0, "readFile is out of scope, not a miss"


# --------------------------------------------------------------------------
# Unlabelled operations are reported, not silently counted
# --------------------------------------------------------------------------


def test_finding_on_an_unlabelled_operation_is_reported_separately(truth):
    findings = [_finding("mystery", "ssrf")]  # no contract for 'mystery'
    result = score(findings, truth, covered_operations={"mystery"})
    assert "mystery::ssrf" in result["unlabelled_confirmed_cells"]
    assert result["confirmed"]["fp"] == 0, "unlabelled is not automatically a false positive"


# --------------------------------------------------------------------------
# Certification
# --------------------------------------------------------------------------


def test_certify_seals_the_file_and_an_edit_unseals_it(tmp_path):
    path = tmp_path / "demo.yaml"
    path.write_text(TRUTH_YAML, encoding="utf-8")

    assert load(path).certification_status() == "uncertified"
    certified = certify(path)
    assert certified.certification_status() == "certified"
    assert certified.content_hash

    # Edit a contract after certification -> the seal must break.
    edited = path.read_text().replace("path_traversal", "os_command_injection")
    path.write_text(edited, encoding="utf-8")
    assert load(path).certification_status() == "unsealed"


def test_certify_keeps_comments_and_citations(tmp_path):
    path = tmp_path / "demo.yaml"
    path.write_text("# provenance: from the app's own tests\n" + TRUTH_YAML.replace(
        "origin: upstream", "origin: upstream   # tests/test_vulns.py::test_sqli", 1))
    certify(path)
    text = path.read_text()
    assert "# provenance: from the app's own tests" in text
    assert "# tests/test_vulns.py::test_sqli" in text
    assert load(path).certification_status() == "certified"


def test_certify_refuses_a_placeholder_schema_fingerprint(tmp_path):
    path = tmp_path / "demo.yaml"
    path.write_text(TRUTH_YAML.replace('"sha256:abc"', '"sha256:REPLACE_AFTER_FIRST_INTROSPECT"'))
    with pytest.raises(GroundTruthError, match="schema fingerprint"):
        certify(path)
    certify(path, schema_fingerprint="sha256:live")  # pinned from a run's schema
    assert load(path).schema_fingerprint == "sha256:live"


def test_certify_refuses_labels_without_an_origin(tmp_path):
    path = tmp_path / "demo.yaml"
    path.write_text(TRUTH_YAML.replace("        origin: upstream\n", "", 1))
    with pytest.raises(GroundTruthError, match="origin"):
        certify(path)


POST_HOC_YAML = TRUTH_YAML.replace(
    "      - id: path_traversal\n"
    "        evidence_kind: sentinel\n"
    "        origin: upstream\n",
    "      - id: path_traversal\n"
    "        evidence_kind: sentinel\n"
    "        origin: upstream\n"
    "      - id: os_command_injection\n"
    "        evidence_kind: sentinel\n"
    "        origin: post_hoc\n"
    "  - operation: debug\n"
    "    vulnerable: true\n"
    "    classes:\n"
    "      - id: os_command_injection\n"
    "        origin: post_hoc\n",
)
assert POST_HOC_YAML != TRUTH_YAML


def test_post_hoc_labels_are_scored_with_and_without(tmp_path):
    """A label added after seeing output must not silently turn an FP into a TP."""
    path = tmp_path / "demo.yaml"
    path.write_text(POST_HOC_YAML)
    findings = [_finding("readFile", "os_command_injection"), _finding("debug", "os_command_injection")]
    result = score(findings, load(path))
    assert result["confirmed"]["tp"] == 2 and result["confirmed"]["fp"] == 0
    assert result["post_hoc_labels"] == ["debug::os_command_injection",
                                         "readFile::os_command_injection"]
    before = result["without_post_hoc"]
    # readFile was labelled for path traversal only: the finding was an FP.
    assert before["confirmed"]["fp_cells"] == ["readFile::os_command_injection"]
    # debug had no contract at all: the finding was unlabelled, not an FP.
    assert before["unlabelled_confirmed_cells"] == ["debug::os_command_injection"]


def test_by_class_agrees_with_the_matrix_on_unlabelled_operations(truth):
    result = score([_finding("unlabelled", "os_command_injection")], truth)
    assert result["confirmed"]["fp"] == 0
    assert result["by_class"].get("os_command_injection", {}).get("fp", 0) == 0
    assert result["unlabelled_confirmed_cells"] == ["unlabelled::os_command_injection"]


def test_score_reports_certification_status(truth):
    result = score([], truth)
    assert result["certification"] == "uncertified"
