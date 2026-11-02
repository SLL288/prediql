"""Ensemble judging: median + agreement over K samples, medoid narrative."""

from __future__ import annotations

from itertools import cycle

from prediql.providers.echo import EchoProvider
from prediql.providers.router import Router
from prediql.security.judge import judge_finding

FINDING = {"class": "xss_reflected", "operation": "echo",
           "witness": {"matched": "reflected", "requests": [{"document": "q"}]}}


def _router(scripted):
    """A router whose judge cycles through scripted verdicts."""
    it = cycle(scripted)
    return Router({"judge": EchoProvider(responder=lambda r: next(it))})


async def test_single_sample_has_no_ensemble_block():
    router = _router([{"is_vulnerability": True, "confidence": 0.8, "rationale": "x"}])
    v = await judge_finding(router, FINDING, samples=1)
    assert v["agrees"] is True and "ensemble" not in v


async def test_majority_vote_decides_agrees():
    # 2 of 3 say real -> majority real.
    router = _router([
        {"is_vulnerability": True, "confidence": 0.7, "rationale": "real-1"},
        {"is_vulnerability": True, "confidence": 0.9, "rationale": "real-2"},
        {"is_vulnerability": False, "confidence": 0.6, "rationale": "not"},
    ])
    v = await judge_finding(router, FINDING, samples=3)
    assert v["agrees"] is True
    assert v["ensemble"]["samples"] == 3
    assert v["ensemble"]["real_votes"] == 2
    assert v["ensemble"]["agreement"] == round(2 / 3, 2)


async def test_confidence_is_the_median_and_rationale_is_the_medoid():
    router = _router([
        {"is_vulnerability": False, "confidence": 0.2, "rationale": "low"},
        {"is_vulnerability": False, "confidence": 0.5, "rationale": "medoid"},
        {"is_vulnerability": False, "confidence": 0.9, "rationale": "high"},
    ])
    v = await judge_finding(router, FINDING, samples=3)
    assert v["confidence"] == 0.5, "median of {0.2, 0.5, 0.9}"
    assert v["rationale"] == "medoid", "narrative comes from the median sample"
    assert v["ensemble"]["confidence_spread"] == round(0.9 - 0.2, 2)


async def test_unanimous_agreement_is_one():
    router = _router([{"is_vulnerability": False, "confidence": 0.95, "rationale": "no"}])
    v = await judge_finding(router, FINDING, samples=3)
    assert v["agrees"] is False
    assert v["ensemble"]["agreement"] == 1.0, "3/3 agree -> full agreement"


async def test_split_vote_lowers_agreement():
    router = _router([
        {"is_vulnerability": True, "confidence": 0.6, "rationale": "a"},
        {"is_vulnerability": False, "confidence": 0.6, "rationale": "b"},
    ])
    v = await judge_finding(router, FINDING, samples=2)
    # a tie: majority_real is False (2 not > 1); agreement counts the losing side too
    assert v["ensemble"]["agreement"] == 0.5
