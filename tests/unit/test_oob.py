"""OOB callback oracle: blind SSRF / command-exec confirmation (S3)."""
import urllib.request

from prediql.oracle.evidence import Evidence, Expectation, Oracle, Verdict
from prediql.oracle.witness import RequestRecord  # noqa: F401 (import sanity)
from prediql.security.oob import OOBServer
from prediql.targets.base import HttpResult


def _result():
    return HttpResult(document="{ x }", identity="anon", status=200,
                      body={"data": {"x": None}}, elapsed_ms=5.0)


def test_oob_server_records_only_tokens_it_was_hit_with():
    with OOBServer(host="127.0.0.1") as oob:
        tok = oob.new_token()
        assert not oob.seen(tok)
        urllib.request.urlopen(oob.url_for(tok), timeout=5).read()
        assert oob.seen(tok)
        assert not oob.seen(oob.new_token())   # a token never delivered


def test_callback_confirms_only_after_the_collaborator_is_hit():
    with OOBServer(host="127.0.0.1") as oob:
        oracle = Oracle(oob=oob)
        tok = oob.new_token()
        exp = Expectation("ssrf", Evidence.CALLBACK, token=tok)

        # No callback yet -> not confirmed.
        j = oracle.judge(exp, _result())
        assert j.verdict is not Verdict.CONFIRMED

        # The target "fetches" our URL (SSRF), then the same probe confirms.
        urllib.request.urlopen(oob.url_for(tok), timeout=5).read()
        j2 = oracle.judge(exp, _result())
        assert j2.confirmed and j2.evidence is Evidence.CALLBACK


def test_callback_without_an_oob_server_is_never_confirmed():
    oracle = Oracle()  # no collaborator configured
    exp = Expectation("ssrf", Evidence.CALLBACK, token="pqloobdeadbeef")
    assert oracle.judge(exp, _result()).verdict is not Verdict.CONFIRMED
