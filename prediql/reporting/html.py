"""Self-contained HTML report (doc 05 §4).

A standalone, offline file: embedded CSS/JS, no external requests, theme-aware.
The design principle is the brief's — a finding is understandable without reading
the code: class in plain language, why it matters, the exact request that proves
it, the response that confirms it, and how to reproduce, with severity and triage
state front and centre.
"""

from __future__ import annotations

import html
import json
from typing import Any

from prediql.scoring.classes import get

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _known_title(class_id: str) -> str:
    try:
        return get(class_id).title
    except KeyError:
        return class_id


def render(
    *,
    target: str,
    run_id: str,
    coverage: dict[str, Any] | None,
    findings: dict[str, Any],
    score: dict[str, Any] | None,
    budget: dict[str, Any] | None,
) -> str:
    rows = findings.get("findings", [])
    confirmed = [f for f in rows if f["state"] == "confirmed"]
    potential = [f for f in rows if f["state"] == "potential"]

    return "\n".join([
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>PrediQL — {_esc(target)}</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        _header(target, run_id),
        _summary(coverage, findings, score, budget),
        _severity_bar(confirmed),
        _findings_section("Confirmed findings", confirmed, empty="No confirmed findings."),
        _findings_section("Potential findings (need triage)", potential,
                          empty="No potential findings."),
        _footer(),
        f"<script>{_JS}</script>",
        "</body></html>",
    ])


def _header(target: str, run_id: str) -> str:
    return (
        '<header class="topbar">'
        '<div class="wrap">'
        '<span class="brand">PrediQL<b>2</b></span>'
        f'<span class="target">{_esc(target)}</span>'
        f'<span class="runid">{_esc(run_id)}</span>'
        '<button id="theme" class="theme" type="button">◐</button>'
        "</div></header>"
    )


def _summary(coverage, findings, score, budget) -> str:
    cards = []
    if coverage:
        cards.append(_kpi("operation coverage",
                          _pct(coverage.get("operation_coverage")),
                          f"{coverage.get('operations_covered')}/{coverage.get('operations_total')} ops"))
        cards.append(_kpi("element coverage", _pct(coverage.get("element_coverage")),
                          f"{coverage.get('elements_covered')}/{coverage.get('elements_total')} fields"))
    cards.append(_kpi("confirmed", str(findings.get("confirmed", 0)),
                      f"{findings.get('potential', 0)} potential", tone="fail"
                      if findings.get("confirmed") else "ok"))
    if score and score.get("confirmed"):
        m = score["confirmed"]
        cards.append(_kpi("precision", _pct(m["precision"]), f"F1 {_pct(m['f1'])}"))
        cards.append(_kpi("recall", _pct(m["recall"]),
                          f"cov-cond. {_pct(m['coverage_conditioned_recall'])}"))
    if budget and budget.get("total"):
        t = budget["total"]
        cards.append(_kpi("tokens", f"{t.get('total_tokens', 0):,}",
                          f"${t.get('usd', 0)} · {t.get('calls', 0)} calls"))
    return '<section class="wrap kpis">' + "".join(cards) + "</section>"


def _kpi(label, value, sub, tone="") -> str:
    cls = f"kpi {tone}" if tone else "kpi"
    return (f'<div class="{cls}"><div class="kpi-label">{_esc(label)}</div>'
            f'<div class="kpi-value">{_esc(value)}</div>'
            f'<div class="kpi-sub">{_esc(sub)}</div></div>')


def _severity_bar(confirmed) -> str:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in confirmed:
        counts[f.get("severity", "medium")] = counts.get(f.get("severity", "medium"), 0) + 1
    if not confirmed:
        return ""
    chips = "".join(
        f'<span class="sev-chip sev-{sev}">{count} {sev}</span>'
        for sev, count in counts.items() if count
    )
    return f'<section class="wrap sevbar">{chips}</section>'


def _findings_section(title: str, findings: list[dict[str, Any]], *, empty: str) -> str:
    ordered = sorted(findings, key=lambda f: (_SEV_ORDER.get(f.get("severity", "medium"), 4),
                                              f.get("class", "")))
    body = "".join(_finding_card(f) for f in ordered) or f'<p class="empty">{_esc(empty)}</p>'
    return (f'<section class="wrap"><h2>{_esc(title)} '
            f'<span class="count">{len(findings)}</span></h2>{body}</section>')


def _finding_card(f: dict[str, Any]) -> str:
    sev = f.get("severity", "medium")
    witness = f.get("witness") or {}
    title = f.get("title") or _known_title(f.get("class", ""))

    parts = [f'<article class="finding sev-border-{sev}">']
    parts.append('<div class="finding-head" onclick="this.parentElement.classList.toggle(\'open\')">')
    parts.append(f'<span class="sev-tag sev-{sev}">{_esc(sev)}</span>')
    parts.append(f'<span class="finding-title">{_esc(title)}</span>')
    parts.append(f'<code class="finding-op">{_esc(f.get("operation", ""))}</code>')
    parts.append(f'<span class="state state-{f.get("state","")}">{_esc(f.get("state",""))}</span>')
    parts.append('<span class="chev">▾</span></div>')

    parts.append('<div class="finding-body">')
    parts.append(f'<p class="why">{_esc(_why(f.get("class","")))}</p>')

    # Evidence
    if witness.get("matched"):
        parts.append(f'<div class="evidence"><span class="lbl">evidence</span>'
                     f'<span>{_esc(witness["matched"])}</span></div>')

    # Chain steps, if any
    chain = f.get("chain")
    if chain:
        steps = " → ".join(f'<code>{_esc(s.get("identity",""))}:{_esc(s["operation"])}</code>'
                           for s in chain)
        parts.append(f'<div class="chain"><span class="lbl">chain</span>{steps}</div>')

    # The request(s) that prove it
    for i, req in enumerate(witness.get("requests") or []):
        label = "request" if len(witness.get("requests") or []) == 1 else f"step {i+1}"
        ident = req.get("identity", "")
        parts.append(f'<div class="block"><span class="lbl">{label}'
                     f'{f" · {_esc(ident)}" if ident else ""}</span>'
                     f'<pre>{_esc(req.get("document",""))}</pre></div>')

    # Response excerpt
    excerpt = witness.get("response_excerpt")
    if excerpt:
        parts.append(f'<div class="block"><span class="lbl">response</span>'
                     f'<pre>{_esc(excerpt)}</pre></div>')

    # LLM judge, when present — shown alongside the oracle, never replacing it
    judge = f.get("judge_verdict")
    if judge:
        agree = "agrees" if judge.get("agrees") else "disagrees"
        ens = judge.get("ensemble")
        band = (f' · {ens["real_votes"]}/{ens["samples"]} say real, '
                f'agreement {ens["agreement"]}') if ens else ""
        parts.append(f'<div class="judge"><span class="lbl">LLM judge'
                     f'{" ×" + str(ens["samples"]) if ens else ""}</span>'
                     f'<span class="judge-{agree}">{_esc(agree)}</span> '
                     f'<span class="judge-conf">conf {judge.get("confidence","?")}{_esc(band)}</span>'
                     f'<p>{_esc(judge.get("rationale",""))}</p></div>')

    # Reproduction
    if f.get("repro"):
        parts.append(f'<div class="repro"><span class="lbl">reproduce</span>'
                     f'<code>{_esc(f["repro"])}</code></div>')

    parts.append("</div></article>")
    return "".join(parts)


def _why(class_id: str) -> str:
    return {
        "sql_injection": "Attacker input reaches a SQL evaluator, allowing data theft or tampering.",
        "os_command_injection": "Attacker input reaches a shell — arbitrary command execution.",
        "path_traversal": "A file path escapes its intended directory, leaking arbitrary files.",
        "xss_reflected": "Injected markup is reflected unescaped and could execute in a browser.",
        "xss_stored": "Injected markup is stored and served to other users.",
        "ssrf": "The server can be induced to make requests to attacker-chosen destinations.",
        "idor": "One user can access another user's resource by supplying its identifier.",
        "uaf": "A deleted resource remains readable — a phantom-resource disclosure.",
        "denial_of_service": "A crafted query amplifies server cost with no complexity limit.",
        "introspection_enabled": "The schema is fully discoverable, aiding an attacker's mapping.",
    }.get(class_id, "See the evidence below.")


def _footer() -> str:
    return ('<footer class="wrap"><p>Generated by PrediQL · every confirmed finding is backed '
            'by a deterministic evidence oracle and a reproducible witness.</p></footer>')


def _pct(value) -> str:
    return "—" if value is None else f"{value:.1%}"


_CSS = """
:root{--bg:#f6f7f9;--surface:#fff;--line:#e2e6ec;--txt:#1a2230;--dim:#5b6675;--faint:#8a94a3;
--crit:#c0392b;--high:#d35400;--med:#b7950b;--low:#2471a3;--ok:#1e8a5a;--fail:#c0392b;--accent:#2c7;}
@media (prefers-color-scheme:dark){:root{--bg:#0e131b;--surface:#161d28;--line:#28323f;
--txt:#dde5ef;--dim:#9aa8bc;--faint:#6a7789;--crit:#ff6b6b;--high:#ff9f45;--med:#f2c94c;
--low:#7aa2f7;--ok:#4ade80;--fail:#ff6b6b;}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:0 20px}
.topbar{background:var(--surface);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
.topbar .wrap{display:flex;align-items:center;gap:14px;height:52px}
.brand{font-weight:800;letter-spacing:-.02em}.brand b{color:var(--accent)}
.target{font-weight:600}.runid{color:var(--faint);font:12px ui-monospace,monospace;margin-left:auto}
.theme{background:none;border:1px solid var(--line);border-radius:6px;color:var(--dim);
cursor:pointer;padding:4px 8px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:22px auto}
.kpi{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.kpi.fail{border-color:var(--fail)}.kpi.ok .kpi-value{color:var(--ok)}
.kpi-label{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--faint)}
.kpi-value{font-size:26px;font-weight:700;margin:4px 0;font-variant-numeric:tabular-nums}
.kpi.fail .kpi-value{color:var(--fail)}.kpi-sub{font-size:12px;color:var(--dim)}
.sevbar{display:flex;gap:8px;margin:4px auto 8px}
.sev-chip{font-size:12px;padding:3px 10px;border-radius:999px;font-weight:600;color:#fff}
h2{font-size:19px;margin:26px 0 12px;display:flex;align-items:center;gap:8px}
.count{font-size:13px;background:var(--line);color:var(--dim);border-radius:999px;padding:1px 9px}
.empty{color:var(--faint)}
.finding{background:var(--surface);border:1px solid var(--line);border-left-width:4px;
border-radius:10px;margin-bottom:10px;overflow:hidden}
.sev-border-critical{border-left-color:var(--crit)}.sev-border-high{border-left-color:var(--high)}
.sev-border-medium{border-left-color:var(--med)}.sev-border-low{border-left-color:var(--low)}
.finding-head{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;user-select:none}
.sev-tag{font-size:11px;text-transform:uppercase;font-weight:700;padding:2px 8px;border-radius:5px;color:#fff}
.sev-critical{background:var(--crit)}.sev-high{background:var(--high)}
.sev-medium{background:var(--med)}.sev-low{background:var(--low)}
.finding-title{font-weight:650}.finding-op{font:13px ui-monospace,monospace;color:var(--dim);
background:var(--bg);padding:2px 7px;border-radius:5px}
.state{margin-left:auto;font-size:12px;font-weight:600}
.state-confirmed{color:var(--fail)}.state-potential{color:var(--med)}
.chev{color:var(--faint);transition:transform .15s}.finding.open .chev{transform:rotate(180deg)}
.finding-body{display:none;padding:0 16px 16px;border-top:1px solid var(--line)}
.finding.open .finding-body{display:block}
.why{color:var(--dim);margin:12px 0}
.lbl{display:inline-block;font-size:11px;text-transform:uppercase;letter-spacing:.06em;
color:var(--faint);margin-right:8px;min-width:74px}
.evidence,.chain,.judge,.repro{margin:8px 0;font-size:14px}
.block{margin:10px 0}.block pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;
padding:10px 12px;overflow-x:auto;font:12.5px ui-monospace,monospace;margin:4px 0;white-space:pre-wrap;
word-break:break-word}
.chain code,.repro code,.evidence code{font:12.5px ui-monospace,monospace;background:var(--bg);
padding:2px 6px;border-radius:5px}
.judge-agrees{color:var(--ok);font-weight:600}.judge-disagrees{color:var(--high);font-weight:600}
.judge-conf{color:var(--faint);font-size:12px}.judge p{color:var(--dim);margin:4px 0 0}
footer{color:var(--faint);font-size:13px;margin:30px auto;padding-bottom:40px}
.sev-chip.sev-critical{background:var(--crit)}.sev-chip.sev-high{background:var(--high)}
.sev-chip.sev-medium{background:var(--med)}.sev-chip.sev-low{background:var(--low)}
"""

_JS = """
(function(){
  var b=document.getElementById('theme');
  if(b)b.addEventListener('click',function(){
    var r=document.documentElement, d=r.getAttribute('data-theme');
    var dark=d?d==='dark':matchMedia('(prefers-color-scheme: dark)').matches;
    r.setAttribute('data-theme',dark?'light':'dark');
    document.body.style.colorScheme=dark?'light':'dark';
  });
  // open the first confirmed finding by default
  var first=document.querySelector('.finding');
  if(first)first.classList.add('open');
})();
"""
