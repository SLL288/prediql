#!/usr/bin/env python3
"""
Offline Jaccard overlap: compare two newline-separated lists of finding keys.

Example::

    echo -e "sql injection\\nxss" > a.txt
    echo -e "sql injection\\npath" > b.txt
    python3 overlap_analysis.py a.txt b.txt

Uses the same Jaccard definition as ``finding_jaccard.jaccard_coefficient``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from finding_jaccard import jaccard_coefficient


def _load_keys(path: Path) -> set[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return {ln.strip().lower() for ln in lines if ln.strip()}


def main() -> int:
    p = argparse.ArgumentParser(description="Jaccard overlap between two finding-key files.")
    p.add_argument("file_a", type=Path, help="Text file: one normalized finding key per line")
    p.add_argument("file_b", type=Path, help="Text file: one normalized finding key per line")
    p.add_argument("--label-a", default="A", help="Label for set A")
    p.add_argument("--label-b", default="B", help="Label for set B")
    args = p.parse_args()

    if not args.file_a.is_file() or not args.file_b.is_file():
        print("Both inputs must be existing files.", file=sys.stderr)
        return 1

    sa = _load_keys(args.file_a)
    sb = _load_keys(args.file_b)
    m = jaccard_coefficient(sa, sb)
    print(f"Labels: {args.label_a} (|A|={m['|A|']}) vs {args.label_b} (|B|={m['|B|']})")
    print(f"|A ∩ B| = {m['|A ∩ B|']},  |A ∪ B| = {m['|A ∪ B|']}")
    print(f"Jaccard = {m['jaccard']}  ({m['formula']})")
    print(f"Note: {m['note']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
