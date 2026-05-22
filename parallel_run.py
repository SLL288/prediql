#!/usr/bin/env python3
"""
Run ``main.py`` for multiple GraphQL URLs in parallel.

Each URL runs in its **own subprocess** with the same CLI flags you would pass
to ``main.py`` (separate ``output/<slug>/<model>/`` trees — no shared Config).

Usage::

    python parallel_run.py --urls-file urls.txt --workers 4 -- \\
        --requests 5 --rounds 2

    python parallel_run.py --url https://a.com/graphql --url https://b.com/graphql -- \\
        --requests 3 --rounds 1 --llm-model llama3.1:8b

The ``--`` separator is required so arguments intended for ``main.py`` are not
parsed by this launcher.
"""

from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from subprocess import CompletedProcess, run
from typing import List, Sequence
from urllib.parse import urlparse

_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
_MAIN_PY = os.path.join(_REPO_ROOT, "main.py")


def _graphql_url_line(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        raise ValueError("empty URL")
    p = urlparse(s)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise ValueError(f"invalid GraphQL URL (need http(s) + host): {raw!r}")
    return s


def read_urls_file(path: str) -> List[str]:
    urls: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            s = line.split("#", 1)[0].strip()
            if not s:
                continue
            try:
                urls.append(_graphql_url_line(s))
            except ValueError as e:
                raise SystemExit(f"{path}:{lineno}: {e}") from e
    return urls


def _default_workers(n_urls: int) -> int:
    cpu = os.cpu_count() or 4
    return max(1, min(n_urls, 8, cpu))


def _run_main_subprocess(
    url: str,
    main_argv: Sequence[str],
    *,
    capture: bool,
) -> CompletedProcess:
    cmd = [sys.executable, _MAIN_PY, "--url", url, *main_argv]
    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    if capture:
        return run(
            cmd,
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            env=env,
        )
    print(f"\n{'=' * 72}\n▶ START {url}\n{'=' * 72}", flush=True)
    return run(cmd, cwd=_REPO_ROOT, env=env)


def main(argv: List[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" not in argv:
        if not argv or set(argv) <= {"-h", "--help"}:
            print(__doc__.strip())
            print(
                "\nLauncher: --urls-file PATH | --url URL (repeat)  [--workers N]  [--dry-run]  [--no-capture]\n"
                "Then a mandatory ``--`` separator, then all arguments for main.py "
                "(e.g. ``--requests 5 --rounds 2``).\n"
            )
            return 0 if argv else 2
        print(
            "Usage:\n"
            "  python parallel_run.py --urls-file URLS.txt [--workers N] [--dry-run] -- "
            "<main.py args>\n\n"
            "Example:\n"
            "  python parallel_run.py --urls-file urls.txt --workers 3 -- "
            "--requests 5 --rounds 2\n\n"
            "Include a literal ``--`` before arguments passed to main.py.",
            file=sys.stderr,
        )
        return 2

    sep = argv.index("--")
    launcher_argv = argv[:sep]
    main_argv = argv[sep + 1 :]

    ap = argparse.ArgumentParser(
        description="Run main.py for multiple GraphQL URLs in parallel (one subprocess per URL).",
    )
    ap.add_argument(
        "--urls-file",
        metavar="PATH",
        help="Text file: one http(s) GraphQL URL per line (# comments allowed)",
    )
    ap.add_argument(
        "--url",
        action="append",
        default=[],
        dest="urls",
        metavar="URL",
        help="GraphQL URL (repeat flag for multiple endpoints)",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=None,
        metavar="N",
        help="Concurrent subprocesses (default: min(8, CPU count, number of URLs))",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned commands and exit without running",
    )
    ap.add_argument(
        "--no-capture",
        action="store_true",
        help="Do not capture child output (live interleaved logs; harder to attribute per URL)",
    )
    args = ap.parse_args(launcher_argv)

    urls: List[str] = []
    if args.urls_file:
        urls.extend(read_urls_file(args.urls_file))
    for u in args.urls:
        try:
            urls.append(_graphql_url_line(u))
        except ValueError as e:
            print(f"❌ Bad --url: {e}", file=sys.stderr)
            return 2

    if not urls:
        print("❌ No URLs: pass --urls-file and/or one or more --url", file=sys.stderr)
        return 2

    if not main_argv:
        print("❌ No arguments after ``--`` for main.py (need at least --requests and --rounds).", file=sys.stderr)
        return 2

    workers = args.workers if args.workers is not None else _default_workers(len(urls))
    workers = max(1, min(workers, len(urls)))

    print(f"Parallel run: {len(urls)} URL(s), {workers} worker(s), main.py argv: {main_argv!r}")

    if args.dry_run:
        for u in urls:
            print(f"  DRY-RUN: {sys.executable} {_MAIN_PY} --url {u!r} ...")
        return 0

    capture = not args.no_capture
    failures: List[str] = []

    def job(url: str) -> CompletedProcess[str]:
        return _run_main_subprocess(url, main_argv, capture=capture)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(job, u): u for u in urls}
        for fut in as_completed(futures):
            u = futures[fut]
            try:
                cp = fut.result()
            except Exception as e:
                print(f"❌ [{u}] launcher error: {e!r}", flush=True)
                failures.append(u)
                continue
            code = cp.returncode or 0
            if code == 0:
                print(f"✅ [{u}] main.py exit 0", flush=True)
            else:
                print(f"❌ [{u}] main.py exit {code}", flush=True)
                failures.append(u)
                if capture and (cp.stdout or cp.stderr):
                    tail = ((cp.stdout or "") + "\n" + (cp.stderr or ""))[-8000:]
                    if tail.strip():
                        print(f"--- tail ({u}) ---\n{tail}", flush=True)

    if failures:
        print(f"\n❌ {len(failures)} run(s) failed: {failures}", flush=True)
        return 1
    print("\n✅ All parallel runs finished successfully.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
