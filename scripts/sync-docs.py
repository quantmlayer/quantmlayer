#!/usr/bin/env python3
"""scripts/sync-docs.py — keep the README's generated regions truthful.

Two things in the README are copies of data that lives somewhere else: the
test-count badge (from `cargo test`) and the attack matrix (from
`benchmark/RESULTS.md`, which `ql-bench` writes). Hand-copied data rots
silently — the badge went stale twice in two releases (186 -> 225 -> 239),
and the matrix was six rows while RESULTS.md had eight.

This script regenerates both between markers. `--check` verifies without
writing, so CI can fail on drift the way `cargo fmt --check` does; that is
the part that actually prevents recurrence, since nobody remembers to run a
sync script by hand.

Usage:
    scripts/sync-docs.py            # rewrite the generated regions
    scripts/sync-docs.py --check    # exit 1 if they are out of date
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
RESULTS = ROOT / "benchmark" / "RESULTS.md"

BADGE_RE = re.compile(
    r"!\[tests\]\(https://img\.shields\.io/badge/tests-\d+%20passing-brightgreen\.svg\)"
)
TABLE_BEGIN = "<!-- BEGIN generated: attack-matrix (scripts/sync-docs.py) -->"
TABLE_END = "<!-- END generated: attack-matrix -->"


def count_tests() -> int:
    """Total passing tests across the workspace, from cargo's own output.

    Parsed rather than hand-maintained: the number changes on nearly every
    change, which makes drift the default state otherwise.
    """
    out = subprocess.run(
        ["cargo", "test", "--workspace"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    # cargo prints one "test result:" line per target; sum the passed counts.
    total = 0
    for line in (out.stdout + out.stderr).splitlines():
        m = re.search(r"test result: ok\. (\d+) passed", line)
        if m:
            total += int(m.group(1))
    if total == 0:
        sys.exit("sync-docs: could not read a test count from cargo output")
    return total


def attack_matrix() -> str:
    """The attack table from benchmark/RESULTS.md, which ql-bench generates.

    Taking it from RESULTS.md rather than re-running the benchmark keeps one
    source of truth and means this script needs no privileged box.
    """
    if not RESULTS.exists():
        sys.exit(f"sync-docs: {RESULTS} not found")
    rows = [
        line
        for line in RESULTS.read_text().splitlines()
        if line.startswith("| ") and "---" not in line
    ]
    if len(rows) < 2:
        sys.exit("sync-docs: no attack table found in benchmark/RESULTS.md")
    header, body = rows[0], rows[1:]
    sep = "|" + "|".join(["---"] * (header.count("|") - 1)) + "|"
    return "\n".join([header, sep, *body])


def render(text: str) -> str:
    """Return `text` with every generated region refreshed."""
    n = count_tests()
    text = BADGE_RE.sub(
        f"![tests](https://img.shields.io/badge/tests-{n}%20passing-brightgreen.svg)",
        text,
        count=1,
    )
    if TABLE_BEGIN in text and TABLE_END in text:
        start = text.index(TABLE_BEGIN) + len(TABLE_BEGIN)
        end = text.index(TABLE_END)
        text = text[:start] + "\n" + attack_matrix() + "\n" + text[end:]
    return text


def main() -> int:
    check = "--check" in sys.argv
    current = README.read_text()
    updated = render(current)

    if current == updated:
        print("sync-docs: README is up to date")
        return 0
    if check:
        print(
            "sync-docs: README is out of date — run `make sync-docs` and commit "
            "the result.",
            file=sys.stderr,
        )
        return 1
    README.write_text(updated)
    print("sync-docs: README updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
