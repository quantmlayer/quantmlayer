#!/usr/bin/env python3
"""scripts/sync-docs.py — keep the README's generated regions truthful.

The README embeds the attack matrix from `benchmark/RESULTS.md`, which
`ql-bench` writes. Hand-copied data rots silently: the matrix sat at six rows
while RESULTS.md had eight. This regenerates it between markers, and
`--check` fails on drift so CI catches it the way `cargo fmt --check` does.

**A test-count badge used to live here and was removed.** Counting is not as
simple as it looks — summing cargo's `test result:` lines and counting its
`^test ` lines disagree with each other on the same machine (243 vs 269),
because ignored and filtered tests appear in one and not the other. A number
that cannot be derived unambiguously does not belong in a badge that implies
precision, and it carried no claim about containment anyway. The matrix does
carry a claim, which is why it is what gets gated.

Usage:
    scripts/sync-docs.py            # rewrite the generated regions
    scripts/sync-docs.py --check    # exit 1 if they are out of date
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
RESULTS = ROOT / "benchmark" / "RESULTS.md"

TABLE_BEGIN = "<!-- BEGIN generated: attack-matrix (scripts/sync-docs.py) -->"
TABLE_END = "<!-- END generated: attack-matrix -->"


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
    """Return `text` with the generated regions refreshed."""
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
        print("sync-docs: attack matrix is current")
        return 0
    if check:
        print(
            "sync-docs: the README's attack matrix does not match "
            "benchmark/RESULTS.md — run `make sync-docs` and commit the result.",
            file=sys.stderr,
        )
        return 1
    README.write_text(updated)
    print("sync-docs: README updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
