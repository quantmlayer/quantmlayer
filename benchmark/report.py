#!/usr/bin/env python3
"""Render the QuantmLayer benchmark results into CSV (and a plot if matplotlib
is available).

The Rust harness (`ql-bench`) is the source of truth: it runs the attacks and
writes `results.json`. This script is presentation-only — it never decides
whether an attack was blocked, so the numbers cannot drift from what was
actually measured.

Usage:
    python3 benchmark/report.py [benchmark/results.json]
"""

import csv
import json
import sys
from pathlib import Path


def load_results(path: Path) -> dict:
    """Load the harness output. Fail loudly if it is missing — that means the
    Rust harness was not run, and a stale report would be misleading."""
    if not path.exists():
        sys.exit(
            f"error: {path} not found. Run the harness first:\n"
            f"    cargo run -p ql-bench -- --out {path.parent}"
        )
    with path.open() as f:
        return json.load(f)


def write_csv(results: dict, out_path: Path) -> None:
    """Write a flat CSV: one row per attack, one column per backend."""
    backends = results["backends"]
    with out_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["attack_id", "title", "wall", *backends])
        for atk in results["attacks"]:
            outcomes = [atk["outcomes"].get(b, "n/a") for b in backends]
            writer.writerow([atk["id"], atk["title"], atk["wall"], *outcomes])
    print(f"wrote {out_path}")


def try_plot(results: dict, out_path: Path) -> None:
    """Render a simple blocked/vulnerable/pending bar chart per backend.

    Degrades gracefully: if matplotlib is not installed we simply skip the
    plot rather than failing the whole report.
    """
    try:
        import matplotlib

        matplotlib.use("Agg")  # headless
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not available; skipping plot (CSV + table still produced)")
        return

    backends = results["backends"]
    states = ["blocked", "vulnerable", "pending", "unsupported"]
    counts = {b: {s: 0 for s in states} for b in backends}
    for atk in results["attacks"]:
        for b in backends:
            counts[b][atk["outcomes"].get(b, "pending")] += 1

    fig, ax = plt.subplots(figsize=(7, 4))
    bottom = {b: 0 for b in backends}
    colors = {
        "blocked": "#2e7d32",
        "vulnerable": "#c62828",
        "pending": "#9e9e9e",
        "unsupported": "#cfcfcf",
    }
    for s in states:
        vals = [counts[b][s] for b in backends]
        ax.bar(backends, vals, bottom=[bottom[b] for b in backends],
               label=s, color=colors[s])
        for b, v in zip(backends, vals):
            bottom[b] += v
    ax.set_ylabel("attacks")
    ax.set_title("QuantmLayer attack benchmark")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=120)
    print(f"wrote {out_path}")


def main() -> None:
    json_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("benchmark/results.json")
    results = load_results(json_path)
    out_dir = json_path.parent
    write_csv(results, out_dir / "results.csv")
    try_plot(results, out_dir / "results.png")


if __name__ == "__main__":
    main()
