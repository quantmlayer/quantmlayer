#!/usr/bin/env python3
"""ql-matrix-table.py — tabulate QuantmLayer capability bundles into a matrix.

Reads the JSON bundles written by ql-matrix-run.sh (one per host/substrate) and
renders the portability matrix: which of the six walls hold and which
exec-enforcement tier is active on each substrate. Standard library only.

Usage:
  scripts/ql-matrix-table.py [DIR] [--format text|md]
  DIR defaults to ./ql-matrix
"""
import argparse
import json
import sys
from pathlib import Path

WALLS = ["namespaces", "capabilities", "seccomp", "cgroups_v2", "network", "exec_wall"]
WALL_ABBR = {
    "namespaces": "ns",
    "capabilities": "cap",
    "seccomp": "sec",
    "cgroups_v2": "cg",
    "network": "net",
    "exec_wall": "exec",
}
SYM = {"ok": "o", "degraded": "~", "off": "x", "unknown": "?"}
TIERS = ["tier1_bpf_lsm", "tier2_seccomp_notify", "tier3_landlock_path"]
TIER_ABBR = {
    "tier1_bpf_lsm": "T1",
    "tier2_seccomp_notify": "T2",
    "tier3_landlock_path": "T3",
}
ACTIVE_LABEL = {
    "tier1_bpf_lsm": "T1 kernel",
    "tier2_seccomp_notify": "T2 seccomp",
    "tier3_landlock_path": "T3 path",
    "none": "none",
}


def load(dirpath):
    rows = []
    files = sorted(Path(dirpath).glob("*.json"))
    if not files:
        print(f"no .json bundles found in {dirpath}", file=sys.stderr)
    for p in files:
        try:
            b = json.loads(p.read_text())
        except (OSError, ValueError) as e:
            print(f"warn: skipping {p.name}: {e}", file=sys.stderr)
            continue
        d = b.get("doctor", {}) or {}
        walls = d.get("walls", {}) or {}
        tiers = (d.get("exec", {}) or {}).get("tiers", {}) or {}
        rows.append(
            {
                "label": b.get("label", p.stem),
                "substrate": b.get("substrate_hint", "?"),
                "root": bool(b.get("ran_as_root", False)),
                "host": d.get("host", {}) or {},
                "walls": {k: (walls.get(k, {}) or {}).get("status", "unknown") for k in WALLS},
                "tiers": {
                    k: bool((tiers.get(k, {}) or {}).get("available", False)) for k in TIERS
                },
                "active": (d.get("exec", {}) or {}).get("active", "none"),
            }
        )
    return rows


def _grid(headers, data_rows):
    widths = [len(h) for h in headers]
    for r in data_rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep = "  ".join("-" * widths[i] for i in range(len(headers)))
    out = [line, sep]
    for r in data_rows:
        out.append("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)))
    return "\n".join(out)


def render_text(rows):
    headers = ["substrate / label", "arch", "kernel"]
    headers += [WALL_ABBR[w] for w in WALLS]
    headers += ["T1", "T2", "T3", "active"]
    data = []
    for r in rows:
        label = f"{r['substrate']} / {r['label']}" + ("" if r["root"] else " (no-root)")
        line = [label, r["host"].get("arch", "?"), r["host"].get("kernel", "?")]
        line += [SYM.get(r["walls"][w], "?") for w in WALLS]
        line += ["Y" if r["tiers"][t] else "-" for t in TIERS]
        line.append(ACTIVE_LABEL.get(r["active"], r["active"]))
        data.append(line)
    legend = "walls: o=ok  ~=degraded  x=off  ?=unknown   tiers: Y=available -=no"
    return _grid(headers, data) + "\n\n" + legend


def render_md(rows):
    headers = ["substrate / label", "arch", "kernel"]
    headers += [WALL_ABBR[w] for w in WALLS]
    headers += ["T1", "T2", "T3", "active tier"]
    out = ["| " + " | ".join(headers) + " |"]
    out.append("|" + "|".join(["---"] * len(headers)) + "|")
    for r in rows:
        label = f"{r['substrate']} / {r['label']}" + ("" if r["root"] else " (no-root)")
        cells = [label, r["host"].get("arch", "?"), r["host"].get("kernel", "?")]
        cells += [SYM.get(r["walls"][w], "?") for w in WALLS]
        cells += ["Y" if r["tiers"][t] else "—" for t in TIERS]
        cells.append("`" + ACTIVE_LABEL.get(r["active"], r["active"]) + "`")
        out.append("| " + " | ".join(cells) + " |")
    out.append("")
    out.append("_walls: o=ok ~=degraded x=off ?=unknown · tiers: Y=available_")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Tabulate QuantmLayer capability bundles.")
    ap.add_argument("dir", nargs="?", default="ql-matrix", help="bundle directory")
    ap.add_argument("--format", choices=["text", "md"], default="text")
    args = ap.parse_args()

    rows = load(args.dir)
    if not rows:
        sys.exit(1)
    if args.format == "md":
        print(render_md(rows))
    else:
        print(render_text(rows))


if __name__ == "__main__":
    main()
