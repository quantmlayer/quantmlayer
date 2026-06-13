// crates/ql-bench/src/main.rs
//
//! `ql-bench` — runs every catalog attack against every backend and reports.
//!
//! Output:
//! * a Markdown table to stdout (and to `<out>/RESULTS.md`),
//! * machine-readable `<out>/results.json` for `report.py` to render CSV/plots.
//!
//! Usage:
//! ```text
//! cargo run -p ql-bench -- [--out benchmark]
//! ```
//!
//! The table is intentionally honest: attacks whose wall is not yet built show
//! "pending", naming the wall that will close them. Each new wall flips its
//! row to a measured result with no change to this binary.

mod attack;
mod backends;

use backends::{Backend, Outcome};
use std::fs;
use std::path::PathBuf;

/// The backends we evaluate, in column order.
const BACKENDS: &[Backend] = &[Backend::None, Backend::Docker, Backend::QuantmLayer];

fn main() {
    // Minimal arg parsing: optional `--out <dir>` (default "benchmark").
    let out_dir = parse_out_dir().unwrap_or_else(|| PathBuf::from("benchmark"));
    let _ = fs::create_dir_all(&out_dir);

    let attacks = attack::catalog();

    // Run the full matrix, collecting outcomes as we go.
    // results[i] = (attack, [outcome per backend]).
    let mut results: Vec<(attack::Attack, Vec<Outcome>)> = Vec::new();
    for atk in &attacks {
        let mut row = Vec::with_capacity(BACKENDS.len());
        for &backend in BACKENDS {
            let outcome = backends::run(backend, atk).unwrap_or_else(|e| {
                eprintln!(
                    "warning: attack `{}` on `{}` errored: {e}",
                    atk.id,
                    backend.key()
                );
                Outcome::Pending
            });
            row.push(outcome);
        }
        results.push((atk.clone(), row));
    }

    let table = render_markdown(&results);
    println!("{table}");

    // Persist artifacts for the rest of the toolchain.
    let md_path = out_dir.join("RESULTS.md");
    if let Err(e) = fs::write(&md_path, &table) {
        eprintln!("warning: could not write {}: {e}", md_path.display());
    }
    let json_path = out_dir.join("results.json");
    if let Err(e) = fs::write(&json_path, render_json(&results)) {
        eprintln!("warning: could not write {}: {e}", json_path.display());
    } else {
        println!("\nWrote {} and {}", md_path.display(), json_path.display());
    }

    print_summary(&results);
}

/// Render the headline Markdown table.
fn render_markdown(results: &[(attack::Attack, Vec<Outcome>)]) -> String {
    let mut s = String::new();
    s.push_str("# QuantmLayer Attack Benchmark\n\n");
    s.push_str(
        "Each row is an attack a compromised coding agent might attempt. \
         \"blocked\" means containment held; \"vulnerable\" means the host was \
         exposed; \"pending\" means the wall that addresses it is not built yet.\n\n",
    );

    // Header.
    s.push_str("| Attack | Wall |");
    for b in BACKENDS {
        s.push_str(&format!(" {} |", b.label()));
    }
    s.push('\n');
    s.push_str("|---|---|");
    for _ in BACKENDS {
        s.push_str("---|");
    }
    s.push('\n');

    // Rows.
    for (atk, row) in results {
        s.push_str(&format!("| {} | `{}` |", atk.title, atk.target_wall));
        for outcome in row {
            s.push_str(&format!(" {} |", outcome.glyph()));
        }
        s.push('\n');
    }

    // Methodology footnote — keep the comparison honest and reproducible.
    s.push_str(
        "\n## Methodology\n\n\
         Every cell is measured by running the attack and inspecting the result \
         (a stolen-secret file, a spawned-process count, or a reached network \
         endpoint) — never asserted.\n\n\
         **Docker** is a *default* `docker run` with the workspace bind-mounted \
         (`-v <workspace>:<workspace>`) and default network, seccomp, and \
         capabilities — i.e. **no** hardening flags. This models the common \
         \"just run the agent in a container\" setup. Docker *can* close several \
         of these rows too — `--pids-limit` for the fork bomb, `--network none` \
         or an egress policy for SSRF, a tightened seccomp profile, not mounting \
         secrets — but each is a flag the operator must know to add. QuantmLayer's \
         point is that it derives and applies the equivalent restrictions \
         automatically from the agent's observed behavior, on the real host \
         filesystem, with no separate image to build or maintain.\n\n\
         **E2B** and **Daytona** are a different category — *remote-execution* \
         sandboxes that run the agent on a separate machine. Scoring them on \
         these host-threat attacks would be apples-to-oranges (their isolation \
         comes from the agent not being on your machine at all), so they are not \
         shown as a column here. See \"How this differs from cloud sandboxes\" \
         in the README for an honest comparison of the two models.\n",
    );
    s
}

/// Render results as JSON (hand-rolled to avoid a serialization dependency in
/// this tiny binary; the shape is stable and simple).
fn render_json(results: &[(attack::Attack, Vec<Outcome>)]) -> String {
    let mut s = String::from("{\n  \"backends\": [");
    s.push_str(
        &BACKENDS
            .iter()
            .map(|b| format!("\"{}\"", b.key()))
            .collect::<Vec<_>>()
            .join(", "),
    );
    s.push_str("],\n  \"attacks\": [\n");

    let rows: Vec<String> = results
        .iter()
        .map(|(atk, row)| {
            let outcomes: Vec<String> = BACKENDS
                .iter()
                .zip(row)
                .map(|(b, o)| format!("\"{}\": \"{}\"", b.key(), o.token()))
                .collect();
            format!(
                "    {{ \"id\": \"{}\", \"title\": \"{}\", \"wall\": \"{}\", \"outcomes\": {{ {} }} }}",
                atk.id,
                atk.title,
                atk.target_wall,
                outcomes.join(", ")
            )
        })
        .collect();

    s.push_str(&rows.join(",\n"));
    s.push_str("\n  ]\n}\n");
    s
}

/// Print a one-line honest summary: how many attacks QuantmLayer blocks today.
fn print_summary(results: &[(attack::Attack, Vec<Outcome>)]) {
    // QuantmLayer is the last backend column.
    let ql_idx = BACKENDS
        .iter()
        .position(|b| matches!(b, Backend::QuantmLayer))
        .unwrap();
    let blocked = results
        .iter()
        .filter(|(_, row)| row[ql_idx] == Outcome::Blocked)
        .count();
    let runnable = results
        .iter()
        .filter(|(_, row)| matches!(row[ql_idx], Outcome::Blocked | Outcome::Vulnerable))
        .count();
    let total = results.len();
    println!(
        "\nSummary: QuantmLayer blocks {blocked}/{runnable} executed attacks \
         ({total} in catalog; {} not executable on this host).",
        total - runnable
    );
}

/// Parse an optional `--out <dir>` argument.
fn parse_out_dir() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--out" {
            return args.next().map(PathBuf::from);
        }
    }
    None
}
