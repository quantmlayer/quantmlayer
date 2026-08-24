// crates/ql-cli/src/htmltree.rs
//
//! Render the process tree as a self-contained HTML document.
//!
//! The same structure `process-tree.md` renders, in a form someone can open
//! and hand to a colleague. Both come from [`crate::proctree::Tree`], so the
//! artifact a person reads and the one they verify cannot drift apart.
//!
//! ## A view, never evidence
//!
//! This file carries no hash of its own and is not covered by the audit chain,
//! deliberately. The bundle's evidence is `records.jsonl`, which `verify.py`
//! checks; an HTML document that looked authoritative would invite someone to
//! treat a rendering as proof. The page says so at the top rather than leaving
//! it to be assumed.
//!
//! ## Everything an agent chose is escaped
//!
//! Hostnames, paths, and comms are strings a contained agent controls, and
//! they end up inside HTML. [`esc`] escapes the five characters that can leave
//! text context. Without it a process named `<script>` would execute in the
//! reader's browser — the same class as the workflow-command injection defence
//! in `--ci`, with a worse blast radius.
//!
//! ## Offline and self-contained
//!
//! No CDN, no external fonts, no analytics. An evidence artifact that phones
//! home when opened is a contradiction, and one that renders differently
//! depending on network conditions is not reproducible.

use crate::proctree::{Endpoint, Tree, TreeNode};

/// Escape text for embedding in HTML.
///
/// Ampersand first, or the escapes would themselves be re-escaped.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// CSS class for a verdict, so the stylesheet can colour it without parsing
/// the label back out.
fn verdict_class(verdict: &str) -> &'static str {
    match verdict.trim() {
        "allow" => "v-allow",
        "DENY" => "v-deny",
        "would-allow" => "v-wallow",
        "WOULD-DENY" => "v-wdeny",
        "PATH miss" => "v-miss",
        _ => "v-other",
    }
}

/// Hover text for a verdict. The distinctions this tool cares about are
/// exactly the ones a reader will not infer from the word alone.
fn verdict_title(verdict: &str) -> &'static str {
    match verdict.trim() {
        "allow" => "Ran, and the exec wall approved it",
        "DENY" => "Refused by the exec wall; this program did not run",
        "would-allow" => "Observe mode: enforce would have approved this",
        "WOULD-DENY" => "Observe mode: enforce would have refused this. Nothing was blocked",
        "PATH miss" => "execve returned an error; this program was never there",
        _ => "",
    }
}

fn render_endpoint(e: &Endpoint, out: &mut String) {
    let times = if e.count > 1 {
        format!(" <span class=\"count\">x{}</span>", e.count)
    } else {
        String::new()
    };
    let err = match e.errno {
        Some(_) => " <span class=\"err\">failed</span>".to_string(),
        None => String::new(),
    };
    // A broker refusal is what a reader came to find, so it leads and is the
    // one thing on the line with colour of its own.
    let denied = if e.denied {
        "<span class=\"denied\">DENIED</span> "
    } else {
        ""
    };
    out.push_str(&format!(
        "<li class=\"ep\"><span class=\"arrow\">-&gt;</span> {denied}<code>{}</code>{times}{err}</li>",
        esc(&e.endpoint)
    ));
}

fn render_node(n: &TreeNode, out: &mut String) {
    let has_children = !n.children.is_empty() || !n.endpoints.is_empty();
    // `open` by default: a tree that hides its contents until clicked makes a
    // reader hunt for the denial they were sent here to look at.
    out.push_str(if has_children {
        "<li><details open><summary>"
    } else {
        "<li><div class=\"leaf\">"
    });

    out.push_str(&format!(
        "<span class=\"v {}\" title=\"{}\">{}</span> \
         <span class=\"pid\">pid {}</span> \
         <span class=\"comm\">{}</span> \
         <code class=\"target\">{}</code>",
        verdict_class(n.verdict),
        esc(verdict_title(n.verdict)),
        esc(n.verdict.trim()),
        n.pid,
        esc(&n.comm),
        esc(&n.target)
    ));

    out.push_str(if has_children {
        "</summary><ul>"
    } else {
        "</div>"
    });

    if has_children {
        for e in &n.endpoints {
            render_endpoint(e, out);
        }
        for k in &n.children {
            render_node(k, out);
        }
        out.push_str("</ul></details>");
    }
    out.push_str("</li>");
}

/// Render `tree` as a complete HTML document.
///
/// `source` names the log this came from and `head` is the chain head, so a
/// reader can tie the page back to a specific verified record set.
pub fn render(tree: &Tree, source: &str, head: &str, records: usize) -> String {
    let mut body = String::new();

    if tree.roots.is_empty() {
        body.push_str("<p class=\"empty\">No exec records in this window.</p>");
    } else {
        body.push_str("<ul class=\"tree\">");
        for r in &tree.roots {
            render_node(r, &mut body);
        }
        body.push_str("</ul>");
    }

    if !tree.any_parent_data && !tree.roots.is_empty() {
        body.push_str(
            "<p class=\"note\"><strong>No parent data in this log.</strong> The recording run \
             used the Tier-2 exec wall, which reports the execing pid but not its parent, so \
             these are listed flat rather than nested.</p>",
        );
    }
    if !tree.unattributed.is_empty() {
        body.push_str(&format!(
            "<p class=\"note\"><strong>{} connection(s) could not be attributed</strong> to a \
             process in this window. They are listed here rather than attached to a \
             neighbouring process, which would invent a link the data does not \
             support.</p><ul class=\"unattr\">",
            tree.unattributed.len()
        ));
        for u in tree.unattributed.iter().take(50) {
            body.push_str(&format!("<li><code>{}</code></li>", esc(u)));
        }
        if tree.unattributed.len() > 50 {
            body.push_str(&format!(
                "<li>and {} more</li>",
                tree.unattributed.len() - 50
            ));
        }
        body.push_str("</ul>");
    }
    if tree.unparsed > 0 {
        body.push_str(&format!(
            "<p class=\"note\">{} exec record(s) could not be placed: their detail did not \
             match the expected form, so the process is unknown.</p>",
            tree.unparsed
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QuantmLayer process tree - {src}</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
        margin: 2rem auto; max-width: 62rem; padding: 0 1rem; }}
h1 {{ font-size: 1.2rem; margin-bottom: .2rem; }}
.sub {{ opacity: .75; margin-top: 0; font-size: .85rem; }}
.banner {{ border-left: 3px solid #888; padding: .6rem .9rem; margin: 1.2rem 0;
           background: rgba(128,128,128,.08); font-size: .85rem; }}
ul.tree, ul.tree ul {{ list-style: none; padding-left: 1.1rem; }}
ul.tree {{ padding-left: 0; }}
li {{ margin: .1rem 0; }}
summary {{ cursor: pointer; }}
.leaf {{ padding-left: 1.1rem; }}
.v {{ display: inline-block; min-width: 6.5rem; font-weight: 600; }}
.v-allow  {{ color: #1a7f37; }}
.v-wallow {{ color: #57606a; }}
.v-deny   {{ color: #cf222e; }}
.v-wdeny  {{ color: #bc4c00; }}
.v-miss   {{ color: #8250df; }}
.pid {{ opacity: .6; min-width: 6rem; display: inline-block; }}
.comm {{ font-weight: 600; min-width: 9rem; display: inline-block; }}
.target {{ opacity: .8; }}
.ep {{ opacity: .9; }}
.arrow {{ opacity: .5; }}
.count {{ opacity: .6; }}
.err {{ color: #cf222e; }}
.denied {{ color: #cf222e; font-weight: 700; }}
.note {{ border-left: 3px solid #bc4c00; padding: .5rem .9rem; margin: 1rem 0;
         background: rgba(188,76,0,.07); font-size: .85rem; }}
.empty {{ opacity: .7; }}
footer {{ margin-top: 2rem; font-size: .8rem; opacity: .75; }}
code {{ font-family: inherit; }}
</style></head><body>
<h1>Process tree</h1>
<p class="sub">{recs} record(s) from <code>{src}</code> - chain head <code>{head}</code></p>

<div class="banner">
<strong>This page is a view, not evidence.</strong> It carries no hash and is not part of the
audit chain. The evidence is <code>records.jsonl</code> in this bundle, which
<code>verify.py</code> checks independently. Every line below corresponds to a record there.
<br><br>
Grouping shows <em>what ran under what</em> - parentage the kernel reported at exec time. It does
not claim causality: "this exec caused that connection" would have to be inferred, and nothing
here is inferred.
</div>

{body}

<footer>
Endpoints show the socket protocol where the <code>socket()</code> call was observed:
<code>udp ...:0</code> is a source-address lookup that sends nothing, <code>tcp ...:443</code> is a
session. Most connections carry no outcome - a non-blocking <code>connect</code> returns
<code>EINPROGRESS</code> and its result arrives later through <code>SO_ERROR</code>, which a
syscall tracer never sees. Generated by QuantmLayer; opens offline, loads nothing.
</footer>
</body></html>
"#,
        src = esc(source),
        head = esc(head),
        recs = records,
        body = body
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proctree::{build_with_connects, ConnectNode, ExecNode};

    fn node(pid: u32, comm: &str, target: &str) -> ExecNode {
        ExecNode {
            pid,
            ppid: None,
            comm: comm.into(),
            target: target.into(),
            allowed: true,
            enforced: false,
            failed: false,
            ts_millis: pid as u64,
            order: pid as u64,
        }
    }

    fn conn(pid: u32, endpoint: &str, order: u64) -> ConnectNode {
        ConnectNode {
            pid,
            ppid: None,
            endpoint: endpoint.into(),
            ts_millis: order,
            order,
            failed_errno: None,
            restarted: false,
            comm: None,
            denied: false,
        }
    }

    /// **The security property.** A contained agent chooses process names and
    /// hostnames, and they end up inside HTML — so a process named `<script>`
    /// must not execute in the reader's browser.
    #[test]
    fn agent_chosen_strings_cannot_execute_in_the_page() {
        let hostile = "<script>alert('x')</script>";
        let n = node(1, hostile, hostile);
        let c = conn(1, hostile, 2);

        let tree = build_with_connects(&[n], &[c], 0);
        let html = render(&tree, hostile, hostile, 1);

        assert!(!html.contains("<script>"), "unescaped script tag");
        assert!(html.contains("&lt;script&gt;"), "not escaped at all");
        // The ampersand must be escaped first, or escapes get double-encoded.
        assert!(!html.contains("&amp;lt;"), "double-encoded");
    }

    /// The page states its own status: a rendering, not the record.
    #[test]
    fn the_page_says_it_is_not_evidence() {
        let tree = build_with_connects(&[node(1, "sh", "/bin/sh")], &[], 0);
        let html = render(&tree, "run.jsonl", "abc123", 1);
        assert!(html.contains("view, not evidence"));
        assert!(html.contains("verify.py"));
        assert!(html.contains("not claim causality"));
    }

    /// It loads nothing: an evidence artifact that phones home when opened is
    /// a contradiction, and one that needs the network is not reproducible.
    #[test]
    fn the_page_is_self_contained() {
        let tree = build_with_connects(&[node(1, "sh", "/bin/sh")], &[], 0);
        let html = render(&tree, "run.jsonl", "abc", 1);
        for external in ["http://", "https://", "//cdn", "<script"] {
            assert!(!html.contains(external), "external reference: {external}");
        }
    }

    /// Unattributed connections are surfaced on the page, not quietly dropped.
    #[test]
    fn unattributed_connections_are_shown() {
        let tree = build_with_connects(
            &[node(1, "sh", "/bin/sh")],
            &[conn(999, "udp 9.9.9.9:53", 5)],
            0,
        );
        let html = render(&tree, "run.jsonl", "abc", 1);
        assert!(html.contains("could not be attributed"));
        assert!(html.contains("9.9.9.9:53"));
    }

    /// The page renders the same nodes the text tree does — they share one
    /// structure, so a node present in one must be present in the other.
    #[test]
    fn html_and_text_render_the_same_nodes() {
        let parent = node(10, "sh", "/bin/sh");
        let mut child = node(11, "curl", "/usr/bin/curl");
        child.ppid = Some(10);
        let tree = build_with_connects(&[parent, child], &[conn(11, "tcp 1.2.3.4:443", 12)], 0);
        let html = render(&tree, "run.jsonl", "abc", 2);

        for line in &tree.lines {
            // Each text line names a pid or an endpoint; both must appear.
            if let Some(rest) = line.trim().strip_prefix("-> ") {
                assert!(html.contains(&esc(rest.trim())), "missing endpoint {rest}");
            }
        }
        assert!(html.contains("pid 10"));
        assert!(html.contains("pid 11"));
    }
}
