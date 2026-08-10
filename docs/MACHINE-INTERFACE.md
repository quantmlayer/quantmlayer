# The `ql` machine interface

`ql` is scriptable without an SDK: every CI-relevant command has a JSON output
mode and a documented exit-code contract. This page is that contract. Within a
schema version, fields are only ever **added** — never renamed, removed, or
retyped. A consumer should ignore fields it does not recognize.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | Success. For `ql run` (enforce mode): the **contained command** exited 0. |
| `1` | `ql` itself failed at runtime (could not build the cell, trace failed, parse error, I/O error after startup). The requested work did not complete. |
| `2` | Usage or configuration error (unknown option, missing/unreadable input, invalid combination). Nothing was run. |
| `3` | **Policy finding.** The mechanism worked and found what it looks for: `ql run --observe --strict` had ≥1 would-deny finding; `ql audit verify` found a broken chain (tamper). Distinct from `1` so a pipeline can tell "the check failed to run" from "the check failed you". |
| other | `ql run` (enforce mode) passes the contained command's exit code through, clamped to 1–255. A cell that runs your test suite exits with your test suite's code. |

Because `ql run` deliberately exits with the child's code, its own conclusions
travel in the `--result-json` document instead (below) — never scrape stderr.

CI gating patterns:

```sh
ql run --observe --strict --agent claude --result-json obs.json -- claude -p "$TASK"
case $? in
  0) echo "no would-deny findings" ;;
  3) jq -r '.would_deny[] | "\(.kind) \(.target)"' obs.json ;;  # findings
  *) echo "observe run itself failed" >&2; exit 1 ;;
esac

ql audit verify session.jsonl --json > verify.json
# 0 = INTACT, 3 = TAMPERED (see verify.json), 1/2 = check could not run
```

## `ql run ... --result-json <path>` — `ql.run.result/v1`

Written when the run concludes (or fails to start a built cell). If the file
is absent after `ql run` returned, `ql` exited on a configuration error before
any cell existed — treat that as a pipeline error.

Enforce mode:

```json
{
  "schema": "ql.run.result/v1",
  "mode": "enforce",
  "brokered": true,
  "exec_tier": "bpf-lsm",
  "cell_built": true,
  "child": { "ran": true, "exit_code": 0 },
  "error": null
}
```

`child.exit_code` is the contained command's raw exit code (`null` when the
command never executed; `error` then says why). `exec_tier` is the tier that
actually governed the session — the same value recorded to the audit chain.

Observe mode (`--observe [--strict]`):

```json
{
  "schema": "ql.run.result/v1",
  "mode": "observe",
  "profile_origin": "<bundled:claude>",
  "strict": true,
  "strict_failed": true,
  "would_deny_count": 2,
  "would_deny": [
    { "kind": "read", "target": "/home/user/.ssh/id_rsa" },
    { "kind": "exec", "target": "/tmp/payload" }
  ]
}
```

`would_deny` lists every action the profile would have denied, evaluated by
the same evaluator enforce mode uses. Remember observe mode does **not**
contain the agent.

## `ql learn --json` — `ql.learn.result/v1`

On stdout. With `--out` the profile and risk report are still written to disk
and the document reports their paths; without `--out` the profile travels in
`profile_yaml` (stdout is the JSON document instead of raw YAML).

```json
{
  "schema": "ql.learn.result/v1",
  "observation": {
    "processes": 3, "reads": 41, "writes": 7,
    "execs": 4, "connects": 2, "syscalls": 68
  },
  "notes": ["..."],
  "profile_yaml": "schema_version: 1\n...",
  "profile_path": "agent.yaml",
  "risk_report_path": "agent.risk-report.json"
}
```

## `ql validate --json` — `ql.validate.result/v1`

On stdout, only for a **valid** profile — an invalid profile exits `1` with
the reason on stderr before any summary. Counts mirror the human summary.

```json
{
  "schema": "ql.validate.result/v1",
  "profile": "agent.yaml",
  "valid": true,
  "schema_version": 1,
  "agent_type": "CodingAgent",
  "filesystem": { "readwrite": 2, "readonly": 5, "denied": 3 },
  "network": { "default_deny": true, "allow_domains": 4, "block_private_ranges": true },
  "syscalls": { "mode": "allow-by-default", "deny": 12, "notify": 2 },
  "resources": { "pids_max": 256, "memory_max_bytes": 2147483648, "cpu_max_percent": 80 },
  "exec_allow": 6,
  "notes": []
}
```

## `ql compile [<dir>] --json` — `ql.compile.envelope/v1`

On stdout. Derives an egress envelope from the project's dependency lockfiles:
the registry domains that dependency set legitimately needs, bound to each
lockfile's content hash. Exit `0` on success, `2` when no recognized lockfile
is found (nothing was compiled).

```json
{
  "schema": "ql.compile.envelope/v1",
  "envelope_hash": "ac79fd488c56aa2d…",
  "lockfiles": [
    { "path": "package-lock.json", "ecosystem": "npm", "sha256": "ca3d163b…" }
  ],
  "domains": ["github.com", "registry.npmjs.org"]
}
```

- `envelope_hash` covers every contributing lockfile's path, ecosystem, and
  content hash. Two compiles agree iff they saw the same lockfiles with the
  same bytes — an agent that edits a lockfile mid-task changes this hash.
- `ecosystem` is one of `cargo`, `npm`, `pypi`, `go`.
- `domains` is sorted and de-duplicated, and is drawn **only** from a fixed
  per-ecosystem table compiled into `ql-compile`. Lockfile *contents* never
  become domains, so an attacker who controls a lockfile can cause ecosystem
  registries to appear but never an arbitrary host.

Deterministic: the same lockfiles always produce a byte-identical envelope.

Applying an envelope to a profile (`--profile`/`--out`) **merges** into the
existing `allow_domains` by default and records each contributing lockfile in
`approved_for.lockfiles` as a `{path, sha256, vcs}` pin, where `vcs` is
`clean`, `dirty`, or `unknown` — durable provenance for whoever audits the
profile later, since a compile-time warning is gone by then. `ql validate`
prints it. `--replace` narrows to
exactly the compiled domains instead, naming what it dropped.

`ql run` verifies those pins before the cell starts: a pinned lockfile that is
missing or changed fails closed with exit `2`, naming the file. Because
`approved_for` is covered by the profile's signing bytes, a signed profile's
pins cannot be altered without invalidating the signature.

## `ql replay <verdicts.jsonl> --profile <p.yaml> --json` — `ql.replay/v1`

Re-evaluates a recorded verdict stream against a proposed profile, offline.
Exit `0` when no axis regressed, `3` when one did, `2` on usage errors.

```json
{
  "schema": "ql.replay/v1",
  "replayed": 3,
  "skipped_lines": 0,
  "axes": {
    "egress": { "outcome": "pass", "observed": 3, "regressions": 0, "undetermined": 0, "reason": null },
    "exec": { "outcome": "unknown", "observed": 0, "regressions": 0, "undetermined": 0, "reason": "..." }
  },
  "not_observable": ["filesystem", "seccomp"]
}
```

- `outcome` is `pass`, `fail`, or **`unknown`** — never two states. `unknown`
  means the stream lacks the events needed to judge that axis; it is absence
  of evidence, not a pass, and does **not** set exit `3`.
- `regressions` counts only events the recording run **allowed** that the
  proposed profile would **deny**. An event denied before and still denied is
  not a regression; counting it would make every replay of a real stream look
  broken.
- `undetermined` counts events whose outcome cannot be derived — chiefly hosts
  the proposed profile newly admits, since the stream records `host:port` but
  not resolved IPs, so the private-range check cannot be evaluated for them.
- `not_observable` names walls no verdict stream can ever cover: filesystem
  and seccomp deny in-kernel with no userspace event.

`pass` means no *observed* operation would be denied — not that the workload is
compatible. A run under a more permissive policy proceeds further and does
things the stream never captured.

## `ql audit verify <log> --json` — `ql.audit.verify/v1`

On stdout. Exit `0` with `"ok": true`, exit `3` with `"ok": false` and the
first break in `error`.

```json
{ "schema": "ql.audit.verify/v1", "file": "session.jsonl", "ok": true, "records": 120, "error": null }
```

## `ql run ... --verdicts <path.jsonl>` — verdict stream `v1`

A real-time, append-only JSONL stream of containment decisions: one complete
JSON line per decision, flushed per line so `tail -f` never sees a torn
record. Egress decisions stream live from the broker; exec-wall decisions are
appended when the kernel/supervisor event queue is drained at end of run.

This stream is deliberately **not** the hash-chained audit log: it trades
tamper-evidence for real-time availability. Use `--audit` for the
tamper-evident record; the two can be requested together.

```json
{"v":1,"ts_millis":1723118400123,"source":"egress","decision":"deny","target":"pastebin.com:443","rule":"host not in allow-list","hint":"add the domain to network.allow_domains in the profile if this is legitimate"}
{"v":1,"ts_millis":1723118400456,"source":"egress","decision":"allow","target":"pypi.org:443","rule":"allowed","hint":""}
{"v":1,"ts_millis":1723118401000,"source":"exec","decision":"deny","target":"9f2c…","rule":"binary not on the approved digest list","hint":"run `ql learn` on this host to measure the binary and add its digest"}
```

- `source` — `egress` (broker) or `exec` (content-verified exec wall, tier 1
  or tier 2).
- `decision` — `allow` or `deny`.
- `target` — the destination `host:port` or the binary's content digest.
  Recorded verbatim as data.
- `rule` / `hint` — always chosen from a fixed table of compile-time
  constants. Guidance text is never synthesized from agent-controlled input,
  so a consumer may safely surface hints to an agent as observations.
- Filesystem (mount-wall) and seccomp denials do not appear: those walls deny
  in-kernel without a userspace event. Their effects are visible to the agent
  as ENOENT/EPERM, not to this stream.

Within `v:1`, fields are only added, never renamed or removed.

## `ql doctor --json`

Pre-existing: host capability report (walls, exec tiers, kernel). Its layout
predates the `schema` field convention and is kept as-is for compatibility.

## Compatibility promise

- Exit codes `0`/`1`/`2`/`3` keep the meanings above from v0.2.0 onward.
  (Before v0.2.0, `--strict` findings and tamper findings exited `1`.)
- `schema` strings version each document independently; a breaking layout
  change bumps to `/v2` and the old layout remains available for one minor
  release behind the old flag semantics.
