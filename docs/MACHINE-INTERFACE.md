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

## `ql audit verify <log> --json` — `ql.audit.verify/v1`

On stdout. Exit `0` with `"ok": true`, exit `3` with `"ok": false` and the
first break in `error`.

```json
{ "schema": "ql.audit.verify/v1", "file": "session.jsonl", "ok": true, "records": 120, "error": null }
```

## `ql doctor --json`

Pre-existing: host capability report (walls, exec tiers, kernel). Its layout
predates the `schema` field convention and is kept as-is for compatibility.

## Compatibility promise

- Exit codes `0`/`1`/`2`/`3` keep the meanings above from v0.2.0 onward.
  (Before v0.2.0, `--strict` findings and tamper findings exited `1`.)
- `schema` strings version each document independently; a breaking layout
  change bumps to `/v2` and the old layout remains available for one minor
  release behind the old flag semantics.
