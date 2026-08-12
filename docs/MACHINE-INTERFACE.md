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

## `ql audit export --format otlp` — OTLP logs

Emits the audit window as an OTLP/HTTP logs document for an existing
observability stack. `--out` names the file (not a directory, as it does for
the evidence bundle), and `--host` sets `host.name`.

```
ql audit export run.jsonl --format otlp --out otlp.json --host $(hostname)
curl -X POST -H 'Content-Type: application/json' \
     --data-binary @otlp.json http://localhost:4318/v1/logs
```

- **Exporter, not a backend.** No dashboard, storage, or query layer — those
  would mean competing with Datadog and Grafana rather than feeding them.
- **No new dependencies.** The document is written directly rather than via the
  OpenTelemetry SDK: the audit log is a finished file on disk, not live
  telemetry, so there is nothing to batch, retry, or flush — and `ql` stays a
  single static binary, which is what makes the install path work.
- **A denial is `WARN`, not `ERROR`.** Denials are the system working as
  configured; a stream of ERRORs for correct behaviour gets muted, and then the
  one that mattered is muted too.
- **An exported copy is not tamper-evident.** Chain integrity lives in
  `prev_hash`/`hash` across the whole sequence, and a system that reorders,
  samples, or drops records breaks it. Every record therefore carries
  `quantmlayer.seq` and `quantmlayer.record_hash` so an investigator can return
  to the source log and verify there — the export is a lead, the chain is the
  evidence.
- Attributes are namespaced `quantmlayer.*`; agent-chosen strings (targets,
  details) are JSON-escaped so a contained agent cannot forge records in
  whatever ingests this.

## `ql token delegate` — cascading attenuation

Hands a sub-agent a strictly narrower slice of an existing credential:

```
ql token delegate --from parent.json --out child.json --only-domains crates.io
ql run --profile p.yaml --token-chain child.json --trust-root <hex> -- <cmd>
```

Each link can only narrow, checked cryptographically at every step and again
by the verifier at point of use — so an orchestrating agent can spawn helpers
whose blast radius is smaller than its own, rather than equal to it.

- **Narrowing intersects.** Naming a domain the parent never held yields
  nothing rather than an error, so a compromised agent asking for more simply
  gets less. Observed live: a 4-link chain requesting `evil.example` ends with
  zero domains.
- **A child cannot outlive its parent** — an over-long expiry is clamped when
  issued, not left to fail later at use.
- **Delegating needs the parent's signing key.** A stolen chain without its
  seed is inert.
- **An unverifiable parent chain is refused up front**, rather than minting a
  credential that could never be used.
- `--token-chain` accepts a bundle (`{"chain": [...]}` or `{"token": {...}}`)
  or a bare token array.

**A token is not containment.** It governs what the broker admits from a
client presenting it; the cell's walls are what stop a process from acting. A
sub-agent with a narrow token in a wide cell is as dangerous as its cell —
narrow the cell too (`--phase`, `ql compile`).

## `ql audit export` — `process-tree.md`

Export bundles now include `process-tree.md`: the same exec records as
`records.jsonl`, grouped by the parent the kernel recorded at exec time.

```
  allow pid 34348   sh               aaaaaaaaaaaaaaaa
    allow pid 34349   dash             bbbbbbbbbbbbbbbb
      DENY  pid 34350   curl             cccccccccccccccc
```

It is a **view**, never evidence: the bundle's evidence is the hash-chained log
that `verify.py` checks, and this file carries no hash of its own.

- Grouping shows what ran under what. It does not claim causality — parentage
  and ordering are facts the kernel supplies; "this exec caused that
  connection" would have to be inferred.
- A record whose parent is absent appears at top level (the cell's first exec
  is parented to `ql`, outside the cell; `--since`/`--until` can cut a chain).
- Denials are leaves: a refused exec never became anyone's parent.
- **Observe-mode runs carry egress lineage.** Each connect hangs off the
  process that opened it, rendered as `-> ip:port` beneath its process, with
  repeats collapsed (`x3`). This is exact rather than correlated: the ptrace
  tracer has the pid at the `connect` syscall stop itself, so no join is
  involved. Endpoints are `ip:port`, not domains — the name is already
  resolved and gone by the time `connect` is called. A connect whose pid
  matches no exec record is listed as **unattributed** rather than attached to
  a neighbouring process.

  Attribution picks the image that was **running when the connect happened**,
  not merely the pid: one pid holds several exec records (a PATH search emits
  one `execve` per directory tried, and shell `exec` replaces the image in
  place), and ordering is by observation sequence rather than timestamp
  because those records share a millisecond. A process that forked and never
  exec'd is running its parent's image, so its connects attribute to the
  nearest ancestor that has one.

  Endpoints carry the socket protocol when the `socket()` call was observed
  (`-> udp 1.2.3.4:53`, `-> tcp 1.2.3.4:443`), because a destination alone can
  mislead. `curl` reuses one UDP socket to probe several addresses before
  opening its real TCP session, so without the protocol those probes render as
  sessions that never happened; a UDP connect to port 0 is how `getaddrinfo`
  asks which source address a destination would use, and sends nothing. The
  tree states the protocol and stops — calling something a "resolver probe"
  would be an inference, and this view does not render inferences. A socket
  created before tracing began has no observed type and is shown without a
  label rather than guessed.

  Threads are attributed to their process: ptrace stops report threads, and
  only a thread-group leader execs, so a resolver thread's connect is recorded
  under its tgid rather than left to the ancestor fallback — which would have
  credited it to whatever spawned the process, one image too high.

  A PATH search calls `execve` once per directory and most of those fail with
  `ENOENT`. Those render as `PATH miss` with no verdict — a program that was
  never there did not run, so predicting whether it would have been allowed
  says nothing. The distinction comes from the syscall exit stop: a successful
  `execve` never returns, so any exec reaching that stop failed.

  A connect that returned a definite error is annotated with it
  (`-> tcp 1.2.3.4:443 (ECONNREFUSED)`) and kept distinct from a success to the
  same endpoint. Failures are shown rather than dropped: unlike a PATH miss,
  where nothing ran, a refused connection is egress the process intended.
  Most connects annotate nothing, and that is correct — a non-blocking
  `connect` returns `EINPROGRESS` and its real outcome arrives later via
  `SO_ERROR`, which a syscall tracer never sees, so the honest state is
  undetermined. Calls the kernel restarted after a signal are collapsed, so a
  count is distinct calls rather than attempts.

  Caveats worth knowing: observe records
  the parent is read from `/proc` at
  the syscall stop, so a process re-parented after its parent exited reports
  its new parent.

  Enforce mode has no equivalent yet: the broker sits across a veth in another
  network namespace and sees a TCP connection, not a process (see B9).
- **Observe-mode runs are included, and labelled as predictions.** An observe
  would-deny is a forecast, not a denial that happened — nothing was stopped.
  Those rows read `would-allow` / `WOULD-DENY` rather than `allow` / `DENY`,
  so a reader cannot mistake a report-only run for an enforced one.
- **Tier-2 logs group nothing** and say so. seccomp user-notification delivers
  the execing pid but not its parent, so those records list flat rather than
  rendering a depth-one tree that would imply parentage was observed.
- Records whose `detail` does not match `pid N ppid N (comm)` are counted as
  unplaced rather than attached to a guessed parent.

## `ql run --phase <name>` and `requirements`

Two additive profile fields, both absent by default — a profile without them
behaves exactly as before.

**`phases`** gives one step of a task its own narrower authority. The same
agent needs different authority at different moments: dependency install needs
the registries but not the model endpoint; build and test need the workspace
but usually no egress at all, and that is where freshly-downloaded code first
executes. Without phases a profile must cover the session at its widest point.

```yaml
phases:
  install:
    only_domains: ["crates.io", "static.crates.io"]
  build:
    no_egress: true
    output_path: "/work/target"
```

`ql run --phase build ...` applies it. **A phase can only narrow**: every list
is intersected with the base profile's, never unioned, so naming a domain the
base does not grant grants nothing. That keeps the base profile an upper bound
on the whole session, which is what makes a signature over it meaningful. A
narrowed profile drops the base's signature, since it is a different document.
An unknown phase name exits `2` and lists the phases the profile defines.

**`requirements`** lets a policy state the guarantee it needs rather than the
platform it runs on, so a substrate that cannot deliver is disqualified instead
of silently providing something weaker:

```yaml
requirements:
  exec_identity: content_hash      # or path_or_signer
  secret_visibility: absent        # or access_denied
  degradation: refuse              # or allow
```

An unmet requirement is named (`exec_identity requires 'content_hash' but this
host provides 'path_or_signer'`) and exits `1` under the default
`degradation: refuse`. `allow` proceeds with the strongest available substitute
and says so.

## `ql run --ci`

An alias, not a mode: it fills in machine-readable artifact paths the caller
did not give (`ql-verdicts.jsonl`, `ql-result.json` — explicit flags win),
emits denials as GitHub `::notice` annotations, and appends a table to
`$GITHUB_STEP_SUMMARY` when the runner provides one. It adds no enforcement
and changes no policy.

**`--ci` does not fail a build on denials.** A denial is what the agent
attempted, not a failure — a real run can be denied several destinations,
route around them, and pass its tests. Exit semantics are unchanged: `ql run`
still returns the contained command's code, containment failures still exit
1/2, and gating on a policy change is `ql replay`'s job (exit 3 on a
regression) in its own step.

Denied targets are agent-chosen strings, so they are scrubbed before being
written into an annotation: control characters are removed by the run summary
on the way in, and `::` runs are collapsed on the way out, so a contained
agent cannot forge or terminate a workflow command.

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

The first line is a **header** declaring which walls were live for the run;
each following line is one decision. Both carry `type`.

```json
{"v":1,"type":"header","live_axes":["egress"]}
{"v":1,"type":"decision","ts_millis":1723118400123,"source":"egress","decision":"deny","target":"pastebin.com:443","rule":"host not in allow-list","hint":"add the domain to network.allow_domains in the profile if this is legitimate"}
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
- `live_axes` names the walls that were in the request path at all, whether or
  not they made a decision. Without it, an axis with no events is ambiguous: a
  brokered run whose workload made no network calls produces exactly the same
  zero egress events as a run with no broker. Those imply opposite conclusions
  — "covered, nothing happened" versus "no coverage" — so consumers must read
  the header rather than infer from emptiness. Streams written before headers
  existed have none; treat its absence as unknown coverage, never as either
  answer.
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
