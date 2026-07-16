# Contributing to QuantmLayer

Thanks for your interest. Two things matter most in this repo: containment
claims must be **measured, never asserted**, and the provenance of every line
must be clean.

## Ground rules

1. **`make check` must pass** — fmt + clippy + tests. That is the CI gate.
2. **No asserted security claims.** If your change adds or strengthens a wall,
   it needs a runnable measurement: a test, or an attack in the
   `ql-bench` catalog that flips from `vulnerable`/`Pending` to `blocked`.
   A README row without a benchmark behind it will not be merged.
3. **Fail closed.** If a wall cannot be applied, the agent must not run.
   Changes that silently degrade a wall to "best effort" will not be merged.
4. **Portability discipline.** `ql-profile` stays pure data with no OS
   dependencies; all OS-specific code lives in `ql-enforce` (or `ql-lsm`).
5. **Only contribute code you have the right to contribute.** No code copied
   from other projects unless its license is Apache-2.0-compatible and the
   provenance is stated in the PR description. No code you wrote for an
   employer who owns it. No AI-generated code you have not reviewed and cannot
   vouch for line by line.

## Licensing of contributions

QuantmLayer is Apache-2.0 (with the single documented exception of
`scripts/lsm-enforce/enforce.bpf.c`, which is GPL-2.0-only — see the License
section of the README). By submitting a contribution you agree that it is
provided under the same license as the file(s) you are modifying, per
Apache-2.0 §5 (inbound = outbound).

## Developer Certificate of Origin (required)

Every commit must be signed off:

```sh
git commit -s
```

This adds a `Signed-off-by: Your Name <you@example.com>` trailer, certifying
the [Developer Certificate of Origin v1.1](https://developercertificate.org/):
in short, that you wrote the change or otherwise have the right to submit it
under the project's license. PRs containing commits without a sign-off will
fail review. Use your real name; anonymous or pseudonymous sign-offs cannot be
accepted.

## Pull request checklist

- [ ] `make check` passes locally.
- [ ] New or changed enforcement behavior has a test or benchmark measuring it.
- [ ] Every commit is signed off (`git commit -s`).
- [ ] The PR description states the provenance of any code not written by you.
- [ ] No secrets, tokens, or personal data in code, tests, fixtures, or docs.

## Security issues

Do **not** open a public issue or PR for a vulnerability — see
[SECURITY.md](SECURITY.md) for private reporting.
