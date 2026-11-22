# Contributing to Gjallar

Thank you. Gjallar is built for the commons; small fixes are as welcome as features.

## Before you start

- Read [the Gjallar Philosophy](https://github.com/heimdallr-dev/gjallar-docs/blob/main/docs/philosophy.md). Changes that add lock-in, a
  score without a reason, or a hidden network call will not be merged.
- For larger changes, open an issue first so we can agree on the shape.
- Security issues: see [SECURITY.md](SECURITY.md), never a public issue.

## Development

```bash
make vet test            # unit and adapter tests
make e2e                 # real binaries + NATS + Postgres + DuckDB (Docker or BUILDER=nerdctl)
helm lint ../gjallar-helm/charts/gjallar   # chart lives in gjallar-helm
```

Rules of the codebase (see [docs/development.md](https://github.com/heimdallr-dev/gjallar-docs/blob/main/docs/development.md)):
- `internal/domain` imports nothing from Gjallar; `internal/app` imports only
  the domain; adapters implement ports; `cmd/*` wires.
- Engines run as subprocesses; new engines are new adapters, not new cores.
- Every new behaviour comes with a test. Pin and checksum every download.
- Dependencies are vendored; add one only when the standard library or an
  existing dependency can't do the job.

## Sign your commits (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/).
Add a sign-off to every commit: `git commit -s`. By signing off you state you
have the right to submit the work under the Apache-2.0 license.

## Pull requests

- One topic per PR, with a description of *why*.
- CI must be green (tests, e2e, govulncheck, helm lint).
- A maintainer reviews every PR; security-relevant changes need two approvals.
