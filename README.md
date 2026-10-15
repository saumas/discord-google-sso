# Discord Google SSO

A minimal, self-hosted Go service that restricts a Discord server to members
who can prove they hold an approved Google Workspace identity. Members verify
through a shared URL — Discord OAuth (`identify`) followed by Google OIDC
(`openid email profile`) — and the service enforces a domain allowlist
against the signed `hd` claim, a verified email, and a strict 1:1 link between
one Google identity and one Discord account, then applies the configured role
changes. State is an app-owned Kubernetes Secret; membership is reconciled
via REST every five minutes; revocation is available through an admin-only
`/revoke` slash command and an operator CLI.

## Repository layout

- `cmd/discord-google-sso` — the single binary: server (default), `revoke`
  operator CLI, and the E2E provider simulators
- `internal/` — configuration, state store (gzip JSON, schema version,
  `resourceVersion` CAS), Discord client, Google OIDC client, session
  manager, core service (Verify / Revoke / Reconcile), HTTP server,
  reconciler, provider simulators
- `charts/discord-google-sso` — Helm chart (single replica, `Recreate`
  strategy, namespaced RBAC; never templates the state Secret)
- `e2e/` — the Kind E2E release gate
- `docs/` — [operator guide](docs/operator-guide.md) and
  [real-provider smoke-test runbook](docs/smoke-test.md)

## Development

```sh
make build   # build the binary
make test    # unit tests (no cluster needed)
make lint    # gofmt/vet + helm lint
make e2e     # full release gate: Kind cluster, simulators, real browser,
             # signed interactions, Helm lifecycle, RBAC and log redaction
```

`make e2e` builds the container image, creates a disposable Kind cluster,
installs the chart with Go-simulated Discord/Google providers, and runs the
full scenario matrix — it needs no real Google/Discord accounts or cloud
credentials, only Docker, kind, helm, kubectl, and Google Chrome.

For deploying against real providers, follow the
[operator guide](docs/operator-guide.md).
