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

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs on every pull request and
every push to `discord-google-sso-mvp-go-service`:

- **build** — `make build` and `make test` (the unit suite; no cluster
  needed). Runs on every PR event; superseded runs are cancelled via a
  concurrency group, so a retitle re-runs the build instead of leaving
  the head commit without a fresh build result.
- **check-pr-title** — requires the PR title to follow
  [Conventional Commits](https://www.conventionalcommits.org/):
  `type(scope)!: description` with a lowercase type from feat, fix, docs,
  style, refactor, perf, test, build, ci, chore, revert. The repo uses
  squash merges, so the PR title becomes the permanent commit message.
  Git-generated titles (`Revert "…"`, `Merge …`) are exempt, matching the
  local hook. Pull requests from forks are title-checked like any other:
  the read-only `GITHUB_TOKEN` a fork PR receives is sufficient for this
  read-only validation (the action's README claims forks error under
  `pull_request`, but that passage is outdated — see
  amannn/action-semantic-pull-request#219).

Actions are pinned to release commit SHAs; Dependabot
(`.github/dependabot.yml`) advances the pins weekly.

To get the same commit-message check locally, activate the commit-msg
hook for your checkout:

```sh
make hooks    # worktree-scoped core.hooksPath -> .githooks
```

Activation is per checkout, not per clone: `make hooks` enables git's
per-worktree config layer (`extensions.worktreeConfig`, which itself is
shared across a repository's worktrees) and writes a worktree-scoped
`core.hooksPath`, so sibling worktrees of the same repository are not
affected. It refuses to overwrite an existing `core.hooksPath`. After
activation, `git commit` rejects subjects that don't match, e.g.
`feat: add token refresh loop` or `fix(auth): redirect after login` pass,
while `update` is rejected with the expected format shown. The hook's
behavior and its parity with the CI allowlist are covered by
`make test-hooks` (also run by `make test`).

For deploying against real providers, follow the
[operator guide](docs/operator-guide.md).
