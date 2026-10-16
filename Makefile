BINARY  := discord-google-sso
IMAGE   := discord-google-sso/e2e
KIND    ?= kind
CLUSTER ?= discord-google-sso-e2e

.PHONY: build test test-hooks vet fmt lint clean e2e test-integration hooks

build:
	go build -o bin/$(BINARY) ./cmd/$(BINARY)

test: test-hooks
	go test ./...

# Behavioral tests for .githooks/commit-msg, including allowlist parity
# with the CI PR-title check (.github/workflows/ci.yml).
test-hooks:
	scripts/test-hooks.sh

vet:
	go vet ./...

fmt:
	gofmt -l -w ./cmd ./internal

lint: fmt vet
	helm lint charts/discord-google-sso

# Integration tests against the current kubeconfig cluster (skipped without
# one); the full Kind E2E suite is `make e2e`.
test-integration:
	go test -tags integration ./internal/state/...

# One documented command: build the image, create a disposable Kind cluster,
# install the chart with the provider simulators, run the full scenario
# matrix, and tear the cluster down. Requires no real Google/Discord
# accounts or cloud credentials.
e2e:
	go run ./e2e

clean:
	rm -rf bin

# Activate the version-controlled git hooks (commit-msg Conventional
# Commits check) for this checkout via a worktree-scoped core.hooksPath
# (plain `git config` in a linked worktree would write the shared config
# and silently activate the hook in every sibling worktree). Refuses to
# clobber an existing core.hooksPath.
hooks:
	@current="$$(git config --get core.hooksPath 2>/dev/null || true)"; \
	if [ -n "$$current" ] && [ "$$current" != ".githooks" ]; then \
		echo "error: core.hooksPath is already set to '$$current'; refusing to overwrite it." >&2; \
		echo "Unset it first (git config --unset core.hooksPath) or point it at .githooks manually." >&2; \
		exit 1; \
	fi; \
	git config extensions.worktreeConfig true; \
	git config --worktree core.hooksPath .githooks; \
	echo "commit-msg hook activated for this checkout (worktree-scoped core.hooksPath=.githooks)."
