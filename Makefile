BINARY  := discord-google-sso
IMAGE   := discord-google-sso/e2e
KIND    ?= kind
CLUSTER ?= discord-google-sso-e2e

.PHONY: build test vet fmt lint clean e2e test-integration

build:
	go build -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	go test ./...

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
