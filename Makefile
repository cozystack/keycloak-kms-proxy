# keycloak-kms-proxy — developer tasks.
# CI gates on `make lint` + `make test`.

GO        ?= go
GOLANGCI  ?= golangci-lint
PKG       ?= ./...

.PHONY: all
all: lint test

.PHONY: build
build:
	$(GO) build $(PKG)

.PHONY: test
test:
	$(GO) test -race -count=1 $(PKG)

.PHONY: cover
cover:
	$(GO) test -race -count=1 -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: lint
lint:
	$(GOLANGCI) run

.PHONY: fmt
fmt:
	$(GOLANGCI) fmt

.PHONY: tidy
tidy:
	$(GO) mod tidy

# Regenerate the Keycloak conformance corpus from a source checkout, e.g.
# make gen-keycloak-tests SRC=/tmp/keycloak-26.0.0.
SRC ?=
.PHONY: gen-keycloak-tests
gen-keycloak-tests:
	$(GO) run ./cmd/gen-keycloak-tests -src "$(SRC)" -out testdata/keycloak

# Re-derive the runtime SQL conformance golden from a captured proxy log
#. The capture itself happens out of band:
#
#   kubectl -n <namespace> logs deploy/kkp-proxy --since=1m \
#     > /tmp/raw.log
#
# (with KKP_DEBUG_RELAY=true on the proxy), after driving a known client
# scenario against Keycloak. Then:
#
#   make capture-runtime-sql LOG=/tmp/raw.log KC_VERSION=26.0.0
#
# On a Keycloak version bump: regenerate, commit, and review the diff
# against the previous version — that diff IS the runtime contract gate
#.
KC_VERSION ?= 26.0.0
LOG ?=
.PHONY: capture-runtime-sql
capture-runtime-sql:
	@test -n "$(LOG)" || { echo "usage: make capture-runtime-sql LOG=/path/to/proxy.log [KC_VERSION=26.0.0]" >&2; exit 2; }
	$(GO) run ./cmd/capture-keycloak-sql -in "$(LOG)" -out testdata/keycloak/$(KC_VERSION)/runtime-sql.txt

# Ephemeral image build/push to ttl.sh — image lives 24h.
SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
IMAGE ?= ttl.sh/keycloak-kms-proxy-$(SHA):1d
DOCKER ?= docker

.PHONY: image
image:
	$(DOCKER) build --platform=linux/amd64 --build-arg VERSION=$(SHA) -t $(IMAGE) .

.PHONY: image-push
image-push: image
	$(DOCKER) push $(IMAGE)

.PHONY: image-name
image-name:
	@echo $(IMAGE)

.PHONY: clean
clean:
	$(GO) clean
	rm -f coverage.out
