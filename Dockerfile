# syntax=docker/dockerfile:1
# Multi-stage image for the keycloak-kms-proxy server. pg_query_go links the
# C PostgreSQL parser via cgo, so the binary needs glibc at runtime — we use
# distroless/base-debian12 (minimal, nonroot, ships glibc).
#
# The build stage runs on the build host and cross-compiles with a Debian
# cross gcc: compiling libpg_query under emulation takes far longer, and the
# cross toolchain links against the same bookworm glibc as the runtime base.

FROM --platform=$BUILDPLATFORM golang:1.26.2-bookworm AS build

ARG BUILDARCH
ARG TARGETARCH

RUN set -eu; \
    if [ "$BUILDARCH" != "$TARGETARCH" ]; then \
      case "$TARGETARCH" in \
        amd64) triplet=x86-64-linux-gnu ;; \
        arm64) triplet=aarch64-linux-gnu ;; \
        *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
      esac; \
      apt-get update; \
      apt-get install --yes --no-install-recommends "gcc-$triplet" "libc6-dev-$TARGETARCH-cross"; \
      rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) cross=x86_64-linux-gnu-gcc ;; \
      arm64) cross=aarch64-linux-gnu-gcc ;; \
    esac; \
    if [ "$BUILDARCH" != "$TARGETARCH" ]; then export CC="$cross"; fi; \
    CGO_ENABLED=1 GOOS=linux GOARCH="$TARGETARCH" \
    go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/proxy ./cmd/proxy

FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=build /out/proxy /usr/local/bin/proxy

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/proxy"]
