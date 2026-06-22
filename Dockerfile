# syntax=docker/dockerfile:1
# Multi-stage image for the keycloak-kms-proxy server. pg_query_go links the
# C PostgreSQL parser via cgo, so the binary needs glibc at runtime — we use
# distroless/base-debian12 (minimal, nonroot, ships glibc).

FROM golang:1.26.2-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/proxy ./cmd/proxy

FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=build /out/proxy /usr/local/bin/proxy

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/proxy"]
