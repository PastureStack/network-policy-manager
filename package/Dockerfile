FROM golang:1.25-bookworm AS build

ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go test -count=1 ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/network-policy-manager \
    ./cmd/network-policy-manager

FROM ubuntu:26.04

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="PastureStack Network Policy Manager" \
      org.opencontainers.image.description="Metadata-driven host network policy enforcement for PastureStack" \
      org.opencontainers.image.source="https://github.com/PastureStack/network-policy-manager" \
      org.opencontainers.image.documentation="https://github.com/PastureStack/network-policy-manager/blob/main/README.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates nftables \
    && rm -f /usr/bin/pebble \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/network-policy-manager /usr/local/bin/network-policy-manager

USER 0:0
ENTRYPOINT ["/usr/local/bin/network-policy-manager"]
CMD ["serve"]
