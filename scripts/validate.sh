#!/bin/sh
set -eu

unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
    echo "gofmt is required" >&2
    echo "$unformatted" >&2
    exit 1
fi

go test -shuffle=on -count=5 ./...
go test -race -count=1 ./...
go vet ./...
go mod verify

mkdir -p bin
go build -trimpath -o bin/network-policy-manager-first ./cmd/network-policy-manager
go build -trimpath -o bin/network-policy-manager-second ./cmd/network-policy-manager
first=$(sha256sum bin/network-policy-manager-first | awk '{print $1}')
second=$(sha256sum bin/network-policy-manager-second | awk '{print $1}')
test "$first" = "$second"
echo "validation passed: $first"
