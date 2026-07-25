$ErrorActionPreference = 'Stop'

$unformatted = gofmt -l .
if ($unformatted) {
    throw "gofmt is required: $($unformatted -join ', ')"
}

go test -shuffle=on -count=5 ./...
go vet ./...
go mod verify

New-Item -ItemType Directory -Force -Path bin | Out-Null
go build -trimpath -o bin/network-policy-manager-first.exe ./cmd/network-policy-manager
go build -trimpath -o bin/network-policy-manager-second.exe ./cmd/network-policy-manager

$first = (Get-FileHash -Algorithm SHA256 -LiteralPath bin/network-policy-manager-first.exe).Hash
$second = (Get-FileHash -Algorithm SHA256 -LiteralPath bin/network-policy-manager-second.exe).Hash
if ($first -ne $second) {
    throw 'reproducible build check failed'
}

Write-Output "validation passed: $first"
