#!/bin/bash

set -euo pipefail

# static binaries
export CGO_ENABLED=0

# build binaries
go generate ./...
go build ./cmd/create-map
go build ./cmd/gatekeeper

# generate key
openssl req -batch -nodes -x509 -newkey rsa:1024 -outform DER -keyout key.der -out cert.der -sha256 -days 365
