#!/bin/bash

set -euxo pipefail

# static binaries
export CGO_ENABLED=0

# disable fsverity if necessary
rm -f tcprtt
rm -f bpf-verity

# build binaries and enable fsverity
go build -o . github.com/cilium/ebpf/examples/tcprtt && fsverity enable tcprtt
go generate && go build . && fsverity enable bpf-verity

exec sudo ./bpf-verity ./tcprtt
