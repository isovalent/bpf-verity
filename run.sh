#!/bin/bash

. ./setup.sh

# Run the gatekeeper
ima_sign "$mnt/gatekeeper"
"$mnt/gatekeeper" &
sleep 1

# Execute without signing. This should fail.
if "$mnt/create-map"; then
	echo "Unexpectedly able to execute bpf() from unsigned binary"
	exit 1
elif ! [ $? -eq 42 ]; then
	echo "bpf() returned an error different than EPERM"
	exit 1
fi

ima_sign "$mnt/create-map"
if ! "$mnt/create-map"; then
	echo "Wasn't able to execute bpf() from signed program"
	exit 1
fi
