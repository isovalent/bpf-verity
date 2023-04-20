#!/bin/bash
# Install the gatekeeper program. Assumes superuser privileges.
# Does not clean up after itself! You probably want to run this in a VM.

set -euo pipefail

add_ima_rule() {
	local rule="$1"

	if ! grep -q "$rule" /sys/kernel/security/ima/policy; then
		echo "$rule" | tee /sys/kernel/security/ima/policy
	fi
}

# ima_sign signs an fsverity enabled file in a format understood by IMA.
ima_sign() {
	local bin="$1"

	echo "signing $bin"
	sig=$(fsverity measure "$bin" | /usr/local/bin/evmctl sign_hash --veritysig --key key.der | cut -d' ' -f3 2> /dev/null)
	setfattr -n security.ima -v "0x$sig" "$bin"
}

tmp="$(mktemp -d)"
img="$tmp/image"
mnt="$tmp/mnt"
readonly tmp img mnt

cleanup() {
	kill $(jobs -p)
	wait
	test -d "$mnt" && umount "$mnt"
	rm -rf "$tmp"
}
trap cleanup EXIT

# Create a temporary file system so that we can restrict the IMA rule by fsuuid.
# Also allows running the script in virtme which uses 9pfs (which doesn't support
# fs-verity.)
dd if=/dev/zero of="$img" bs=20M count=1 &> /dev/null
mkfs -t ext4 -q "$img" -O verity
mkdir "$mnt" && mount -v -o loop "$img" "$mnt"

# create local _ima keyring and add our public key
# On production systems the kernel uses .ima instead, but this can be locked
# down. Not great for a demo.
keyring="$(keyctl newring _ima @u)"
readonly keyring

keyctl padd asymmetric "bpf-verity" "$keyring" < cert.der
keyctl list "$keyring"

# Tail dmesg so that IMA messages appear in the output
dmesg -C
dmesg --follow &

# Copy binaries to the temporary filesystem and enable fsverity on them
for bin in gatekeeper create-map; do
	cp "$bin" "$mnt/"
	# enable fsverity
	fsverity enable --block-size 1024 "$mnt/$bin"
done

# Measure any file that is being executed and force verity type digests
uuid="$(blkid -s UUID -o value "$img")"
readonly uuid

if ! mount | grep -q /sys/kernel/security; then
	mount -t securityfs securityfs /sys/kernel/security
fi

add_ima_rule "measure func=BPRM_CHECK template=ima-ngv2 digest_type=verity fsuuid=$uuid"

# Get some debug info going
cat /sys/kernel/debug/tracing/trace_pipe &

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
