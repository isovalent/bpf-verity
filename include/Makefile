# SPDX-License-Identifier: BSD-3-Clause

LINUX_INC ?= /usr/include
LIBBPF_INC ?= /usr/local/include

.PHONY: update
update:
	rsync --existing --exclude "types.h" -av "$(LINUX_INC)/linux/" "$(CURDIR)/linux"
	rsync --existing -av "$(LIBBPF_INC)/bpf/" "$(CURDIR)/bpf"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
