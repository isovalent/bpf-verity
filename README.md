bpf-verity
===

A proof-of-concept gatekeeper for `bpf()` syscalls based on [fs-verity], [IMA] and [BPF LSM][lsm].

* `fs-verity` provides simple and fast file integrity. Only data that is actually
  accesses has to be verified.
* `IMA` has tooling to handle keychains and supports signing `fs-verity` digests.
  There is a way to attach signatures to files via xattr and verification outcomes
  (appraisals) are cached.
* `BPF LSM` is used to write a custom hook which only allows executables with a
  valid IMA signature to access the `bpf()` syscall.

# Requirements

* [`virtme`](https://github.com/arighi/virtme)
* Go toolchain
* `fsverity` binary
* `evmctl` with support for [`--veritysig`](https://sourceforge.net/p/linux-ima/ima-evm-utils/ci/fc46af121ef090241606a97c0e1c96897d723365/) in `/usr/local/bin`
* A custom kernel with `patches/` applied. Use `virtme-configkernel --defconfig --custom /path/to/bpf-verity/kconfig` to configure.

# Running the PoC

`build.sh` compiles the necessary binary. Afterwards invoke `run.sh` using `virtme-run`:

```
$ virtme-run --pwd --kimg /path/to/vmlinux --memory 512M --cpus 2 --script-exec ./run.sh
mount: /dev/loop0 mounted on /tmp/tmp.trT0V4Kola/mnt.
953562878
1 key in keyring:
953562878: --als--v     0     0 asymmetric: bpf-verity
measure func=BPRM_CHECK template=ima-ngv2 digest_type=verity fsuuid=307da5e2-28d6-4cfb-b3da-3ad102df037c
signing /tmp/tmp.trT0V4Kola/mnt/gatekeeper
hash(sha256): eb8cc22dc8e55408291995c79d6bf921910e05ed1712cda92313b53189dbd58d
evm/ima signature: 136 bytes
Attached program to bpf(), ctrl-c to exit...
           <...>-186     [001] ...11     3.072183: bpf_trace_printk: granting access
           <...>-189     [001] ...11     3.886923: bpf_trace_printk: denying access: 4
      create-map-189     [001] ...11     3.887112: bpf_trace_printk: denying access: 4
      create-map-189     [001] ...11     3.887118: bpf_trace_printk: denying access: 4
Error: creating map: map create: operation not permitted (MEMLOCK may be too low, consider rlimit.RemoveMemlock)
signing /tmp/tmp.trT0V4Kola/mnt/create-map
hash(sha256): 06ffcd0bd9a43895ac2b8c689738d992783fe15c8ba78bd6b018f74a769b4a23
evm/ima signature: 136 bytes
      create-map-198     [000] ...11     3.916500: bpf_trace_printk: granting access
      create-map-198     [000] ...11     3.916672: bpf_trace_printk: granting access
      create-map-198     [000] ...11     3.916730: bpf_trace_printk: granting access
      create-map-198     [000] ...11     3.916795: bpf_trace_printk: granting access
      create-map-198     [000] ...11     3.916854: bpf_trace_printk: granting access
created map
```

[fs-verity]: https://www.kernel.org/doc/html/latest/filesystems/fsverity.html
[IMA]: https://sourceforge.net/p/linux-ima/wiki/Home/
[lsm]: https://docs.kernel.org/bpf/prog_lsm.html
