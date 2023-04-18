bpf-verity
===

A proof-of-concept gatekeeper for `bpf()` syscalls based on [fs-verity] and [BPF LSM][lsm].

`fs-verity` provides file integrity and measurement. A custom LSM hook written
in BPF denies access to any binary that doesn't have an allow listed verity digest.

# Requirements

* A recent kernel, tested on `6.2.10-200.fc37.x86_64`
* `CONFIG_FS_VERITY=y`
* `fsverity` binary
* Go toolchain
* `sudo`

# Running the PoC

The `run.sh` script compiles `bpf-verity` and an example binary, and then sets
things up so that only the example is granted access to `bpf()`.

```
$ ./run.sh
+ export CGO_ENABLED=0
+ CGO_ENABLED=0
+ rm -f tcprtt
+ rm -f bpf-verity
+ go build -o . github.com/cilium/ebpf/examples/tcprtt
+ fsverity enable tcprtt
+ go generate
Compiled /home/lorenz/dev/bpf-verity/lsm_bpfel.o
Stripped /home/lorenz/dev/bpf-verity/lsm_bpfel.o
Wrote /home/lorenz/dev/bpf-verity/lsm_bpfel.go
Compiled /home/lorenz/dev/bpf-verity/lsm_bpfeb.o
Stripped /home/lorenz/dev/bpf-verity/lsm_bpfeb.o
Wrote /home/lorenz/dev/bpf-verity/lsm_bpfeb.go
+ go build .
+ fsverity enable bpf-verity
+ exec sudo ./bpf-verity ./tcprtt
Allowing verity digest of "./bpf-verity" (83524cd005a235183200cecca20210bda9608d0daa37779eda3ce29181d99d5a)
Allowing verity digest of "./tcprtt" (cf3fd9d5b31a30c28e0c0b7c3b190e98e9a25ac8f1ae075e5e08542e09a357b9)
Attached program to bpf(), ctrl-c to exit...
```

In a separate shell, execute some commands to check that things work as expected:

```
$ sudo bpftool prog list
Error: can't get next program: Operation not permitted
$ sudo ./tcprtt
2023/04/18 10:56:14 Src addr        Port   -> Dest addr       Port   RTT
```

The LSM program has some debug logging which you can follow via the trace_pipe:

```sh
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
      bpf-verity-35254   [015] d..21  5792.699707: bpf_trace_printk: granting access
           <...>-35285   [002] d..21  5795.031177: bpf_trace_printk: no verity information
           <...>-35285   [002] d..21  5795.031312: bpf_trace_printk: no verity information
           <...>-35285   [002] d..21  5795.031314: bpf_trace_printk: no verity information
           <...>-35285   [002] d..21  5795.031315: bpf_trace_printk: no verity information
           <...>-35285   [002] d..21  5795.031330: bpf_trace_printk: no verity information
           <...>-35300   [006] d..21  5807.620858: bpf_trace_printk: granting access
           <...>-35300   [006] d..21  5807.620897: bpf_trace_printk: granting access
           <...>-35300   [006] d..21  5807.620906: bpf_trace_printk: granting access
           <...>-35300   [006] d..21  5807.620971: bpf_trace_printk: granting access
           <...>-35306   [002] d..21  5807.621338: bpf_trace_printk: granting access
           <...>-35306   [002] d..21  5807.621349: bpf_trace_printk: granting access
           <...>-35306   [002] d..21  5807.621406: bpf_trace_printk: granting access
           <...>-35306   [002] d..21  5807.624551: bpf_trace_printk: granting access
           <...>-35307   [006] d..21  5807.726222: bpf_trace_printk: granting access
           <...>-35303   [005] d..21  5807.797234: bpf_trace_printk: granting access
           <...>-35303   [005] d..21  5807.797565: bpf_trace_printk: granting access
           <...>-35303   [005] d..21  5807.798990: bpf_trace_printk: granting access
```

[fs-verity]: https://www.kernel.org/doc/html/latest/filesystems/fsverity.html
[lsm]: https://docs.kernel.org/bpf/prog_lsm.html
