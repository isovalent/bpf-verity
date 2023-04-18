package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go lsm lsm.c -- -nostdinc -Iinclude

func run(args []string) error {
	fs := flag.NewFlagSet("bpf-verity", flag.ContinueOnError)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if fs.NArg() != 1 {
		return fmt.Errorf("missing path to binary")
	}

	spec, err := loadLsm()
	if err != nil {
		return err
	}

	allowed := spec.Maps["allowed"]
	for _, path := range []string{args[0], fs.Arg(0)} {
		hash, err := measureVerityDigest(path)
		if err != nil {
			return fmt.Errorf("measure verity digest: %w", err)
		}

		fmt.Printf("Allowing verity digest of %q (%x)\n", path, hash.Value[:])
		allowed.Contents = append(allowed.Contents, ebpf.MapKV{Key: hash, Value: uint32(0)})
	}

	// Make sure the hash table isn't too full.
	allowed.MaxEntries = uint32(len(allowed.Contents)) * 2

	var objs lsmPrograms
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return err
	}
	defer objs.Close()

	link, err := link.AttachLSM(link.LSMOptions{Program: objs.Bpf})
	if err != nil {
		return fmt.Errorf("attach lsm: %w", err)
	}
	defer link.Close()

	fmt.Println("Attached program to bpf(), ctrl-c to exit...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	fmt.Println("Shutting down")

	if err := link.Close(); err != nil {
		return fmt.Errorf("failed to detach lsm: %s", err)
	}

	return nil
}

func measureVerityDigest(path string) (*lsmDigest, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buf := make([]byte, 256)
	verity := (*unix.FsverityDigest)(unsafe.Pointer(&buf[0]))
	verity.Size = uint16(len(buf) - int(unsafe.Sizeof(*verity)))

	sc, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}

	var ioctlErr error
	err = sc.Control(func(fd uintptr) {
		ioctlErr = ioctlMeasureVerity(fd, verity)
	})
	if err != nil {
		return nil, err
	}
	if ioctlErr != nil {
		return nil, fmt.Errorf("ioctl: %w", err)
	}

	var digest lsmDigest
	if len(digest.Value) != int(verity.Size) {
		return nil, fmt.Errorf("verity digest is %d bytes, expected %d", verity.Size, len(digest.Value))
	}

	copy(digest.Value[:], buf[unsafe.Sizeof(*verity):])
	return &digest, nil
}

func ioctlMeasureVerity(fd uintptr, arg *unix.FsverityDigest) (err error) {
	_, _, e1 := unix.Syscall(unix.SYS_IOCTL, fd, unix.FS_IOC_MEASURE_VERITY, uintptr(unsafe.Pointer(arg)))
	if e1 != 0 {
		err = e1
	}
	return
}

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
