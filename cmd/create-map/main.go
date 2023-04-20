package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
)

func run() error {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		return err
	}
	fmt.Println("created map")
	return m.Close()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		if errors.Is(err, syscall.EPERM) {
			os.Exit(42)
		}
		os.Exit(1)
	}
}
