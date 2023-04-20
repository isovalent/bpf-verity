package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go lsm lsm.c -- -nostdinc -I../../include

func run(args []string) error {
	fs := flag.NewFlagSet("bpf-verity", flag.ContinueOnError)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if fs.NArg() != 0 {
		return fmt.Errorf("extra args")
	}

	spec, err := loadLsm()
	if err != nil {
		return err
	}

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

	return errors.New("clean shutdown")
}

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
