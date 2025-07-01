package main

import (
	"bufio"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go openfile openfile.c

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock: %v", err)
	}

	var objs openfileObjects
	if err := loadOpenfileObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load objects: %v", err)
	}

	// Attach the eBPF program to the tracepoint.
	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		log.Fatalf("failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	log.Println("eBPF program attached. Waiting for events...")

	// Print logs from the trace pipe to see files opening traces
	go func() {
		cmd := exec.Command("cat", "/sys/kernel/debug/tracing/trace_pipe")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("failed to get stdout pipe: %v", err)
			return
		}

		if err := cmd.Start(); err != nil {
			log.Printf("failed to start trace_pipe reader: %v", err)
			return
		}

		log.Println("Reading trace_pipe output...")

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			log.Println(scanner.Text())
			time.Sleep(1 * time.Second)
		}

		if err := scanner.Err(); err != nil {
			log.Printf("scanner error reading trace_pipe: %v", err)
		}

		if err := cmd.Wait(); err != nil {
			log.Printf("trace_pipe command exited: %v", err)
		}
	}()

	// Set up signal handling to gracefully exit.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Print("\nReceived signal, exiting..")
}
