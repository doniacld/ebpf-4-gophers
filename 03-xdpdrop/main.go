package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Temporary change to fix local issues in Lima VM.
////go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdpdrop xdpdrop.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I/usr/src/linux-headers/usr/include" xdpdrop xdpdrop.c

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// Load the compiled eBPF program
	var objs xdpdropObjects
	if err := loadXdpdropObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load droppacket objects: %v", err)
	}

	// Get the network interface
	ifaceName := "lo" // Replace with your interface name
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", ifaceName, err)
	}

	// Attach the eBPF program to the interface using XDP
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDrop,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer l.Close()

	fmt.Printf("eBPF program attached to interface %s\n", ifaceName)

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-tick.C:
			iter := objs.BlockedIps.Iterate()
			var ipKey uint32
			var dropCount uint64

			fmt.Println("📊 Blocked destination IPs:")
			for iter.Next(&ipKey, &dropCount) {
				fmt.Printf("- %s: %d packets dropped\n", ipFromUint32(ipKey), dropCount)
			}
			if err := iter.Err(); err != nil {
				log.Printf("Map iteration failed: %v", err)
			}

		case <-stop:
			fmt.Println("\nReceived signal, exiting...")
			return
		}
	}
}

func ipFromUint32(ip uint32) string {
	return net.IPv4(
		byte(ip>>24),
		byte(ip>>16),
		byte(ip>>8),
		byte(ip),
	).String()
}
