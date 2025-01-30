package main

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdp_drop xdp_drop.c

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// Load the compiled eBPF program
	var objs xdp_dropObjects
	if err := loadXdp_dropObjects(&objs, nil); err != nil {
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

	// Keep the program running
	fmt.Println("Press Ctrl+C to exit...")
	select {}
}
