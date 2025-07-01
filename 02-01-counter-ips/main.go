package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

////go:generate go run github.com/cilium/ebpf/cmd/bpf2go counter counter.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I/usr/src/linux-headers/usr/include" counter counter.c

func main() {
	// Add CLI flag for interface name
	ifname := flag.String("iface", "eth0", "Name of the interface to attach XDP to")
	flag.Parse()

	// Remove memlock rlimit so the BPF program can be loaded (especially on kernels < 5.11)
	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Fatal("Removing memlock", err)
	}

	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", *ifname, err)
	}

	xdp, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPacketsBySrc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Attaching XDP: %s", err)
	}
	defer xdp.Close()

	log.Printf("Counting incoming packets on %s...", *ifname)

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-tick:
			iter := objs.PktCount.Iterate()
			var key uint32
			var value uint64 // src IP and packet count

			log.Println("📥 Packet count by source IP:")
			for iter.Next(&key, &value) {
				ip := net.IPv4(
					byte(key>>24),
					byte(key>>16),
					byte(key>>8),
					byte(key),
				)
				log.Printf("- %s: %d packets", ip.String(), value)
			}
			if err := iter.Err(); err != nil {
				log.Printf("Map iteration error: %s", err)
			}

		case <-stop:
			log.Print("\nReceived signal, exiting..")
			return
		}
	}

}
