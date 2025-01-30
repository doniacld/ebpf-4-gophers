package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go counter counter.c

func main() {
	// remove resource limits for kernels <5.11
	// ? why do we need to remove a limit, what is the limit
	// and what is my kernel version?
	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Fatal("Removing memlock", err)
	}

	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects", err)
	}
	// do not forget the defer, why do we need this?
	defer objs.Close()

	ifname := "eth0"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets, // Not sure to get this?!
		Interface: iface.Index,
		//Flags: nil, // What are these flags?
	})
	if err != nil {
		log.Fatalf("Attaching XDP: %s", err)
	}
	// Again do not forget close but why?
	defer link.Close()

	log.Printf("Counting incoming packets on %s...", ifname)

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}
			log.Printf("Received %d packets", count)
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
