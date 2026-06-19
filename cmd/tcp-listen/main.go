package main

import (
	"fmt"
	"log"
	"net/netip"

	"github.com/maxcelant/tcp-from-scratch/internal/tcp"
)

func main() {
	ln, err := tcp.Listen(netip.MustParseAddrPort("10.0.0.2:7777"))
	if err != nil {
		log.Fatal(err)
	}
	log.Println("listening on 10.0.0.2:7777")
	for {
		// Accept blocks; it won't return until ESTABLISHED (L08).
		// The read loop inside Listen still emits the SYN/ACK.
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Conn State: %s\n", conn.State())
	}
}
