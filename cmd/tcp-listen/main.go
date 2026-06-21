package main

import (
	"context"
	"log"
	"log/slog"
	"net/netip"
	"os"

	"github.com/maxcelant/tcp-from-scratch/internal/tcp"
)

func main() {
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ln, err := tcp.Listen(tcp.WithLogger(ctx, logger), netip.MustParseAddrPort("10.0.0.2:7777"))
	if err != nil {
		log.Fatal(err)
	}
	logger.Info("listening", "address", "10.0.0.2", "port", "7777")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		logger.Info("connection made", "conn state", conn.State().String())
	}
}
