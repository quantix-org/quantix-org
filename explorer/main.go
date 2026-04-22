// MIT License
// Copyright (c) 2024 quantix-org

// Package main implements the Quantix Block Explorer server.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/quantix-org/quantix-org/explorer/server"
)

func main() {
	// Parse flags
	addr := flag.String("addr", ":3000", "HTTP server address")
	rpcURL := flag.String("rpc", "http://localhost:8545", "Quantix node RPC URL")
	network := flag.String("network", "mainnet", "Network name (mainnet, testnet, devnet)")
	logLevel := flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	flag.Parse()

	// Setup logging
	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	// Create server
	cfg := &server.Config{
		Addr:    *addr,
		RPCURL:  *rpcURL,
		Network: *network,
	}
	srv := server.New(cfg, logger)

	// Handle shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		logger.Info("Shutting down...")
		cancel()
	}()

	// Start server
	logger.Info("Starting Quantix Explorer", "addr", *addr, "rpc", *rpcURL, "network", *network)
	if err := srv.Start(ctx); err != nil {
		logger.Error("Server error", "error", err)
		os.Exit(1)
	}
}
