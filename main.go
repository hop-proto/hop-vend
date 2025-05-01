package main

import (
	"log"
	"log/slog"

	"hop.computer/vend/pkg/config"
	"hop.computer/vend/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		log.Fatalf("failed to load config: %v", err)
	}

	srv := server.New(cfg)
	if err := srv.Start(); err != nil {
		slog.Error("failed to load config", "error", err)
		log.Fatalf("server exited with error: %v", err)
	}
}
