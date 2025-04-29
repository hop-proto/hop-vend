package main

import (
	"log"

	"hop.computer/vend/pkg/config"
	"hop.computer/vend/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	srv := server.New(cfg)
	if err := srv.Start(); err != nil {
		log.Fatalf("server exited with error: %v", err)
	}
}
