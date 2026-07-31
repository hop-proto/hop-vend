// hop-vend-client enrolls the local Hop key through a Hop Vend server.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	vendclient "hop.computer/vend/client"
)

func main() {
	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to locate home directory: %v\n", err)
		os.Exit(1)
	}
	userDirectory := filepath.Join(homeDirectory, ".hop")
	cfg := vendclient.Config{}
	flag.StringVar(&cfg.Address, "address", "localhost:7777", "Hop Vend UDP address")
	flag.StringVar(&cfg.KeyPath, "key", filepath.Join(userDirectory, "id_hop.pem"), "Hop private key path")
	flag.StringVar(&cfg.CertificatePath, "certificate", filepath.Join(userDirectory, "id_hop.cert"), "issued certificate path")
	flag.StringVar(&cfg.IntermediatePath, "intermediate", filepath.Join(userDirectory, "intermediate.cert"), "intermediate certificate path")
	flag.StringVar(&cfg.RootCAPath, "ca", filepath.Join(userDirectory, "root.cert"), "trusted Hop root certificate path")
	flag.StringVar(&cfg.ServerName, "server-name", "vend-server", "expected name on the Hop Vend server certificate")
	flag.BoolVar(&cfg.Insecure, "insecure", false, "skip Hop Vend server certificate verification")
	flag.DurationVar(&cfg.Timeout, "timeout", 10*time.Minute, "maximum time to complete GitHub authentication")
	flag.Parse()
	cfg.Output = os.Stdout

	credential, err := vendclient.Enroll(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Enrollment failed: %v\n", err)
		os.Exit(1)
	}
	if err := vendclient.Save(cfg, credential); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to save credential: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(
		"Credential issued for %s and valid until %s.\nSaved certificate to %s.\n",
		credential.Username,
		credential.ExpiresAt.Local().Format(time.RFC3339),
		cfg.CertificatePath,
	)
}
