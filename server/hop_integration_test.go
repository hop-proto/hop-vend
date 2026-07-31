package server

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	vendclient "hop.computer/vend/client"
	"hop.computer/vend/protocol"
	"hop.computer/vend/server/config"
)

func TestHopEnrollmentConnectionCarriesLoginAndResult(t *testing.T) {
	srv := New(&config.Config{
		GitHubClientID:      "id",
		GitHubClientSecret:  "secret",
		GitHubOrg:           "testorg",
		IntermediateCAPath:  "../intermediate.pem",
		IntermediateKeyPath: "../intermediate.key.pem",
		CertValidity:        time.Hour,
		RequestTimeout:      time.Minute,
		PublicURL:           "https://vend.example",
		HopAddress:          "127.0.0.1:0",
		HopServerName:       "vend-server",
	})
	hopServer, err := srv.startHop()
	if err != nil {
		t.Fatal(err)
	}
	defer hopServer.Close()

	directory := t.TempDir()
	var output bytes.Buffer
	result := make(chan error, 1)
	go func() {
		_, err := vendclient.Enroll(context.Background(), vendclient.Config{
			Address:  hopServer.Addr().String(),
			KeyPath:  directory + "/id_hop.pem",
			Insecure: true,
			Timeout:  5 * time.Second,
			Output:   &output,
		})
		result <- err
	}()

	var requestID string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		srv.pendingMu.Lock()
		for id := range srv.pending {
			requestID = id
			break
		}
		srv.pendingMu.Unlock()
		if requestID != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if requestID == "" {
		t.Fatal("client did not create a pending enrollment request")
	}
	if err := srv.completePending(requestID, protocol.Credential{Error: "test result"}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil || err.Error() != "test result" {
		t.Fatalf("client error = %v, want test result", err)
	}
	if got := output.String(); !strings.Contains(got, "https://vend.example/login?request=") {
		t.Fatalf("client output did not contain login URL: %q", got)
	}
}
