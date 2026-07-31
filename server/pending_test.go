package server

import (
	"errors"
	"testing"
	"time"

	"hop.computer/hop/keys"
	"hop.computer/vend/protocol"
	"hop.computer/vend/server/config"
)

func TestPendingRequestIsSingleUseAndExpires(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	srv := &Server{
		cfg:     &config.Config{RequestTimeout: time.Minute},
		now:     func() time.Time { return now },
		pending: make(map[string]*pendingRequest),
	}
	id, pending, err := srv.addPending(keys.GenerateNewX25519KeyPair().Public)
	if err != nil {
		t.Fatal(err)
	}
	result := protocol.Credential{Username: "member"}
	if err := srv.completePending(id, result); err != nil {
		t.Fatal(err)
	}
	if got := <-pending.result; got.Username != "member" {
		t.Fatalf("result username = %q", got.Username)
	}
	if err := srv.completePending(id, result); !errors.Is(err, errRequestExpired) {
		t.Fatalf("second completion error = %v, want expired", err)
	}

	id, _, err = srv.addPending(keys.GenerateNewX25519KeyPair().Public)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := srv.getPending(id); !errors.Is(err, errRequestExpired) {
		t.Fatalf("expired lookup error = %v, want expired", err)
	}
}
