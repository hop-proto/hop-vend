package server

import (
	"crypto/ed25519"
	"testing"
)

func TestSignAndVerifyStateToken(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	state := []byte("some-random-state")

	// Sign and encode the state to string
	tokenStr := SignStateToString(state, privateKey)

	// Decode the string back into a RawStateToken
	rawToken, err := RawStateTokenFromString(tokenStr)
	if err != nil {
		t.Fatalf("failed to decode token string: %v", err)
	}

	// Verify the token
	verifiedToken, err := rawToken.Verify(publicKey)
	if err != nil {
		t.Fatalf("failed to verify token: %v", err)
	}

	if string(verifiedToken.Value) != string(state) {
		t.Errorf("expected state %q, got %q", state, verifiedToken.Value)
	}

	// Double-check signature against manual verification
	sig := verifiedToken.Signature
	msg := verifiedToken.Value
	if !ed25519.Verify(publicKey, msg, sig) {
		t.Errorf("manual verification of signature failed")
	}
}
