package server

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestSignAndVerifyStateToken(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	state := &State{
		Random:    []byte("some-random-state"),
		PublicKey: "pub",
	}

	// Sign and encode the state to string
	tokenStr, err := SignStateToString(state, privateKey)
	if err != nil {
		t.Fatalf("failed to sign state: %v", err)
	}

	// Decode the string back into a RawStateToken
	rawToken, err := RawStateTokenFromString(tokenStr)
	if err != nil {
		t.Fatalf("failed to decode token string: %v", err)
	}

	// Verify and decode the token
	decodedState, err := rawToken.VerifyAndDecode(publicKey)
	if err != nil {
		t.Fatalf("failed to verify token: %v", err)
	}

	if !bytes.Equal(decodedState.Random, state.Random) || decodedState.PublicKey != state.PublicKey {
		t.Errorf("decoded state does not match original")
	}

	// Double-check signature against manual verification
	signed, err := rawToken.Verify(publicKey)
	if err != nil {
		t.Fatalf("failed to verify token: %v", err)
	}
	if !ed25519.Verify(publicKey, signed.Value, signed.Signature) {
		t.Errorf("manual verification of signature failed")
	}
}
