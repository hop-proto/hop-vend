package server

import (
	"crypto/ed25519"
	"reflect"
	"testing"
)

func TestSignAndVerifyStateToken(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	state := &State{Random: []byte("some-random-state"), PublicKey: "test"}

	// Sign and encode the state to string
	tokenStr, err := SignStateToString(state, privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

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

	dec, err := verifiedToken.Unmarshal()
	if err != nil {
		t.Fatalf("failed to unmarshal token: %v", err)
	}

	if !reflect.DeepEqual(dec, state) {
		t.Errorf("expected state %#v, got %#v", state, dec)
	}

	// Double-check signature against manual verification
	sig := verifiedToken.Signature
	msg := verifiedToken.Value
	if !ed25519.Verify(publicKey, msg, sig) {
		t.Errorf("manual verification of signature failed")
	}
}
