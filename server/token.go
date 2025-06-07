package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

var ErrInvalidSignature = errors.New("invalid token signature")

type State struct {
	Random    []byte `cbor:"random"`
	PublicKey string `cbor:"public_key"`
}

type RawStateToken []byte

type SignedStateToken struct {
	Signature []byte
	Value     []byte
}

func RawStateTokenFromString(s string) (RawStateToken, error) {
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return RawStateToken(b), nil
}

func SignState(state *State, signingKey ed25519.PrivateKey) (RawStateToken, error) {
	encodedState, err := cbor.Marshal(state)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(signingKey, encodedState)
	b := make([]byte, len(sig)+len(encodedState))
	copy(b, sig)
	copy(b[len(sig):], encodedState)
	return b, nil
}

func SignStateToString(state *State, signingKey ed25519.PrivateKey) (string, error) {
	raw, err := SignState(state, signingKey)
	if err != nil {
		return "", err
	}
	buf := bytes.Buffer{}
	enc := base64.NewEncoder(base64.URLEncoding, &buf)
	if _, err := enc.Write(raw); err != nil {
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (rst *RawStateToken) Verify(verifyKey ed25519.PublicKey) (*SignedStateToken, error) {
	if len(*rst) < ed25519.SignatureSize {
		return nil, errors.New("invalid signature size")
	}
	sig := (*rst)[0:ed25519.SignatureSize]
	msg := (*rst)[ed25519.SignatureSize:]
	ok := ed25519.Verify(verifyKey, msg, sig)
	if !ok {
		return nil, ErrInvalidSignature
	}
	return &SignedStateToken{
		Signature: sig,
		Value:     msg,
	}, nil
}

func (sst *SignedStateToken) Unmarshal() (*State, error) {
	dec := State{}
	if err := cbor.Unmarshal(sst.Value, &dec); err != nil {
		return nil, err
	}
	return &dec, nil
}

func (rst *RawStateToken) VerifyAndDecode(verifyKey ed25519.PublicKey) (*State, error) {
	sst, err := rst.Verify(verifyKey)
	if err != nil {
		return nil, err
	}
	dec := State{}
	if err := cbor.Unmarshal(sst.Value, &dec); err != nil {
		return nil, err
	}
	return &dec, nil
}
