package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

var ErrInvalidSignature = errors.New("invalid token signature")

type RawStateToken []byte

type StateToken struct {
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

func SignState(state []byte, signingKey ed25519.PrivateKey) RawStateToken {
	sig := ed25519.Sign(signingKey, state)
	b := make([]byte, len(sig)+len(state))
	copy(b, sig)
	copy(b[len(sig):], state)
	return b
}

func SignStateToString(state []byte, signingKey ed25519.PrivateKey) string {
	sig := ed25519.Sign(signingKey, state)
	buf := bytes.Buffer{}
	enc := base64.NewEncoder(base64.URLEncoding, &buf)
	if _, err := enc.Write(sig); err != nil {
		panic("unable to write sig: " + err.Error())
	}
	if _, err := enc.Write(state); err != nil {
		panic("unable to write state: " + err.Error())
	}
	enc.Close()
	return buf.String()
}

func (rst *RawStateToken) Verify(verifyKey ed25519.PublicKey) (*StateToken, error) {
	if len(*rst) < ed25519.SignatureSize {
		return nil, errors.New("invalid signature size")
	}
	sig := (*rst)[0:ed25519.SignatureSize]
	msg := (*rst)[ed25519.SignatureSize:]
	ok := ed25519.Verify(verifyKey, msg, sig)
	if !ok {
		return nil, ErrInvalidSignature
	}
	return &StateToken{
		Signature: sig,
		Value:     msg,
	}, nil
}
