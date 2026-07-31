package server

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"hop.computer/hop/keys"
	"hop.computer/vend/protocol"
)

var errRequestExpired = errors.New("credential request is missing or expired")

type pendingRequest struct {
	publicKey keys.DHPublicKey
	expiresAt time.Time
	result    chan protocol.Credential
}

func newRequestID() (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

func (s *Server) addPending(publicKey keys.DHPublicKey) (string, *pendingRequest, error) {
	id, err := newRequestID()
	if err != nil {
		return "", nil, err
	}
	pending := &pendingRequest{
		publicKey: publicKey,
		expiresAt: s.now().Add(s.cfg.RequestTimeout),
		result:    make(chan protocol.Credential, 1),
	}
	s.pendingMu.Lock()
	s.pending[id] = pending
	s.pendingMu.Unlock()
	return id, pending, nil
}

func (s *Server) getPending(id string) (*pendingRequest, error) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	pending, ok := s.pending[id]
	if !ok {
		return nil, errRequestExpired
	}
	if !s.now().Before(pending.expiresAt) {
		delete(s.pending, id)
		return nil, errRequestExpired
	}
	return pending, nil
}

func (s *Server) completePending(id string, result protocol.Credential) error {
	s.pendingMu.Lock()
	pending, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	}
	s.pendingMu.Unlock()
	if !ok || !s.now().Before(pending.expiresAt) {
		return errRequestExpired
	}
	pending.result <- result
	return nil
}

func (s *Server) cancelPending(id string) {
	s.pendingMu.Lock()
	delete(s.pending, id)
	s.pendingMu.Unlock()
}
