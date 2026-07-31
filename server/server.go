package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	"hop.computer/hop/pkg"
	"hop.computer/hop/transport"
	"hop.computer/vend/protocol"
	"hop.computer/vend/server/config"
)

const stateCookieName = "hop_vend_state"

// Server authenticates authorized identities and issues Hop credentials.
type Server struct {
	cfg              *config.Config
	authenticator    Authenticator
	authorizer       Authorizer
	stateVerifyKey   ed25519.PublicKey
	stateSigningKey  ed25519.PrivateKey
	intermediateCert *certs.Certificate
	intermediatePEM  string
	now              func() time.Time
	pendingMu        sync.Mutex
	pending          map[string]*pendingRequest
}

// New loads the issuing material and creates a Server.
func New(cfg *config.Config) *Server {
	authenticator, authorizer, err := authenticationForConfig(cfg)
	if err != nil {
		pkg.Panicf("unable to configure authentication: %s", err)
	}
	return NewWithAuth(cfg, authenticator, authorizer)
}

// NewWithAuth loads the issuing material and creates a Server using the
// supplied authentication and authorization implementations.
func NewWithAuth(cfg *config.Config, authenticator Authenticator, authorizer Authorizer) *Server {
	if authenticator == nil {
		pkg.Panicf("authenticator is required")
	}
	if authorizer == nil {
		pkg.Panicf("authorizer is required")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		pkg.Panicf("unable to generate ed25519 key: %s", err)
	}
	intermediate, err := certs.ReadCertificatePEMFile(cfg.IntermediateCAPath)
	if err != nil {
		pkg.Panicf("unable to read intermediate CA at %s: %s", cfg.IntermediateCAPath, err)
	}
	if intermediate.Type != certs.Intermediate {
		pkg.Panicf("intermediate %s is a %s, not an intermediate", cfg.IntermediateCAPath, intermediate.Type)
	}
	now := time.Now()
	if now.Before(intermediate.IssuedAt) || !now.Before(intermediate.ExpiresAt) {
		pkg.Panicf(
			"intermediate certificate is not currently valid (valid from %s until %s)",
			intermediate.IssuedAt,
			intermediate.ExpiresAt,
		)
	}
	intermediateKey, err := keys.ReadSigningPrivateKeyPEMFile(cfg.IntermediateKeyPath)
	if err != nil {
		pkg.Panicf("unable to read issuing private key %s: %s", cfg.IntermediateKeyPath, err)
	}
	if !bytes.Equal(intermediate.PublicKey[:], intermediateKey.Public[:]) {
		pkg.Panicf("intermediate certificate and private key do not match")
	}
	if err := intermediate.ProvideKey((*[32]byte)(&intermediateKey.Private)); err != nil {
		pkg.Panicf("unable to use issuing private key: %s", err)
	}
	intermediatePEM, err := certs.EncodeCertificateToPEM(intermediate)
	if err != nil {
		pkg.Panicf("unable to encode intermediate CA: %s", err)
	}

	return &Server{
		cfg:              cfg,
		authenticator:    authenticator,
		authorizer:       authorizer,
		stateVerifyKey:   public,
		stateSigningKey:  private,
		intermediateCert: intermediate,
		intermediatePEM:  string(intermediatePEM),
		now:              time.Now,
		pending:          make(map[string]*pendingRequest),
	}
}

// Handler returns the HTTP endpoints served by Hop Vend.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/callback", s.handleCallback)
	return mux
}

// Start serves the Hop enrollment protocol and browser authentication
// endpoints.
func (s *Server) Start() error {
	if _, err := s.startHop(); err != nil {
		return fmt.Errorf("start Hop enrollment server: %w", err)
	}

	httpServer := &http.Server{
		Addr:              s.cfg.ServerAddress,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	slog.Info("starting HTTP server", "address", s.cfg.ServerAddress)
	return httpServer.ListenAndServe()
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestID := r.URL.Query().Get("request")
	pending, err := s.getPending(requestID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusGone)
		return
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		http.Error(w, "unable to create authentication state", http.StatusInternalServerError)
		return
	}
	state := State{
		Random:    random,
		RequestID: requestID,
		PublicKey: pending.publicKey.String(),
		ExpiresAt: pending.expiresAt.Unix(),
	}
	signedState, err := SignStateToString(&state, s.stateSigningKey)
	if err != nil {
		http.Error(w, "unable to create authentication state", http.StatusInternalServerError)
		return
	}

	secureCookie := strings.HasPrefix(strings.ToLower(s.cfg.PublicURL), "https://")
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    signedState,
		Path:     "/callback",
		MaxAge:   int(time.Until(pending.expiresAt).Seconds()),
		HttpOnly: true,
		Secure:   secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
	if err := s.authenticator.Begin(w, r, AuthTransaction{
		State: signedState,
		Nonce: base64.RawURLEncoding.EncodeToString(random),
	}); err != nil {
		s.failRequest(requestID, "unable to start authentication")
		http.Error(w, "unable to start authentication", http.StatusBadGateway)
	}
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	stateParam, err := s.authenticator.State(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rawURLState, err := RawStateTokenFromString(stateParam)
	if err != nil {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	urlState, err := rawURLState.Verify(s.stateVerifyKey)
	if err != nil {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	decoded, err := urlState.Unmarshal()
	if err != nil {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie(stateCookieName)
	if err != nil {
		s.failRequest(decoded.RequestID, "browser session was not preserved")
		http.Error(w, "missing state cookie", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(stateParam)) != 1 {
		s.failRequest(decoded.RequestID, "authentication state did not match")
		http.Error(w, "mismatched state", http.StatusBadRequest)
		return
	}
	pending, err := s.getPending(decoded.RequestID)
	if err != nil || decoded.ExpiresAt <= s.now().Unix() || decoded.PublicKey != pending.publicKey.String() {
		http.Error(w, errRequestExpired.Error(), http.StatusGone)
		return
	}
	s.clearStateCookie(w)

	principal, err := s.authenticator.Complete(r.Context(), r, AuthTransaction{
		State: stateParam,
		Nonce: base64.RawURLEncoding.EncodeToString(decoded.Random),
	})
	if err != nil {
		s.failRequest(decoded.RequestID, "authentication failed")
		http.Error(w, "authentication failed", http.StatusBadGateway)
		return
	}
	if err := s.authorizer.Authorize(r.Context(), principal); err != nil {
		if errors.Is(err, ErrUnauthorized) {
			s.failRequest(decoded.RequestID, err.Error())
			http.Error(w, "identity is not authorized", http.StatusForbidden)
			return
		}
		s.failRequest(decoded.RequestID, "authorization check failed")
		http.Error(w, "authorization check failed", http.StatusBadGateway)
		return
	}

	credential, err := issueLeafFor(
		s.intermediateCert,
		pending.publicKey,
		certs.RawStringName(principal.Name),
		s.cfg.CertValidity,
		s.now(),
	)
	if err != nil {
		s.failRequest(decoded.RequestID, "credential issuance failed")
		http.Error(w, "unable to issue credential", http.StatusInternalServerError)
		return
	}
	credentialPEM, err := certs.EncodeCertificateToPEM(credential)
	if err != nil {
		s.failRequest(decoded.RequestID, "credential encoding failed")
		http.Error(w, "unable to encode credential", http.StatusInternalServerError)
		return
	}
	result := protocol.Credential{
		Certificate:  string(credentialPEM),
		Intermediate: s.intermediatePEM,
		Username:     principal.Name,
		ExpiresAt:    credential.ExpiresAt,
	}
	if err := s.completePending(decoded.RequestID, result); err != nil {
		http.Error(w, err.Error(), http.StatusGone)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "Credential issued for %s. You can return to the terminal.\n", principal.Name)
}

func (s *Server) clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    "",
		Path:     "/callback",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   strings.HasPrefix(strings.ToLower(s.cfg.PublicURL), "https://"),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) failRequest(id, message string) {
	if id == "" {
		return
	}
	_ = s.completePending(id, protocol.Credential{Error: message})
}

func (s *Server) startHop() (*transport.Server, error) {
	key := keys.GenerateNewX25519KeyPair()
	credential, err := issueLeafFor(
		s.intermediateCert,
		key.Public,
		certs.RawStringName(s.cfg.HopServerName),
		24*time.Hour,
		s.now(),
	)
	if err != nil {
		return nil, err
	}
	packetConn, err := net.ListenPacket("udp", s.cfg.HopAddress)
	if err != nil {
		return nil, err
	}
	cfg := transport.ServerConfig{
		KeyPair:          key,
		Certificate:      credential,
		Intermediate:     s.intermediateCert,
		HandshakeTimeout: 15 * time.Second,
		ClientVerify:     &transport.VerifyConfig{InsecureSkipVerify: true},
	}
	hopServer, err := transport.NewServer(transport.NewUDPMsgConn(packetConn.(*net.UDPConn)), cfg)
	if err != nil {
		_ = packetConn.Close()
		return nil, err
	}
	go s.acceptHopConnections(hopServer)
	go hopServer.Serve()
	slog.Info("starting Hop enrollment server", "address", packetConn.LocalAddr().String())
	return hopServer, nil
}

func (s *Server) acceptHopConnections(hopServer *transport.Server) {
	for {
		conn, err := hopServer.Accept()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			slog.Error("Hop accept failed", "error", err)
			continue
		}
		go s.handleHopConnection(conn)
	}
}

func (s *Server) handleHopConnection(conn *transport.Handle) {
	defer conn.Close()
	leaf := conn.FetchClientLeaf()
	if leaf == nil {
		slog.Warn("enrollment connection did not present a client certificate")
		return
	}
	requestID, pending, err := s.addPending(keys.DHPublicKey(leaf.PublicKey))
	if err != nil {
		slog.Error("unable to create enrollment request", "error", err)
		return
	}
	defer s.cancelPending(requestID)

	loginURL := strings.TrimRight(s.cfg.PublicURL, "/") + "/login?request=" + url.QueryEscape(requestID)
	if err := json.NewEncoder(conn).Encode(protocol.Login{
		LoginURL:  loginURL,
		ExpiresAt: pending.expiresAt,
	}); err != nil {
		slog.Warn("unable to send enrollment URL", "error", err)
		return
	}

	timer := time.NewTimer(time.Until(pending.expiresAt))
	defer timer.Stop()
	disconnected := make(chan struct{})
	go func() {
		buffer := make([]byte, 1)
		_, _ = conn.Read(buffer)
		close(disconnected)
	}()
	select {
	case result := <-pending.result:
		if err := json.NewEncoder(conn).Encode(result); err != nil {
			slog.Warn("unable to send enrollment result", "error", err)
		}
	case <-timer.C:
		_ = json.NewEncoder(conn).Encode(protocol.Credential{Error: "credential request expired"})
	case <-disconnected:
		return
	}
}
