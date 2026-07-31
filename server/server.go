package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
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

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	"hop.computer/hop/pkg"
	"hop.computer/hop/transport"
	"hop.computer/vend/protocol"
	"hop.computer/vend/server/config"
	"hop.computer/vend/server/gh"
)

const stateCookieName = "hop_vend_state"

// Server authenticates GitHub organization members and issues Hop credentials.
type Server struct {
	cfg              *config.Config
	oauthConfig      *oauth2.Config
	stateVerifyKey   ed25519.PublicKey
	stateSigningKey  ed25519.PrivateKey
	intermediateCert *certs.Certificate
	intermediatePEM  string
	apiBaseURL       string
	apiVersion       string
	now              func() time.Time
	pendingMu        sync.Mutex
	pending          map[string]*pendingRequest
}

// New loads the issuing material and creates a Server.
func New(cfg *config.Config) *Server {
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
		cfg: cfg,
		oauthConfig: &oauth2.Config{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			RedirectURL:  strings.TrimRight(cfg.PublicURL, "/") + "/callback",
			Scopes:       []string{"read:user", "read:org"},
			Endpoint:     github.Endpoint,
		},
		stateVerifyKey:   public,
		stateSigningKey:  private,
		intermediateCert: intermediate,
		intermediatePEM:  string(intermediatePEM),
		apiBaseURL:       "https://api.github.com",
		apiVersion:       "2022-11-28",
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

// Start serves the Hop enrollment protocol and the OAuth endpoints.
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
		http.Error(w, "unable to create OAuth state", http.StatusInternalServerError)
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
		http.Error(w, "unable to create OAuth state", http.StatusInternalServerError)
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
	authURL := s.oauthConfig.AuthCodeURL(signedState, oauth2.AccessTypeOnline)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	stateParam := r.URL.Query().Get("state")
	if stateParam == "" {
		http.Error(w, "missing state", http.StatusBadRequest)
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
		s.failRequest(decoded.RequestID, "OAuth state did not match")
		http.Error(w, "mismatched state", http.StatusBadRequest)
		return
	}
	pending, err := s.getPending(decoded.RequestID)
	if err != nil || decoded.ExpiresAt <= s.now().Unix() || decoded.PublicKey != pending.publicKey.String() {
		http.Error(w, errRequestExpired.Error(), http.StatusGone)
		return
	}
	s.clearStateCookie(w)

	code := r.URL.Query().Get("code")
	if code == "" {
		s.failRequest(decoded.RequestID, "GitHub did not return an authorization code")
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}
	token, err := s.oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		s.failRequest(decoded.RequestID, "GitHub authorization failed")
		http.Error(w, "failed to exchange GitHub authorization", http.StatusBadGateway)
		return
	}

	client := s.oauthConfig.Client(r.Context(), token)
	user, err := s.fetchGitHubUser(r.Context(), client)
	if err != nil {
		s.failRequest(decoded.RequestID, "GitHub user lookup failed")
		http.Error(w, "failed to fetch GitHub user", http.StatusBadGateway)
		return
	}
	member, err := s.isActiveOrgMember(r.Context(), client)
	if err != nil {
		s.failRequest(decoded.RequestID, "GitHub organization lookup failed")
		http.Error(w, "failed to check GitHub organization membership", http.StatusBadGateway)
		return
	}
	if !member {
		s.failRequest(decoded.RequestID, "GitHub account is not an active member of "+s.cfg.GitHubOrg)
		http.Error(w, "active organization membership required", http.StatusForbidden)
		return
	}

	credential, err := issueLeafFor(
		s.intermediateCert,
		pending.publicKey,
		certs.RawStringName(user.Login),
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
		Username:     user.Login,
		ExpiresAt:    credential.ExpiresAt,
	}
	if err := s.completePending(decoded.RequestID, result); err != nil {
		http.Error(w, err.Error(), http.StatusGone)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "Credential issued for %s. You can return to the terminal.\n", user.Login)
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

func (s *Server) fetchGitHubUser(ctx context.Context, client *http.Client) (*gh.User, error) {
	var user gh.User
	status, err := s.getGitHubJSON(ctx, client, s.apiBaseURL+"/user", &user)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || user.Login == "" {
		return nil, fmt.Errorf("GitHub user endpoint returned status %d", status)
	}
	return &user, nil
}

func (s *Server) isActiveOrgMember(ctx context.Context, client *http.Client) (bool, error) {
	endpoint := fmt.Sprintf("%s/user/memberships/orgs/%s", s.apiBaseURL, url.PathEscape(s.cfg.GitHubOrg))
	var membership gh.Membership
	status, err := s.getGitHubJSON(ctx, client, endpoint, &membership)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusOK:
		return membership.State == "active", nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("GitHub membership endpoint returned status %d", status)
	}
}

func (s *Server) getGitHubJSON(ctx context.Context, client *http.Client, endpoint string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", s.apiVersion)
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return resp.StatusCode, err
	}
	return resp.StatusCode, nil
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
