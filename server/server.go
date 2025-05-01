package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"hop.computer/vend/pkg/config"
)

type Server struct {
	cfg             *config.Config
	oauthConfig     *oauth2.Config
	stateVerifyKey  ed25519.PublicKey
	stateSigningKey ed25519.PrivateKey
}

func New(cfg *config.Config) *Server {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic("unable to generate ed25519 key: " + err.Error())
	}
	return &Server{
		cfg: cfg,
		oauthConfig: &oauth2.Config{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			Scopes:       []string{"read:user", "read:org"},
			Endpoint:     github.Endpoint,
		},
		stateVerifyKey:  public,
		stateSigningKey: private,
	}
}

func (s *Server) Start() error {
	http.HandleFunc("/healthz", s.handleHealthz)
	http.HandleFunc("/login", s.handleLogin)
	http.HandleFunc("/callback", s.handleCallback)
	http.HandleFunc("/issue", s.handleIssue)

	slog.Info("Starting server", "address", s.cfg.ServerAddress)
	return http.ListenAndServe(s.cfg.ServerAddress, nil)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "ok")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	rawState := make([]byte, 4)
	_, err := rand.Read(rawState)
	if err != nil {
		panic("unable to read random: " + err.Error())
	}
	state := SignStateToString(rawState, s.stateSigningKey)
	url := s.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline)
	slog.Debug("generate callback", "state", state, "url", url)
	// TODO(dadrian)[2025-04-30]: Determine if these are the cookie settings we
	// want. Set expiry, etc.
	http.SetCookie(w, &http.Cookie{Name: "state", Value: state})
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	cookie, err := r.Cookie("state")
	if err != nil {
		http.Error(w, "missing cookie", http.StatusBadRequest)
		return
	}
	slog.Debug("got cookie", "state", cookie.Value)
	rawCookieState, err := RawStateTokenFromString(cookie.Value)
	if err != nil {
		http.Error(w, "unparsed cookie", http.StatusBadRequest)
		return
	}
	cookieState, err := rawCookieState.Verify(s.stateVerifyKey)
	if err != nil {
		http.Error(w, "invalid cookie "+err.Error(), http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "missing state", http.StatusBadRequest)
		return
	}
	rawURLState, err := RawStateTokenFromString(state)
	if err != nil {
		http.Error(w, "bad state", http.StatusBadRequest)
		return
	}
	urlState, err := rawURLState.Verify(s.stateVerifyKey)
	if err != nil {
		http.Error(w, "bad state", http.StatusBadRequest)
		return
	}

	if subtle.ConstantTimeCompare(urlState.Value, cookieState.Value) != 1 {
		http.Error(w, "mismatched state", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	token, err := s.oauthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Unset the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	fmt.Fprintf(w, "Access token: %s", token.AccessToken)
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	// TODO: Validate GitHub token, check org membership, issue cert
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
