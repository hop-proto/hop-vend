package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"hop.computer/vend/pkg/config"
)

type Server struct {
	cfg         *config.Config
	oauthConfig *oauth2.Config
}

func New(cfg *config.Config) *Server {
	return &Server{
		cfg: cfg,
		oauthConfig: &oauth2.Config{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			Scopes:       []string{"read:user", "read:org"},
			Endpoint:     github.Endpoint,
		},
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
	state := "placeholder-state" // TODO: generate and validate this state
	url := s.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
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

	fmt.Fprintf(w, "Access token: %s", token.AccessToken)
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	// TODO: Validate GitHub token, check org membership, issue cert
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
