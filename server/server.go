package server

import (
	"fmt"
	"log"
	"net/http"

	"hop.computer/vend/pkg/config"
)

type Server struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Server {
	return &Server{
		cfg: cfg,
	}
}

func (s *Server) Start() error {
	http.HandleFunc("/healthz", s.handleHealthz)
	http.HandleFunc("/login", s.handleLogin)
	http.HandleFunc("/callback", s.handleCallback)
	http.HandleFunc("/issue", s.handleIssue)

	log.Printf("Starting server at %s...", s.cfg.ServerAddress)
	return http.ListenAndServe(s.cfg.ServerAddress, nil)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "ok")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// TODO: Redirect user to GitHub OAuth login
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	// TODO: Handle GitHub OAuth callback and exchange code for token
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	// TODO: Validate GitHub token, check org membership, issue cert
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
