package server

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"hop.computer/hop/pkg/must"
	"hop.computer/vend/server/config"
	"hop.computer/vend/server/gh"
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
	must.ReadRandom(rawState)
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
	// TODO(dadrian): This might actually be a bad idea. If the OAuth request
	// gets replayed, e.g. because the user clicked back, it's unclear which
	// state value Github will want to use.
	//
	// It may make more sense to keep the cookie, and just track a bunch of
	// state server-side.
	//
	// Alternatively, depending on how this app shakes out, maybe the server can
	// be completely stateless.
	http.SetCookie(w, &http.Cookie{
		Name:     "state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	// Use the access token to fetch the user's organizations, and compare to
	// the target organization in the configuration.

	// Begin by fetching the user to get their organizations URL.
	client := s.oauthConfig.Client(ctx, token)
	var user gh.User
	{
		resp, err := client.Get("https://api.github.com/user")

		if err != nil || resp.StatusCode != http.StatusOK {
			http.Error(w, "failed to fetch user", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			http.Error(w, "failed to decode user", http.StatusInternalServerError)
			return
		}
		slog.Info("github api", "user", user)
	}

	{
		var orgs []gh.Organization
		resp, err := client.Get(user.OrganizationsURL)

		if err != nil || resp.StatusCode != http.StatusOK {
			http.Error(w, "failed to fetch orgs", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
			http.Error(w, "failed to decode orgs", http.StatusInternalServerError)
			return
		}
		slog.Info("github api", "orgs", orgs)

	}

	// Use the username of the user and the org name from the configuration to
	// check membership. There is an API call specific for this that returns
	// 204.
	// https://api.github.com/orgs/ORG/members/USERNAME
	{
		url := fmt.Sprintf("https://api.github.com/orgs/%s/members/%s", url.PathEscape(s.cfg.GitHubOrg), url.PathEscape(user.Login))
		slog.Info("github api", "url", url, "user", user.Login, "org", s.cfg.GitHubOrg)
		resp, err := client.Get(url)

		if err != nil || resp.StatusCode != 204 {
			http.Error(w, fmt.Sprintf("bad status %d", resp.StatusCode), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
	}
	fmt.Fprintf(w, "gh access token %s", token.AccessToken)

	// TODO(dadrian): Issue Hop certificate here based on Github username
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	// TODO: Validate GitHub token, check org membership, issue cert
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
