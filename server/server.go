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

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	"hop.computer/hop/pkg"
	"hop.computer/hop/pkg/must"
	"hop.computer/vend/server/config"
	"hop.computer/vend/server/gh"
)

type Server struct {
	cfg              *config.Config
	oauthConfig      *oauth2.Config
	stateVerifyKey   ed25519.PublicKey
	stateSigningKey  ed25519.PrivateKey
	intermediateCert *certs.Certificate
}

func New(cfg *config.Config) *Server {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		pkg.Panicf("unable to generate ed25519 key: %s", err)
	}
	inter, err := certs.ReadCertificatePEMFile(cfg.IntermediateCAPath)
	if err != nil {
		pkg.Panicf("unable to read intermediate CA at %s: %s", cfg.IntermediateCAPath, err)
	}
	if inter.Type != certs.Intermediate {
		pkg.Panicf("intermediate %s is a %s, not an intermediate", cfg.IntermediateCAPath, inter.Type)
	}
	interKey, err := keys.ReadSigningPrivateKeyPEMFile(cfg.IntermediateKeyPath)
	if err != nil {
		pkg.Panicf("unable to read issuing private key %s: %s", cfg.IntermediateKeyPath, err)
	}
	p := &interKey.Private
	if err := inter.ProvideKey((*[32]byte)(p)); err != nil {
		pkg.Panicf("mismatched private key: %s", err)
	}
	return &Server{
		cfg: cfg,
		oauthConfig: &oauth2.Config{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			Scopes:       []string{"read:user", "read:org"},
			Endpoint:     github.Endpoint,
		},
		stateVerifyKey:   public,
		stateSigningKey:  private,
		intermediateCert: inter,
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
	fmt.Fprintf(w, "gh access token %s\n", token.AccessToken)

	// Issue Hop certificate here based on Github username
	//
	// TODO(dadrian): Pipe a public key through `state`
	// The struggle here is that we don't know what public key to issue to. If
	// we want to avoid storing state in this program, then we want to somehow
	// we want to shuffle the private key through the `state` variable during
	// the exchange. This means we would want to provide the public key to the
	// app at some endpoint before doing the redirect on login. This could be,
	// e.g., via a form on /login (or by query parameter).
	//
	// For now, just issue to a random identity
	clientKey := keys.GenerateNewX25519KeyPair()
	identity := certs.LeafIdentity(clientKey, certs.RawStringName(user.Login))
	cert, err := certs.IssueLeaf(s.intermediateCert, identity)
	if err != nil {
		http.Error(w, "unable to issue cert: "+err.Error(), http.StatusInternalServerError)
		return
	}
	certBytes, err := certs.EncodeCertificateToPEM(cert)
	if err != nil {
		http.Error(w, "unable to write cert: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%s\n", certBytes)
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	// TODO: Validate GitHub token, check org membership, issue cert
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
