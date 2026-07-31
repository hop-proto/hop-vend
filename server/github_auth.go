package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"hop.computer/vend/server/gh"
)

const (
	githubAPIBaseURL = "https://api.github.com"
	githubAPIVersion = "2022-11-28"
)

// GitHubAuthenticatorConfig configures GitHub OAuth authentication.
type GitHubAuthenticatorConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	APIBaseURL   string
	APIVersion   string
	Endpoint     oauth2.Endpoint
}

// GitHubAuthenticator authenticates a GitHub user through OAuth.
type GitHubAuthenticator struct {
	oauthConfig *oauth2.Config
	apiBaseURL  string
	apiVersion  string
}

type githubSession struct {
	client     *http.Client
	apiBaseURL string
	apiVersion string
}

// NewGitHubAuthenticator creates a GitHub OAuth authenticator.
func NewGitHubAuthenticator(cfg GitHubAuthenticatorConfig) *GitHubAuthenticator {
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = githubAPIBaseURL
	}
	if cfg.APIVersion == "" {
		cfg.APIVersion = githubAPIVersion
	}
	if cfg.Endpoint.AuthURL == "" || cfg.Endpoint.TokenURL == "" {
		cfg.Endpoint = github.Endpoint
	}
	return &GitHubAuthenticator{
		oauthConfig: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{"read:user", "read:org"},
			Endpoint:     cfg.Endpoint,
		},
		apiBaseURL: cfg.APIBaseURL,
		apiVersion: cfg.APIVersion,
	}
}

// Begin redirects the browser to GitHub's authorization endpoint.
func (a *GitHubAuthenticator) Begin(w http.ResponseWriter, r *http.Request, transaction AuthTransaction) error {
	http.Redirect(w, r, a.oauthConfig.AuthCodeURL(transaction.State, oauth2.AccessTypeOnline), http.StatusFound)
	return nil
}

// State returns the OAuth state from a GitHub callback.
func (a *GitHubAuthenticator) State(r *http.Request) (string, error) {
	return oauthState(r)
}

// Complete exchanges the authorization code and resolves the authenticated
// GitHub user.
func (a *GitHubAuthenticator) Complete(
	ctx context.Context,
	r *http.Request,
	_ AuthTransaction,
) (*Principal, error) {
	if err := oauthProviderError(r); err != nil {
		return nil, err
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, errors.New("GitHub did not return an authorization code")
	}
	token, err := a.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchange GitHub authorization: %w", err)
	}
	client := a.oauthConfig.Client(ctx, token)
	session := &githubSession{
		client:     client,
		apiBaseURL: a.apiBaseURL,
		apiVersion: a.apiVersion,
	}
	var user gh.User
	status, err := session.getJSON(ctx, a.apiBaseURL+"/user", &user)
	if err != nil {
		return nil, fmt.Errorf("fetch GitHub user: %w", err)
	}
	if status != http.StatusOK || user.Login == "" || user.ID == 0 {
		return nil, fmt.Errorf("GitHub user endpoint returned status %d or an incomplete identity", status)
	}
	return &Principal{
		Subject: "github:" + strconv.FormatInt(user.ID, 10),
		Name:    user.Login,
		Claims: map[string]any{
			"login": user.Login,
			"id":    user.ID,
			"type":  user.Type,
		},
		session: session,
	}, nil
}

// GitHubOrganizationAuthorizer requires active membership in a GitHub
// organization.
type GitHubOrganizationAuthorizer struct {
	Organization string
}

// Authorize checks the authenticated user's organization membership.
func (a GitHubOrganizationAuthorizer) Authorize(ctx context.Context, principal *Principal) error {
	if principal == nil {
		return fmtUnauthorized("GitHub principal is missing")
	}
	session, ok := principal.session.(*githubSession)
	if !ok {
		return errors.New("GitHub authorization requires a GitHub authentication session")
	}
	endpoint := fmt.Sprintf(
		"%s/user/memberships/orgs/%s",
		session.apiBaseURL,
		url.PathEscape(a.Organization),
	)
	var membership gh.Membership
	status, err := session.getJSON(ctx, endpoint, &membership)
	if err != nil {
		return fmt.Errorf("check GitHub organization membership: %w", err)
	}
	switch status {
	case http.StatusOK:
		if membership.State != "active" {
			return fmtUnauthorized("GitHub account is not an active member of " + a.Organization)
		}
		return nil
	case http.StatusNotFound:
		return fmtUnauthorized("GitHub account is not an active member of " + a.Organization)
	default:
		return fmt.Errorf("GitHub membership endpoint returned status %d", status)
	}
}

func (s *githubSession) getJSON(ctx context.Context, endpoint string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", s.apiVersion)
	resp, err := s.client.Do(req)
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

func oauthState(r *http.Request) (string, error) {
	if r.Method != http.MethodGet {
		return "", errors.New("OAuth callback requires GET")
	}
	state := r.URL.Query().Get("state")
	if state == "" {
		return "", errors.New("missing OAuth state")
	}
	return state, nil
}

func oauthProviderError(r *http.Request) error {
	query := r.URL.Query()
	providerError := query.Get("error")
	if providerError == "" {
		return nil
	}
	description := query.Get("error_description")
	if description == "" {
		description = providerError
	}
	return fmt.Errorf("identity provider rejected authentication: %s", description)
}
