package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCAuthenticatorConfig configures a generic OpenID Connect provider.
type OIDCAuthenticatorConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	Scopes        []string
	IdentityClaim string
}

// OIDCAuthenticator authenticates identities from an OpenID Connect provider.
type OIDCAuthenticator struct {
	oauthConfig   *oauth2.Config
	verifier      *oidc.IDTokenVerifier
	identityClaim string
}

// NewOIDCAuthenticator discovers and configures an OpenID Connect provider.
func NewOIDCAuthenticator(ctx context.Context, cfg OIDCAuthenticatorConfig) (*OIDCAuthenticator, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	scopes := append([]string(nil), cfg.Scopes...)
	if !slices.Contains(scopes, oidc.ScopeOpenID) {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}
	return &OIDCAuthenticator{
		oauthConfig: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		verifier:      provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		identityClaim: cfg.IdentityClaim,
	}, nil
}

// Begin redirects the browser to the discovered OIDC authorization endpoint.
func (a *OIDCAuthenticator) Begin(w http.ResponseWriter, r *http.Request, transaction AuthTransaction) error {
	http.Redirect(
		w,
		r,
		a.oauthConfig.AuthCodeURL(
			transaction.State,
			oauth2.AccessTypeOnline,
			oauth2.SetAuthURLParam("nonce", transaction.Nonce),
		),
		http.StatusFound,
	)
	return nil
}

// State returns the OAuth state from an OIDC callback.
func (a *OIDCAuthenticator) State(r *http.Request) (string, error) {
	return oauthState(r)
}

// Complete exchanges the authorization code and verifies the returned ID
// token, including issuer, audience, signature, expiry, and nonce.
func (a *OIDCAuthenticator) Complete(
	ctx context.Context,
	r *http.Request,
	transaction AuthTransaction,
) (*Principal, error) {
	if err := oauthProviderError(r); err != nil {
		return nil, err
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, errors.New("OIDC provider did not return an authorization code")
	}
	oauthToken, err := a.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchange OIDC authorization: %w", err)
	}
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("OIDC token response did not contain an ID token")
	}
	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify OIDC ID token: %w", err)
	}
	if idToken.Subject == "" {
		return nil, errors.New("OIDC ID token subject is missing")
	}
	if idToken.Nonce == "" || idToken.Nonce != transaction.Nonce {
		return nil, errors.New("OIDC ID token nonce did not match")
	}
	claims := make(map[string]any)
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode OIDC ID token claims: %w", err)
	}
	name, ok := stringClaim(claims, a.identityClaim)
	if !ok {
		return nil, fmt.Errorf("OIDC ID token claim %q is missing or is not a string", a.identityClaim)
	}
	return &Principal{
		Subject: idToken.Issuer + "#" + idToken.Subject,
		Name:    name,
		Claims:  claims,
	}, nil
}

// ClaimAuthorizer requires an OIDC claim to contain a configured value.
type ClaimAuthorizer struct {
	Claim string
	Value string
}

// Authorize checks a scalar or array-valued claim.
func (a ClaimAuthorizer) Authorize(_ context.Context, principal *Principal) error {
	if principal == nil {
		return fmtUnauthorized("OIDC principal is missing")
	}
	value, ok := principal.Claims[a.Claim]
	if !ok || !claimContains(value, a.Value) {
		return fmtUnauthorized(fmt.Sprintf("identity claim %q does not contain %q", a.Claim, a.Value))
	}
	return nil
}

func stringClaim(claims map[string]any, name string) (string, bool) {
	value, ok := claims[name].(string)
	return value, ok && strings.TrimSpace(value) != ""
}

func claimContains(claim any, expected string) bool {
	switch value := claim.(type) {
	case string:
		return value == expected
	case []string:
		return slices.Contains(value, expected)
	case []any:
		for _, item := range value {
			if item == expected {
				return true
			}
		}
	}
	return false
}
