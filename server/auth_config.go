package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"hop.computer/vend/server/config"
)

func authenticationForConfig(cfg *config.Config) (Authenticator, Authorizer, error) {
	redirectURL := strings.TrimRight(cfg.PublicURL, "/") + "/callback"
	switch strings.ToLower(cfg.AuthProvider) {
	case "", "github":
		return NewGitHubAuthenticator(GitHubAuthenticatorConfig{
				ClientID:     cfg.GitHubClientID,
				ClientSecret: cfg.GitHubClientSecret,
				RedirectURL:  redirectURL,
			}),
			GitHubOrganizationAuthorizer{Organization: cfg.GitHubOrg},
			nil
	case "oidc":
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		authenticator, err := NewOIDCAuthenticator(ctx, OIDCAuthenticatorConfig{
			Issuer:        cfg.OIDCIssuer,
			ClientID:      cfg.OIDCClientID,
			ClientSecret:  cfg.OIDCClientSecret,
			RedirectURL:   redirectURL,
			Scopes:        cfg.OIDCScopes,
			IdentityClaim: cfg.OIDCIdentityClaim,
		})
		if err != nil {
			return nil, nil, err
		}
		var authorizer Authorizer = AuthenticatedAuthorizer{}
		if cfg.AuthorizationClaim != "" {
			authorizer = ClaimAuthorizer{
				Claim: cfg.AuthorizationClaim,
				Value: cfg.AuthorizationValue,
			}
		}
		return authenticator, authorizer, nil
	default:
		return nil, nil, fmt.Errorf("unsupported authentication provider %q", cfg.AuthProvider)
	}
}
