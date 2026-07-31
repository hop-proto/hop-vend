package server

import (
	"strings"

	"hop.computer/vend/server/config"
)

func authenticationForConfig(cfg *config.Config) (Authenticator, Authorizer, error) {
	redirectURL := strings.TrimRight(cfg.PublicURL, "/") + "/callback"
	return NewGitHubAuthenticator(GitHubAuthenticatorConfig{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			RedirectURL:  redirectURL,
		}),
		GitHubOrganizationAuthorizer{Organization: cfg.GitHubOrg},
		nil
}
