// Package config loads Hop Vend configuration from TOML and the environment.
package config

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config contains the validated Hop Vend configuration.
type Config struct {
	AuthProvider string

	GitHubClientID     string
	GitHubClientSecret string
	GitHubOrg          string

	OIDCIssuer        string
	OIDCClientID      string
	OIDCClientSecret  string
	OIDCScopes        []string
	OIDCIdentityClaim string

	AuthorizationClaim string
	AuthorizationValue string

	IntermediateCAPath  string
	IntermediateKeyPath string
	CertValidity        time.Duration
	RequestTimeout      time.Duration

	ServerAddress string
	PublicURL     string
	HopAddress    string
	HopServerName string
}

// Load reads configuration from environment variables or a config file.
func Load() (*Config, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("toml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")
	v.AddConfigPath("/etc/hop-vend/")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetEnvPrefix("hop_vend")

	v.SetDefault("server.address", ":8080")
	v.SetDefault("hop.address", ":7777")
	v.SetDefault("hop.server_name", "vend-server")
	v.SetDefault("authentication.provider", "github")
	v.SetDefault("oidc.identity_claim", "preferred_username")
	v.SetDefault("oidc.scopes", []string{"openid", "profile", "email"})
	v.SetDefault("credential.validity_seconds", 3600)
	v.SetDefault("credential.request_timeout_seconds", 600)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	cfg := &Config{
		AuthProvider:        v.GetString("authentication.provider"),
		GitHubClientID:      v.GetString("github.client_id"),
		GitHubClientSecret:  v.GetString("github.client_secret"),
		GitHubOrg:           v.GetString("github.org"),
		OIDCIssuer:          strings.TrimRight(v.GetString("oidc.issuer"), "/"),
		OIDCClientID:        v.GetString("oidc.client_id"),
		OIDCClientSecret:    v.GetString("oidc.client_secret"),
		OIDCScopes:          v.GetStringSlice("oidc.scopes"),
		OIDCIdentityClaim:   v.GetString("oidc.identity_claim"),
		AuthorizationClaim:  v.GetString("authorization.claim"),
		AuthorizationValue:  v.GetString("authorization.value"),
		IntermediateCAPath:  v.GetString("ca.cert_path"),
		IntermediateKeyPath: v.GetString("ca.key_path"),
		CertValidity:        time.Duration(v.GetInt("credential.validity_seconds")) * time.Second,
		RequestTimeout:      time.Duration(v.GetInt("credential.request_timeout_seconds")) * time.Second,
		ServerAddress:       v.GetString("server.address"),
		PublicURL:           strings.TrimRight(v.GetString("server.public_url"), "/"),
		HopAddress:          v.GetString("hop.address"),
		HopServerName:       v.GetString("hop.server_name"),
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	missing := make([]string, 0, 8)
	for name, value := range map[string]string{
		"authentication.provider": c.AuthProvider,
		"ca.cert_path":            c.IntermediateCAPath,
		"ca.key_path":             c.IntermediateKeyPath,
		"server.public_url":       c.PublicURL,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	switch strings.ToLower(c.AuthProvider) {
	case "github":
		for name, value := range map[string]string{
			"github.client_id":     c.GitHubClientID,
			"github.client_secret": c.GitHubClientSecret,
			"github.org":           c.GitHubOrg,
		} {
			if strings.TrimSpace(value) == "" {
				missing = append(missing, name)
			}
		}
	case "oidc":
		for name, value := range map[string]string{
			"oidc.client_id":      c.OIDCClientID,
			"oidc.client_secret":  c.OIDCClientSecret,
			"oidc.identity_claim": c.OIDCIdentityClaim,
			"oidc.issuer":         c.OIDCIssuer,
		} {
			if strings.TrimSpace(value) == "" {
				missing = append(missing, name)
			}
		}
	default:
		return fmt.Errorf("authentication.provider must be github or oidc")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("missing required configuration fields: %s", strings.Join(missing, ", "))
	}
	publicURL, err := url.Parse(c.PublicURL)
	if err != nil || publicURL.Host == "" || (publicURL.Scheme != "http" && publicURL.Scheme != "https") {
		return fmt.Errorf("server.public_url must be an absolute HTTP(S) URL")
	}
	if strings.EqualFold(c.AuthProvider, "oidc") {
		issuer, err := url.Parse(c.OIDCIssuer)
		if err != nil || issuer.Host == "" || (issuer.Scheme != "http" && issuer.Scheme != "https") {
			return fmt.Errorf("oidc.issuer must be an absolute HTTP(S) URL")
		}
		if (c.AuthorizationClaim == "") != (c.AuthorizationValue == "") {
			return fmt.Errorf("authorization.claim and authorization.value must be configured together")
		}
	}
	if c.CertValidity <= 0 {
		return fmt.Errorf("credential.validity_seconds must be positive")
	}
	if c.RequestTimeout <= 0 {
		return fmt.Errorf("credential.request_timeout_seconds must be positive")
	}
	return nil
}
