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
	GitHubClientID     string
	GitHubClientSecret string
	GitHubOrg          string

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
	v.SetDefault("credential.validity_seconds", 3600)
	v.SetDefault("credential.request_timeout_seconds", 600)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	cfg := &Config{
		GitHubClientID:      v.GetString("github.client_id"),
		GitHubClientSecret:  v.GetString("github.client_secret"),
		GitHubOrg:           v.GetString("github.org"),
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
	missing := make([]string, 0, 6)
	for name, value := range map[string]string{
		"github.client_id":     c.GitHubClientID,
		"github.client_secret": c.GitHubClientSecret,
		"github.org":           c.GitHubOrg,
		"ca.cert_path":         c.IntermediateCAPath,
		"ca.key_path":          c.IntermediateKeyPath,
		"server.public_url":    c.PublicURL,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("missing required configuration fields: %s", strings.Join(missing, ", "))
	}
	publicURL, err := url.Parse(c.PublicURL)
	if err != nil || publicURL.Host == "" || (publicURL.Scheme != "http" && publicURL.Scheme != "https") {
		return fmt.Errorf("server.public_url must be an absolute HTTP(S) URL")
	}
	if c.CertValidity <= 0 {
		return fmt.Errorf("credential.validity_seconds must be positive")
	}
	if c.RequestTimeout <= 0 {
		return fmt.Errorf("credential.request_timeout_seconds must be positive")
	}
	return nil
}
