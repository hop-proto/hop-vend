package config

import (
	"strings"
	"testing"
	"time"
)

func validConfig() *Config {
	return &Config{
		GitHubClientID:      "id",
		GitHubClientSecret:  "secret",
		GitHubOrg:           "org",
		IntermediateCAPath:  "intermediate.pem",
		IntermediateKeyPath: "intermediate-key.pem",
		CertValidity:        time.Hour,
		RequestTimeout:      10 * time.Minute,
		ServerAddress:       ":8080",
		PublicURL:           "https://vend.example",
		HopAddress:          ":7777",
		HopServerName:       "vend-server",
	}
}

func TestValidate(t *testing.T) {
	if err := validConfig().validate(); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "missing secret", mutate: func(c *Config) { c.GitHubClientSecret = "" }, want: "github.client_secret"},
		{name: "relative public URL", mutate: func(c *Config) { c.PublicURL = "/callback" }, want: "absolute HTTP(S) URL"},
		{name: "invalid validity", mutate: func(c *Config) { c.CertValidity = 0 }, want: "validity_seconds"},
		{name: "invalid timeout", mutate: func(c *Config) { c.RequestTimeout = -time.Second }, want: "request_timeout_seconds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			test.mutate(cfg)
			err := cfg.validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validate() error = %v, want containing %q", err, test.want)
			}
		})
	}
}
