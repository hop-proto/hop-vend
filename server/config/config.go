package config

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	GitHubClientID     string
	GitHubClientSecret string
	GitHubOrg          string

	RootCAPath          string
	RootKeyPath         string
	CertValiditySeconds int

	ServerAddress string
}

// Load reads configuration from environment variables or a config file.
func Load() (*Config, error) {
	viper.SetConfigName("config") // name of config file (without extension)
	viper.SetConfigType("toml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/hop-vend/")

	// Environment variables override config file
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetEnvPrefix("hop_vend")

	// Set default values
	viper.SetDefault("ServerAddress", ":8080")
	viper.SetDefault("CertValidityHours", 24)

	if err := viper.ReadInConfig(); err != nil {
		// It's okay if config file is missing; rely on env vars
		fmt.Printf("No config file found, relying on env vars: %v\n", err)
	}

	cfg := &Config{
		GitHubClientID:      viper.GetString("github.client_id"),
		GitHubClientSecret:  viper.GetString("github.client_secret"),
		GitHubOrg:           viper.GetString("github.org"),
		RootCAPath:          viper.GetString("ca.cert_path"),
		RootKeyPath:         viper.GetString("ca.key_path"),
		CertValiditySeconds: viper.GetInt("credential.validity_seconds"),
		ServerAddress:       viper.GetString("ServerAddress"),
	}
	slog.Info("github", "client_id", cfg.GitHubClientID)

	// Basic validation
	missingFields := []string{}
	if cfg.GitHubClientID == "" {
		missingFields = append(missingFields, "GitHubClientID")
	}
	if cfg.GitHubClientSecret == "" {
		missingFields = append(missingFields, "github.client_secret")
	}
	if cfg.GitHubOrg == "" {
		missingFields = append(missingFields, "GitHubOrg")
	}
	if cfg.RootCAPath == "" {
		missingFields = append(missingFields, "RootCAPath")
	}
	if cfg.RootKeyPath == "" {
		missingFields = append(missingFields, "RootKeyPath")
	}
	if len(missingFields) > 0 {
		return nil, fmt.Errorf("missing required configuration fields: %v", missingFields)
	}

	return cfg, nil
}
