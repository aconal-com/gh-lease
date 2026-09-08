// Package config loads gh-lease configuration from environment variables.
//
// Loading fails closed: every required value either has a default or causes
// Load to return an error. There is no on-disk config file in v0.1.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the resolved, validated gh-lease configuration.
type Config struct {
	AppID              int64
	InstallationID     int64
	PrivateKeyPEM      []byte
	PrivateKeyPath     string
	MaxTTL             time.Duration
	DefaultTTL         time.Duration
	AllowedPermissions []string
	AllowedRepos       []string

	// GitHubAPI is the base URL for the GitHub REST API. Tests override this
	// to point at httptest.Server. Defaults to api.github.com.
	GitHubAPI string

	// HTTPClientTimeout caps the time any individual GitHub request can take.
	HTTPClientTimeout time.Duration
}

// Load reads configuration from the environment. Required variables:
//
//	GH_LEASE_APP_ID
//	GH_LEASE_INSTALLATION_ID
//	GH_LEASE_PRIVATE_KEY_FILE  (or GH_LEASE_PRIVATE_KEY for tests only)
//	GH_LEASE_MAX_TTL
//	GH_LEASE_ALLOWED_PERMISSIONS
//	GH_LEASE_ALLOWED_REPOSITORIES
func Load() (Config, error) {
	var c Config

	appIDStr, err := requireEnv("GH_LEASE_APP_ID")
	if err != nil {
		return c, err
	}
	c.AppID, err = strconv.ParseInt(appIDStr, 10, 64)
	if err != nil || c.AppID <= 0 {
		return c, fmt.Errorf("GH_LEASE_APP_ID must be a positive integer")
	}

	instIDStr, err := requireEnv("GH_LEASE_INSTALLATION_ID")
	if err != nil {
		return c, err
	}
	c.InstallationID, err = strconv.ParseInt(instIDStr, 10, 64)
	if err != nil || c.InstallationID <= 0 {
		return c, fmt.Errorf("GH_LEASE_INSTALLATION_ID must be a positive integer")
	}

	// Prefer file-based key configuration. Inline key is a fallback for
	// tests and unusual deployments where the key is provided via secret
	// manager environment.
	if keyPath := os.Getenv("GH_LEASE_PRIVATE_KEY_FILE"); keyPath != "" {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return c, fmt.Errorf("read GH_LEASE_PRIVATE_KEY_FILE: %w", err)
		}
		c.PrivateKeyPEM = key
		c.PrivateKeyPath = keyPath
	} else if inline := os.Getenv("GH_LEASE_PRIVATE_KEY"); inline != "" {
		c.PrivateKeyPEM = []byte(inline)
	} else {
		return c, errors.New("GH_LEASE_PRIVATE_KEY_FILE (or GH_LEASE_PRIVATE_KEY) is required")
	}

	maxTTLStr, err := requireEnv("GH_LEASE_MAX_TTL")
	if err != nil {
		return c, err
	}
	c.MaxTTL, err = time.ParseDuration(maxTTLStr)
	if err != nil || c.MaxTTL <= 0 {
		return c, fmt.Errorf("GH_LEASE_MAX_TTL must be a positive duration (e.g. 5m)")
	}

	c.DefaultTTL = 60 * time.Second
	if def := os.Getenv("GH_LEASE_DEFAULT_TTL"); def != "" {
		d, err := time.ParseDuration(def)
		if err != nil || d <= 0 {
			return c, fmt.Errorf("GH_LEASE_DEFAULT_TTL must be a positive duration")
		}
		c.DefaultTTL = d
	}

	perms, err := requireEnv("GH_LEASE_ALLOWED_PERMISSIONS")
	if err != nil {
		return c, err
	}
	c.AllowedPermissions = splitNonEmpty(perms)
	if len(c.AllowedPermissions) == 0 {
		return c, errors.New("GH_LEASE_ALLOWED_PERMISSIONS must list at least one permission")
	}

	repos, err := requireEnv("GH_LEASE_ALLOWED_REPOSITORIES")
	if err != nil {
		return c, err
	}
	c.AllowedRepos = splitNonEmpty(repos)
	if len(c.AllowedRepos) == 0 {
		return c, errors.New("GH_LEASE_ALLOWED_REPOSITORIES must list at least one repository")
	}

	c.GitHubAPI = os.Getenv("GH_LEASE_API")
	if c.GitHubAPI == "" {
		c.GitHubAPI = "https://api.github.com"
	}
	c.HTTPClientTimeout = 10 * time.Second
	return c, nil
}

func requireEnv(name string) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return v, nil
}

func splitNonEmpty(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
