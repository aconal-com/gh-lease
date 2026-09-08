package config

import (
	"os"
	"testing"
	"time"
)

// writeValidEnv writes a complete, valid environment into the process env,
// then returns a cleanup func the caller defers.
func writeValidEnv(t *testing.T) func() {
	t.Helper()
	prev := map[string]string{}
	keys := []string{
		"GH_LEASE_APP_ID",
		"GH_LEASE_INSTALLATION_ID",
		"GH_LEASE_PRIVATE_KEY_FILE",
		"GH_LEASE_PRIVATE_KEY",
		"GH_LEASE_MAX_TTL",
		"GH_LEASE_DEFAULT_TTL",
		"GH_LEASE_ALLOWED_PERMISSIONS",
		"GH_LEASE_ALLOWED_REPOSITORIES",
		"GH_LEASE_API",
	}
	for _, k := range keys {
		prev[k] = os.Getenv(k)
		os.Unsetenv(k)
	}
	os.Setenv("GH_LEASE_APP_ID", "123456")
	os.Setenv("GH_LEASE_INSTALLATION_ID", "12345678")
	os.Setenv("GH_LEASE_PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----\nstub\n-----END RSA PRIVATE KEY-----")
	os.Setenv("GH_LEASE_MAX_TTL", "5m")
	os.Setenv("GH_LEASE_ALLOWED_PERMISSIONS", "contents:read,contents:write,pull_requests:write")
	os.Setenv("GH_LEASE_ALLOWED_REPOSITORIES", "myorg/repo-a,myorg/repo-b")

	return func() {
		for k, v := range prev {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}
}

func TestLoad_OK(t *testing.T) {
	defer writeValidEnv(t)()

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AppID != 123456 {
		t.Errorf("AppID = %d, want 123456", c.AppID)
	}
	if c.InstallationID != 12345678 {
		t.Errorf("InstallationID = %d, want 12345678", c.InstallationID)
	}
	if c.MaxTTL != 5*time.Minute {
		t.Errorf("MaxTTL = %s, want 5m", c.MaxTTL)
	}
	if c.DefaultTTL != 60*time.Second {
		t.Errorf("DefaultTTL = %s, want 60s", c.DefaultTTL)
	}
	if len(c.AllowedPermissions) != 3 {
		t.Errorf("AllowedPermissions len = %d, want 3", len(c.AllowedPermissions))
	}
	if len(c.AllowedRepos) != 2 {
		t.Errorf("AllowedRepos len = %d, want 2", len(c.AllowedRepos))
	}
	if c.GitHubAPI != "https://api.github.com" {
		t.Errorf("GitHubAPI = %q", c.GitHubAPI)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	// Wipe everything and try to load.
	for _, k := range []string{
		"GH_LEASE_APP_ID",
		"GH_LEASE_INSTALLATION_ID",
		"GH_LEASE_PRIVATE_KEY_FILE",
		"GH_LEASE_PRIVATE_KEY",
		"GH_LEASE_MAX_TTL",
		"GH_LEASE_ALLOWED_PERMISSIONS",
		"GH_LEASE_ALLOWED_REPOSITORIES",
	} {
		os.Unsetenv(k)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected error when required env vars missing")
	}
}

func TestLoad_DefaultTTL_Override(t *testing.T) {
	defer writeValidEnv(t)()
	os.Setenv("GH_LEASE_DEFAULT_TTL", "30s")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.DefaultTTL != 30*time.Second {
		t.Errorf("DefaultTTL = %s, want 30s", c.DefaultTTL)
	}
}

func TestLoad_InvalidMaxTTL(t *testing.T) {
	defer writeValidEnv(t)()
	os.Setenv("GH_LEASE_MAX_TTL", "not-a-duration")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for invalid GH_LEASE_MAX_TTL")
	}
}

func TestLoad_PreferFileOverInline(t *testing.T) {
	defer writeValidEnv(t)()
	tmp := t.TempDir()
	keyPath := tmp + "/key.pem"
	if err := os.WriteFile(keyPath, []byte("file-key-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Setenv("GH_LEASE_PRIVATE_KEY_FILE", keyPath)
	os.Setenv("GH_LEASE_PRIVATE_KEY", "inline-key")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(c.PrivateKeyPEM) != "file-key-bytes" {
		t.Errorf("PrivateKeyPEM = %q, want file contents", string(c.PrivateKeyPEM))
	}
}
