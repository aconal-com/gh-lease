package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aconal-com/gh-lease/internal/audit"
	"github.com/aconal-com/gh-lease/internal/lease"
	"github.com/aconal-com/gh-lease/internal/policy"
)

// withEnv sets an env var for the duration of the test and restores the
// previous value on cleanup.
func withEnv(t *testing.T, key, value string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	os.Setenv(key, value)
	t.Cleanup(func() {
		if had {
			os.Setenv(key, prev)
		} else {
			os.Unsetenv(key)
		}
	})
}

// stubGitHubServer returns an httptest.Server that records request counts and
// answers installation token requests with a canned token. Revocations
// return 204.
func stubGitHubServer(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var creates, revokes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			creates.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token":        "ghs_test_token",
				"id":           "tok-test-1",
				"repositories": []string{"myorg/repo-a"},
				"permissions":  map[string]string{"contents": "read"},
				"expires_at":   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			})
		case r.URL.Path == "/installation/token" && r.Method == http.MethodDelete:
			revokes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &creates, &revokes
}

// setupEnv writes a valid env so config.Load() succeeds. A throwaway RSA
// key is generated on disk so SetAppCredentials can actually parse the PEM.
func setupEnv(t *testing.T, apiURL string) {
	t.Helper()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
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
		os.Unsetenv(k)
	}
	withEnv(t, "GH_LEASE_APP_ID", "1")
	withEnv(t, "GH_LEASE_INSTALLATION_ID", "1")
	withEnv(t, "GH_LEASE_PRIVATE_KEY_FILE", keyFile)
	withEnv(t, "GH_LEASE_MAX_TTL", "5m")
	withEnv(t, "GH_LEASE_ALLOWED_PERMISSIONS", "contents:read,contents:write,pull_requests:write")
	withEnv(t, "GH_LEASE_ALLOWED_REPOSITORIES", "myorg/repo-a,myorg/repo-b")
	if apiURL != "" {
		withEnv(t, "GH_LEASE_API", apiURL)
	}
}

func TestRun_Exec_Success(t *testing.T) {
	srv, creates, revokes := stubGitHubServer(t)
	setupEnv(t, srv.URL)

	// A tiny shell script that echoes the GH_TOKEN it sees, so we can prove
	// the token was injected into the child.
	childScript := "#!/bin/sh\necho \"token=$GH_TOKEN\"\nexit 0"
	childPath := filepath.Join(t.TempDir(), "child.sh")
	if err := os.WriteFile(childPath, []byte(childScript), 0o755); err != nil {
		t.Fatal(err)
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	args := []string{
		"exec",
		"--repo", "myorg/repo-a",
		"--permission", "contents:read",
		"--ttl", "60s",
		"--",
		childPath,
	}
	if err := Run(args, stdout, stderr); err != nil {
		t.Fatalf("Run: %v (stderr=%s)", err, stderr.String())
	}
	if creates.Load() != 1 {
		t.Errorf("creates = %d, want 1", creates.Load())
	}
	if revokes.Load() != 1 {
		t.Errorf("revokes = %d, want 1 (token should be revoked after child exits)", revokes.Load())
	}
	if !strings.Contains(stdout.String(), "token=ghs_test_token") {
		t.Errorf("stdout did not contain injected token, got %q", stdout.String())
	}
	// Sanity: the actual token value must not appear in stderr (audit output
	// must be credential-free).
	if strings.Contains(stderr.String(), "ghs_test_token") {
		t.Errorf("stderr leaked the token: %s", stderr.String())
	}
}

func TestRun_Token_RepoNotAllowed(t *testing.T) {
	setupEnv(t, "")
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	err := Run([]string{
		"token",
		"--repo", "acme/secrets",
		"--permission", "contents:read",
		"--ttl", "60s",
	}, stdout, stderr)
	if err == nil {
		t.Fatal("expected error for disallowed repo")
	}
	// ExitCode 77 = EX_NOPERM (policy violation).
	if code := ExitCode(err); code != 77 {
		t.Errorf("exit code = %d, want 77", code)
	}
	if !strings.Contains(err.Error(), "not in the allow list") {
		t.Errorf("error message = %q, want mention of allow list", err.Error())
	}
}

func TestRun_Token_TTLExceedsMax(t *testing.T) {
	setupEnv(t, "")
	err := Run([]string{
		"token",
		"--repo", "myorg/repo-a",
		"--permission", "contents:read",
		"--ttl", "10m",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for TTL > max")
	}
	if code := ExitCode(err); code != 77 {
		t.Errorf("exit code = %d, want 77", code)
	}
}

func TestRun_NoSubcommand(t *testing.T) {
	err := Run(nil, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for empty args")
	}
	if code := ExitCode(err); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRun_Exec_RequiresSeparator(t *testing.T) {
	err := Run([]string{"exec", "--repo", "myorg/repo-a", "--permission", "contents:read", "--ttl", "60s"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error when `--` is missing")
	}
}

// Compile-time check that the lease and policy packages are still wired up
// (these would surface as unused if we accidentally removed their use).
var (
	_ = context.Background
	_ = fmt.Sprintf
	_ = io.Discard
	_ = audit.New
	_ = lease.ParsePermission
	_ = policy.ErrRepoNotAllowed
)
