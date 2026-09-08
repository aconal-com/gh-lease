package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestKey generates a throwaway RSA private key for tests.
func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

func TestAppJWT_IsValidShape(t *testing.T) {
	key := newTestKey(t)
	c := &Client{appID: 12345, signKey: key}
	tok, err := c.appJWT()
	if err != nil {
		t.Fatalf("appJWT: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3", len(parts))
	}
	// Decode the payload and confirm iss + exp are sensible.
	payload, err := base64Decode(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var p struct {
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
		Iss int64 `json:"iss"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if p.Iss != 12345 {
		t.Errorf("iss = %d, want 12345", p.Iss)
	}
	if p.Exp <= time.Now().Unix() {
		t.Errorf("exp = %d, want in the future", p.Exp)
	}
	if p.Exp-p.Iat > 11*60 {
		t.Errorf("JWT lifetime = %ds, want <= 11 min", p.Exp-p.Iat)
	}
}

func TestCreateInstallationToken_Success(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if !strings.HasSuffix(r.URL.Path, "/access_tokens") {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusBadRequest)
			return
		}
		// Confirm Authorization header carries a JWT.
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing bearer", http.StatusBadRequest)
			return
		}
		// Echo back a minimal installation token.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":        "ghs_abc",
			"id":           "tok-1",
			"repositories": []string{"o/r"},
			"permissions":  map[string]string{"contents": "write"},
			"expires_at":   time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	if err := c.SetAppCredentials(1, 99, mustPEM(t, newTestKey(t))); err != nil {
		t.Fatal(err)
	}

	tok, err := c.CreateInstallationToken(context.Background(), CreateTokenRequest{
		Repositories: []string{"o/r"},
		Permissions:  map[string]string{"contents": "write"},
	})
	if err != nil {
		t.Fatalf("CreateInstallationToken: %v", err)
	}
	if tok.Token != "ghs_abc" {
		t.Errorf("Token = %q", tok.Token)
	}
	if tok.Permissions["contents"] != "write" {
		t.Errorf("permissions[contents] = %q", tok.Permissions["contents"])
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", hits.Load())
	}
}

func TestCreateInstallationToken_GitHubError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"forbidden"}`, http.StatusForbidden)
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	if err := c.SetAppCredentials(1, 99, mustPEM(t, newTestKey(t))); err != nil {
		t.Fatal(err)
	}
	_, err := c.CreateInstallationToken(context.Background(), CreateTokenRequest{})
	if err == nil {
		t.Fatal("expected error on 403")
	}
	if !strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("error %q does not mention HTTP 403", err.Error())
	}
}

func TestRevokeInstallationToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "expected DELETE", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"access_token":"tok-1"`) {
			http.Error(w, "missing access_token", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	if err := c.SetAppCredentials(1, 99, mustPEM(t, newTestKey(t))); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeInstallationToken(context.Background(), "tok-1"); err != nil {
		t.Errorf("Revoke: %v", err)
	}
}

func TestRevokeInstallationToken_AlreadyGone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	if err := c.SetAppCredentials(1, 99, mustPEM(t, newTestKey(t))); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeInstallationToken(context.Background(), "tok-gone"); err != nil {
		t.Errorf("expected nil error for already-revoked, got %v", err)
	}
}

// base64Decode wraps base64.RawURLEncoding to keep tests readable.
func base64Decode(s string) ([]byte, error) {
	return base64RawURLDecode(s)
}

// mustPEM serializes an RSA private key in PKCS#1 PEM form for SetAppCredentials.
func mustPEM(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	pemBytes := pemEncodeRSAPrivateKey(k)
	return pemBytes
}
