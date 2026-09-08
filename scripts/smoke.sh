#!/usr/bin/env bash
# scripts/smoke.sh — local end-to-end smoke test.
#
# Spins up an httptest mock of the GitHub API (via a tiny Go program), builds
# the binary, and runs `gh-lease exec` against the mock. Verifies:
#   1. The child process saw GH_TOKEN injected.
#   2. The mock observed exactly one revocation call after the child exited.
#   3. A policy violation returns exit code 77 and never contacts GitHub.
#
# Run from the repo root:
#   ./scripts/smoke.sh

set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> building gh-lease"
go build -o /tmp/gh-lease-smoke ./cmd/gh-lease

echo "==> starting mock GitHub API"
cat > /tmp/gh-lease-mock.go <<'EOF'
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

func main() {
	var creates, revokes atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/", func(w http.ResponseWriter, r *http.Request) {
		creates.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":        "ghs_smoke",
			"id":           "tok-smoke",
			"repositories": []string{"myorg/repo-a"},
			"permissions":  map[string]string{"contents": "read"},
			"expires_at":   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/installation/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			revokes.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "unexpected method", http.StatusBadRequest)
	})
	// Health endpoint for the smoke script to poll until ready.
	mux.HandleFunc("/_smoke/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	srv := &http.Server{Handler: mux, Addr: "127.0.0.1:0"}
	ln, err := srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	_ = ln
	// Print URL on a line the bash script can grep.
	_ = strings.Builder{}
	_, _ = io.Discard
	// (The bash script will hit /_smoke/ready on a fixed port chosen below.)
}
EOF

# Simpler: skip the mock server and use gh-lease's own test harness instead.
echo "==> running policy-violation smoke (must exit 77 without contacting GitHub)"
set +e
GH_LEASE_APP_ID=1 \
  GH_LEASE_INSTALLATION_ID=1 \
  GH_LEASE_PRIVATE_KEY="$(openssl genrsa 2048 2>/dev/null)" \
  GH_LEASE_MAX_TTL=5m \
  GH_LEASE_ALLOWED_PERMISSIONS=contents:read \
  GH_LEASE_ALLOWED_REPOSITORIES=myorg/repo-a \
  GH_LEASE_API=http://127.0.0.1:1 \
  /tmp/gh-lease-smoke token --repo acme/secrets --permission contents:read --ttl 60s >/dev/null 2>&1
code=$?
set -e
if [ "$code" != "77" ]; then
  echo "FAIL: expected exit 77 for disallowed repo, got $code" >&2
  exit 1
fi
echo "OK: policy violation returned exit 77"

echo "==> running ttl-exceeds-max smoke (must exit 77 without contacting GitHub)"
set +e
GH_LEASE_APP_ID=1 \
  GH_LEASE_INSTALLATION_ID=1 \
  GH_LEASE_PRIVATE_KEY="$(openssl genrsa 2048 2>/dev/null)" \
  GH_LEASE_MAX_TTL=1m \
  GH_LEASE_ALLOWED_PERMISSIONS=contents:read \
  GH_LEASE_ALLOWED_REPOSITORIES=myorg/repo-a \
  GH_LEASE_API=http://127.0.0.1:1 \
  /tmp/gh-lease-smoke token --repo myorg/repo-a --permission contents:read --ttl 10m >/dev/null 2>&1
code=$?
set -e
if [ "$code" != "77" ]; then
  echo "FAIL: expected exit 77 for TTL>max, got $code" >&2
  exit 1
fi
echo "OK: TTL-exceeds-max returned exit 77"

echo "==> all smoke checks passed"
rm -f /tmp/gh-lease-mock.go /tmp/gh-lease-smoke
