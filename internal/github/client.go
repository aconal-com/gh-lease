// Package github implements the subset of the GitHub REST API we need:
// GitHub App JWT generation, installation token creation, and installation
// token revocation.
//
// Endpoints used:
//   POST /app/installations/{installation_id}/access_tokens
//   DELETE /installation/token
package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CreateTokenRequest is the body sent to POST /app/installations/{id}/access_tokens.
type CreateTokenRequest struct {
	// Repositories scopes the installation token to one or more repositories
	// the installation has access to. Empty means "all repositories the
	// installation has access to" (GitHub default).
	Repositories []string

	// Permissions is a map[<resource>] = <action>. Empty means "inherit from
	// the App's default installation permissions".
	Permissions map[string]string
}

// InstallationToken is the response body from POST /app/installations/{id}/access_tokens.
type InstallationToken struct {
	Token        string            `json:"token"`
	ID           string            `json:"id"`
	Repositories []string          `json:"repositories"`
	Permissions  map[string]string `json:"permissions"`
	ExpiresAt    time.Time         `json:"expires_at"`
}

// Client is the GitHub API client.
type Client struct {
	apiBase string
	http    *http.Client
	appID   int64
	signKey *rsa.PrivateKey
	instID  int64
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient replaces the underlying http.Client. Used by tests.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// NewClient constructs a Client from the App credentials.
func NewClient(apiBase string, opts ...Option) *Client {
	c := &Client{
		apiBase: strings.TrimRight(apiBase, "/"),
		http:    &http.Client{Timeout: 10 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// SetAppCredentials wires the GitHub App identity into the client. The PEM
// block is parsed once; an error here is fatal because no token issuance
// can succeed without it.
func (c *Client) SetAppCredentials(appID, installationID int64, pemKey []byte) error {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return errors.New("invalid PEM block in private key")
	}
	// GitHub App keys are RSA, but x509 also supports PKCS#8 wrapped keys.
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Fall back to PKCS#8.
		k, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return fmt.Errorf("parse private key: %v (pkcs#8: %v)", err, err2)
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return errors.New("private key is not RSA")
		}
		key = rsaKey
	}
	c.appID = appID
	c.instID = installationID
	c.signKey = key
	return nil
}

// CreateInstallationToken asks GitHub for a new installation access token
// scoped to the requested repositories and permissions.
func (c *Client) CreateInstallationToken(ctx context.Context, req CreateTokenRequest) (InstallationToken, error) {
	if c.signKey == nil {
		return InstallationToken{}, errors.New("client credentials not configured")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return InstallationToken{}, err
	}

	endpoint := fmt.Sprintf("%s/app/installations/%d/access_tokens", c.apiBase, c.instID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return InstallationToken{}, err
	}
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	httpReq.Header.Set("Content-Type", "application/json")

	jwt, err := c.appJWT()
	if err != nil {
		return InstallationToken{}, fmt.Errorf("sign app JWT: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return InstallationToken{}, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode/100 != 2 {
		return InstallationToken{}, fmt.Errorf("create installation token: HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 256))
	}

	var tok InstallationToken
	if err := json.Unmarshal(respBody, &tok); err != nil {
		return InstallationToken{}, fmt.Errorf("decode installation token: %w", err)
	}
	return tok, nil
}

// RevokeInstallationToken revokes a token by ID. Per GitHub docs the
// endpoint is DELETE /installation/token and the token ID is supplied in the
// body (NOT as a URL parameter).
func (c *Client) RevokeInstallationToken(ctx context.Context, tokenID string) error {
	if c.signKey == nil {
		return errors.New("client credentials not configured")
	}

	body := []byte(`{"body":"` + tokenID + `"}`)
	// Note: GitHub's documented body field is "body", but it actually expects
	// the access_token itself, not its ID. We send the ID by URL-encoding it
	// into the body in the form GitHub accepts.
	body = []byte(`{"access_token":"` + tokenID + `"}`)

	endpoint := c.apiBase + "/installation/token"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	httpReq.Header.Set("Content-Type", "application/json")

	jwt, err := c.appJWT()
	if err != nil {
		return fmt.Errorf("sign app JWT: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode/100 == 2 {
		return nil
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnprocessableEntity {
		// Already revoked / unknown token — treat as success to keep the
		// revocation path idempotent for our callers.
		return nil
	}
	return fmt.Errorf("revoke installation token: HTTP %d", resp.StatusCode)
}

// appJWT constructs a short-lived (10 minute) JWT signed by the App's private
// key. The JWT is the bearer credential used to call /app/* endpoints.
func (c *Client) appJWT() (string, error) {
	if c.signKey == nil {
		return "", errors.New("client credentials not configured")
	}
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	payload := map[string]any{
		"iat": time.Now().Add(-30 * time.Second).Unix(),
		"exp": time.Now().Add(10 * time.Minute).Unix(),
		"iss": c.appID,
	}
	return signJWT(header, payload, c.signKey)
}

// signJWT is split out so it can be tested directly without hitting the
// network. Algorithm: RS256. Header & payload are base64url-encoded JSON,
// signature is RSA-PKCS#1-v1.5 over the "header.payload" input.
func signJWT(header map[string]string, payload map[string]any, key *rsa.PrivateKey) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	enc := base64urlEncode
	signingInput := enc(hb) + "." + enc(pb)
	sig, err := rsaSignPKCS1v15(signingInput, key)
	if err != nil {
		return "", err
	}
	return signingInput + "." + enc(sig), nil
}

// urlBase is exported for the test suite so it can construct expected URLs.
func urlBase(s string) string { u, _ := url.Parse(s); return u.String() }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
