// Package lease models the lifetime and policy of a single short-lived GitHub
// credential. It is intentionally decoupled from the GitHub API client so the
// policy layer can be unit-tested without any network I/O.
package lease

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Permission is a typed "<resource>:<action>" pair, e.g. contents:write.
// GitHub installation tokens can be scoped to a known set of (resource,
// action) pairs.
type Permission struct {
	Resource string
	Action   string
}

// String returns the canonical "<resource>:<action>" form.
func (p Permission) String() string { return p.Resource + ":" + p.Action }

// ParsePermission parses "contents:write"-style strings.
func ParsePermission(s string) (Permission, error) {
	parts := strings.SplitN(strings.TrimSpace(s), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Permission{}, fmt.Errorf("invalid permission %q (expected <resource>:<action>)", s)
	}
	return Permission{Resource: parts[0], Action: parts[1]}, nil
}

// Request is the invocation-level request for a token. It is always narrower
// than (or equal to) the configured maximum policy.
type Request struct {
	Repositories []string
	Permissions  []Permission
	TTL          time.Duration
}

// Lease is the in-memory representation of an issued token.
type Lease struct {
	ID    string
	Token string
	TTL   time.Duration

	// expiresAt is set when the lease is issued and is the moment the TTL
	// timer should fire.
	expiresAt time.Time

	// Repositories and Permissions are the effective scope granted. They may
	// be a strict subset of the request (e.g. GitHub may reject a permission
	// the App does not have, in which case we record what was actually issued).
	Repositories []string
	Permissions  []Permission
}

// Expires returns a channel that closes when the TTL elapses. Useful for
// goroutines that wait for lease expiry.
func (l *Lease) Expires() <-chan time.Time {
	return time.After(time.Until(l.expiresAt))
}

// IssuedAt returns the moment the lease was created.
func (l *Lease) IssuedAt() time.Time { return l.expiresAt.Add(-l.TTL) }

// Sentinel errors for the lease package.
var (
	ErrNoRepositories = errors.New("at least one repository is required")
	ErrNoPermissions  = errors.New("at least one permission is required")
	ErrZeroTTL        = errors.New("TTL must be positive")
)
