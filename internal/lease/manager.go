package lease

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aconal-com/gh-lease/internal/github"
)

// Client is the subset of the GitHub API used by the lease manager. Defined
// here (rather than imported in tests) so we can substitute a fake.
type Client interface {
	CreateInstallationToken(ctx context.Context, req github.CreateTokenRequest) (github.InstallationToken, error)
	RevokeInstallationToken(ctx context.Context, tokenID string) error
}

// Manager owns outstanding leases and the revocation logic.
type Manager struct {
	client Client
	audit  Auditor

	mu     sync.Mutex
	leases map[string]*Lease
}

// Auditor is satisfied by the audit package. Kept as an interface so the
// manager can be tested in isolation.
type Auditor interface {
	Issued(l *Lease)
	Revoked(l *Lease, err error)
}

// NewManager constructs a Manager. The audit parameter may be nil for tests.
func NewManager(c Client, a Auditor) *Manager {
	if a == nil {
		a = noopAuditor{}
	}
	return &Manager{
		client: c,
		audit:  a,
		leases: map[string]*Lease{},
	}
}

// Issue creates a new lease after validating the request and asking GitHub
// for an installation token scoped to the requested repositories and
// permissions.
func (m *Manager) Issue(ctx context.Context, req Request) (*Lease, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if req.TTL <= 0 {
		return nil, ErrZeroTTL
	}

	ghReq := github.CreateTokenRequest{
		Repositories: req.Repositories,
		Permissions:  toGitHubPermissions(req.Permissions),
	}
	tok, err := m.client.CreateInstallationToken(ctx, ghReq)
	if err != nil {
		return nil, fmt.Errorf("create installation token: %w", err)
	}

	now := timeNow()
	l := &Lease{
		ID:           tok.ID,
		Token:        tok.Token,
		TTL:          req.TTL,
		expiresAt:    now.Add(req.TTL),
		Repositories: tok.Repositories,
		Permissions:  fromGitHubPermissions(tok.Permissions),
	}
	m.mu.Lock()
	m.leases[l.ID] = l
	m.mu.Unlock()
	m.audit.Issued(l)
	return l, nil
}

// Revoke revokes a single lease. Idempotent: revoking an already-revoked
// lease returns nil.
func (m *Manager) Revoke(ctx context.Context, id string) error {
	m.mu.Lock()
	l, ok := m.leases[id]
	if !ok {
		m.mu.Unlock()
		return nil
	}
	delete(m.leases, id)
	m.mu.Unlock()

	if err := m.client.RevokeInstallationToken(ctx, id); err != nil {
		m.audit.Revoked(l, err)
		return err
	}
	m.audit.Revoked(l, nil)
	return nil
}

// RevokeAll revokes every outstanding lease. Returns the first error.
func (m *Manager) RevokeAll(ctx context.Context) error {
	m.mu.Lock()
	ids := make([]string, 0, len(m.leases))
	for id := range m.leases {
		ids = append(ids, id)
	}
	m.mu.Unlock()

	var firstErr error
	for _, id := range ids {
		if err := m.Revoke(ctx, id); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Validate enforces required fields on a Request.
func (r Request) Validate() error {
	if len(r.Repositories) == 0 {
		return ErrNoRepositories
	}
	if len(r.Permissions) == 0 {
		return ErrNoPermissions
	}
	if r.TTL <= 0 {
		return ErrZeroTTL
	}
	return nil
}

// GitHub's API represents permissions as a map[<resource>] = <action>. We
// convert to and from the typed Permission slice so the rest of the codebase
// doesn't have to think about it.
func toGitHubPermissions(perms []Permission) map[string]string {
	out := map[string]string{}
	for _, p := range perms {
		out[p.Resource] = p.Action
	}
	return out
}

func fromGitHubPermissions(m map[string]string) []Permission {
	out := make([]Permission, 0, len(m))
	for r, a := range m {
		out = append(out, Permission{Resource: r, Action: a})
	}
	return out
}

type noopAuditor struct{}

func (noopAuditor) Issued(*Lease)                   {}
func (noopAuditor) Revoked(*Lease, error)           {}

// timeNow is a var so tests can stub the clock. Default is time.Now.
var timeNow = func() time.Time { return time.Now() }

// Ensure imports compile when test files are excluded.
var _ = errors.New
