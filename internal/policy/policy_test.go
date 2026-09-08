package policy

import (
	"errors"
	"testing"
	"time"

	"github.com/aconal-com/gh-lease/internal/config"
	"github.com/aconal-com/gh-lease/internal/lease"
)

func mustCfg(t *testing.T, override func(*config.Config)) config.Config {
	t.Helper()
	c := config.Config{
		MaxTTL:             5 * time.Minute,
		AllowedPermissions: []string{"contents:read", "contents:write", "pull_requests:write"},
		AllowedRepos:       []string{"myorg/repo-a", "myorg/repo-b"},
	}
	if override != nil {
		override(&c)
	}
	return c
}

func TestPolicy_OK(t *testing.T) {
	p, err := New(mustCfg(t, nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := lease.Request{
		Repositories: []string{"myorg/repo-a"},
		Permissions:  []lease.Permission{{Resource: "contents", Action: "read"}},
		TTL:          30 * time.Second,
	}
	if err := p.Authorize(r); err != nil {
		t.Errorf("Authorize(ok) = %v", err)
	}
}

func TestPolicy_TTL_ExceedsMax(t *testing.T) {
	p, err := New(mustCfg(t, nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := lease.Request{
		Repositories: []string{"myorg/repo-a"},
		Permissions:  []lease.Permission{{Resource: "contents", Action: "read"}},
		TTL:          10 * time.Minute,
	}
	if err := p.Authorize(r); !errors.Is(err, ErrTTLExceedsMax) {
		t.Errorf("Authorize(big TTL) = %v, want ErrTTLExceedsMax", err)
	}
}

func TestPolicy_TTL_Zero(t *testing.T) {
	p, _ := New(mustCfg(t, nil))
	r := lease.Request{
		Repositories: []string{"myorg/repo-a"},
		Permissions:  []lease.Permission{{Resource: "contents", Action: "read"}},
		TTL:          0,
	}
	if err := p.Authorize(r); !errors.Is(err, ErrZeroTTL) {
		t.Errorf("Authorize(zero TTL) = %v, want ErrZeroTTL", err)
	}
}

func TestPolicy_Repo_NotAllowed(t *testing.T) {
	p, _ := New(mustCfg(t, nil))
	r := lease.Request{
		Repositories: []string{"acme/secrets"},
		Permissions:  []lease.Permission{{Resource: "contents", Action: "read"}},
		TTL:          30 * time.Second,
	}
	if err := p.Authorize(r); !errors.Is(err, ErrRepoNotAllowed) {
		t.Errorf("Authorize(bad repo) = %v, want ErrRepoNotAllowed", err)
	}
}

func TestPolicy_Permission_NotAllowed(t *testing.T) {
	p, _ := New(mustCfg(t, nil))
	r := lease.Request{
		Repositories: []string{"myorg/repo-a"},
		Permissions:  []lease.Permission{{Resource: "administration", Action: "write"}},
		TTL:          30 * time.Second,
	}
	if err := p.Authorize(r); !errors.Is(err, ErrPermissionNotAllowed) {
		t.Errorf("Authorize(bad perm) = %v, want ErrPermissionNotAllowed", err)
	}
}

func TestPolicy_StrictEqual_Allowed(t *testing.T) {
	// contents:write is in the allow list and the request asks for exactly
	// that. Per the spec, scope can only narrow — the request must match an
	// explicitly listed permission.
	p, _ := New(mustCfg(t, func(c *config.Config) {
		c.AllowedPermissions = []string{"contents:write"}
	}))
	r := lease.Request{
		Repositories: []string{"myorg/repo-a"},
		Permissions:  []lease.Permission{{Resource: "contents", Action: "write"}},
		TTL:          30 * time.Second,
	}
	if err := p.Authorize(r); err != nil {
		t.Errorf("Authorize(exact match) = %v, want nil", err)
	}
}

func TestPolicy_DifferentAction_Denied(t *testing.T) {
	// contents:write in allow list, request asks contents:read. The actions
	// are different verbs; the allow list does not imply a wider permission.
	p, _ := New(mustCfg(t, func(c *config.Config) {
		c.AllowedPermissions = []string{"contents:write"}
	}))
	r := lease.Request{
		Repositories: []string{"myorg/repo-a"},
		Permissions:  []lease.Permission{{Resource: "contents", Action: "read"}},
		TTL:          30 * time.Second,
	}
	if err := p.Authorize(r); !errors.Is(err, ErrPermissionNotAllowed) {
		t.Errorf("Authorize(different action) = %v, want ErrPermissionNotAllowed", err)
	}
}
