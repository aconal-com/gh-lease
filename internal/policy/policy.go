// Package policy implements the gh-lease security policy engine. Every lease
// request is narrowed against a configured maximum:
//
//	GitHub App permissions
//	  ↓
//	Global max policy
//	  ↓
//	Repository policy
//	  ↓
//	Invocation request
//	  ↓
//	Effective permission
//
// The effective scope can only become narrower as it moves down the chain.
// Never broader.
package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aconal-com/gh-lease/internal/config"
	"github.com/aconal-com/gh-lease/internal/lease"
)

// Policy is the resolved authorization policy. Constructed once at process
// start from configuration; queries are read-only.
type Policy struct {
	maxTTL             time.Duration
	allowedRepos       map[string]struct{}
	allowedPermissions map[string]struct{}
}

// New constructs a Policy from a validated config.Config.
func New(cfg config.Config) (*Policy, error) {
	p := &Policy{
		maxTTL:             cfg.MaxTTL,
		allowedRepos:       map[string]struct{}{},
		allowedPermissions: map[string]struct{}{},
	}
	for _, r := range cfg.AllowedRepos {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		p.allowedRepos[r] = struct{}{}
	}
	for _, perm := range cfg.AllowedPermissions {
		perm = strings.TrimSpace(perm)
		if perm == "" {
			continue
		}
		p.allowedPermissions[perm] = struct{}{}
	}
	return p, nil
}

// Errors returned by Authorize. Each is a stable, distinguishable value so
// callers can match with errors.Is.
var (
	ErrTTLExceedsMax        = errors.New("requested TTL exceeds configured maximum")
	ErrRepoNotAllowed       = errors.New("requested repository is not in the allow list")
	ErrPermissionNotAllowed = errors.New("requested permission is not in the allow list")
	ErrZeroTTL              = errors.New("TTL must be positive")
)

// Authorize narrows a Request against the policy. Returns nil on success,
// otherwise an error describing the first policy violation.
func (p *Policy) Authorize(r lease.Request) error {
	if r.TTL <= 0 {
		return ErrZeroTTL
	}
	if r.TTL > p.maxTTL {
		return fmt.Errorf("%w: requested %s, maximum %s", ErrTTLExceedsMax, r.TTL, p.maxTTL)
	}
	for _, repo := range r.Repositories {
		if _, ok := p.allowedRepos[repo]; !ok {
			return fmt.Errorf("%w: %q", ErrRepoNotAllowed, repo)
		}
	}
	for _, perm := range r.Permissions {
		if _, ok := p.allowedPermissions[perm.String()]; !ok {
			return fmt.Errorf("%w: %q", ErrPermissionNotAllowed, perm.String())
		}
	}
	return nil
}

// MaxTTL returns the configured maximum TTL.
func (p *Policy) MaxTTL() time.Duration { return p.maxTTL }
