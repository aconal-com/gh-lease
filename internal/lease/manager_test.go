package lease

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aconal-com/gh-lease/internal/github"
)

type fakeClient struct {
	mu          sync.Mutex
	createCalls []github.CreateTokenRequest
	revokeCalls []string
	nextToken   github.InstallationToken
	nextErr     error
}

func (f *fakeClient) CreateInstallationToken(_ context.Context, req github.CreateTokenRequest) (github.InstallationToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls = append(f.createCalls, req)
	if f.nextErr != nil {
		return github.InstallationToken{}, f.nextErr
	}
	return f.nextToken, nil
}

func (f *fakeClient) RevokeInstallationToken(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokeCalls = append(f.revokeCalls, id)
	return nil
}

func TestRequest_Validate(t *testing.T) {
	tests := []struct {
		name string
		req  Request
		ok   bool
	}{
		{"ok", Request{Repositories: []string{"o/r"}, Permissions: []Permission{{Resource: "contents", Action: "read"}}, TTL: time.Second}, true},
		{"no repos", Request{Permissions: []Permission{{Resource: "contents", Action: "read"}}, TTL: time.Second}, false},
		{"no perms", Request{Repositories: []string{"o/r"}, TTL: time.Second}, false},
		{"zero ttl", Request{Repositories: []string{"o/r"}, Permissions: []Permission{{Resource: "contents", Action: "read"}}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.Validate()
			if tc.ok && err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
			if !tc.ok && err == nil {
				t.Errorf("Validate() = nil, want error")
			}
		})
	}
}

func TestManager_Issue_Revoke(t *testing.T) {
	fc := &fakeClient{
		nextToken: github.InstallationToken{
			ID:           "tok-1",
			Token:        "ghs_secret",
			Repositories: []string{"o/r"},
			Permissions:  map[string]string{"contents": "write"},
		},
	}
	m := NewManager(fc, nil)

	req := Request{
		Repositories: []string{"o/r"},
		Permissions:  []Permission{{Resource: "contents", Action: "write"}},
		TTL:          10 * time.Second,
	}
	l, err := m.Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if l.ID != "tok-1" || l.Token != "ghs_secret" {
		t.Errorf("Lease = %+v", l)
	}
	if len(fc.createCalls) != 1 {
		t.Fatalf("expected 1 CreateInstallationToken call, got %d", len(fc.createCalls))
	}
	if fc.createCalls[0].Permissions["contents"] != "write" {
		t.Errorf("permissions[contents] = %q, want write", fc.createCalls[0].Permissions["contents"])
	}

	if err := m.Revoke(context.Background(), "tok-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(fc.revokeCalls) != 1 || fc.revokeCalls[0] != "tok-1" {
		t.Errorf("revokeCalls = %v", fc.revokeCalls)
	}
}

func TestManager_Revoke_Idempotent(t *testing.T) {
	fc := &fakeClient{}
	m := NewManager(fc, nil)
	if err := m.Revoke(context.Background(), "unknown"); err != nil {
		t.Errorf("Revoke(unknown) = %v, want nil", err)
	}
}

func TestManager_RevokeAll(t *testing.T) {
	fc := &fakeClient{
		nextToken: github.InstallationToken{ID: "tok", Token: "x", Repositories: []string{"o/r"}, Permissions: map[string]string{"contents": "read"}},
	}
	m := NewManager(fc, nil)
	for i := 0; i < 3; i++ {
		fc.nextToken.ID = "tok-" + string(rune('a'+i))
		_, _ = m.Issue(context.Background(), Request{
			Repositories: []string{"o/r"},
			Permissions:  []Permission{{Resource: "contents", Action: "read"}},
			TTL:          1 * time.Second,
		})
	}
	if err := m.RevokeAll(context.Background()); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}
	if len(fc.revokeCalls) != 3 {
		t.Errorf("expected 3 revoke calls, got %d", len(fc.revokeCalls))
	}
}

func TestParsePermission(t *testing.T) {
	cases := map[string]struct {
		in   string
		want Permission
		err  bool
	}{
		"ok":     {"contents:read", Permission{Resource: "contents", Action: "read"}, false},
		"empty":  {"", Permission{}, true},
		"noact":  {"contents", Permission{}, true},
		"nested": {"pull_requests:write", Permission{Resource: "pull_requests", Action: "write"}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ParsePermission(tc.in)
			if tc.err {
				if err == nil {
					t.Errorf("ParsePermission(%q) = nil err, want error", tc.in)
				}
				return
			}
			if err != nil {
				t.Errorf("ParsePermission(%q): %v", tc.in, err)
				return
			}
			if got != tc.want {
				t.Errorf("ParsePermission(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

var _ = errors.New
