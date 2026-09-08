package lease

import (
	"context"
	"testing"
	"time"

	"github.com/aconal-com/gh-lease/internal/github"
)

// BenchmarkIssue measures the cost of Issue() against a fake client. The
// real production cost is dominated by the GitHub App JWT signing and the
// network round-trip; this benchmark isolates the local bookkeeping.
func BenchmarkIssue(b *testing.B) {
	fc := &fakeClient{
		nextToken: github.InstallationToken{
			ID:           "tok-1",
			Token:        "ghs_x",
			Repositories: []string{"o/r"},
			Permissions:  map[string]string{"contents": "write"},
		},
	}
	m := NewManager(fc, nil)
	req := Request{
		Repositories: []string{"o/r"},
		Permissions:  []Permission{{Resource: "contents", Action: "write"}},
		TTL:          60 * time.Second,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := m.Issue(context.Background(), req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRevoke_Idle measures Revoke() for an unknown lease id — the path
// taken when an exec child exits and the manager sweeps outstanding leases.
func BenchmarkRevoke_Idle(b *testing.B) {
	fc := &fakeClient{}
	m := NewManager(fc, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Revoke(context.Background(), "nonexistent")
	}
}
