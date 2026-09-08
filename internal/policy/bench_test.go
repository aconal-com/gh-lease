package policy

import (
	"testing"
	"time"

	"github.com/aconal-com/gh-lease/internal/config"
	"github.com/aconal-com/gh-lease/internal/lease"
)

func BenchmarkAuthorize_Allowed(b *testing.B) {
	cfg := config.Config{
		MaxTTL:             5 * time.Minute,
		AllowedPermissions: []string{"contents:read", "contents:write", "pull_requests:write"},
		AllowedRepos:       []string{"myorg/repo-a", "myorg/repo-b"},
	}
	p, _ := New(cfg)
	r := lease.Request{
		Repositories: []string{"myorg/repo-a"},
		Permissions:  []lease.Permission{{Resource: "contents", Action: "read"}},
		TTL:          30 * time.Second,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := p.Authorize(r); err != nil {
			b.Fatal(err)
		}
	}
}
