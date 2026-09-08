// Package audit emits structured, credential-free audit records for every
// lease lifecycle event. The default writer is stderr; production
// deployments will swap in a remote sink.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/aconal-com/gh-lease/internal/lease"
)

// Event is the structured payload for an audit log line.
type Event struct {
	Timestamp    time.Time `json:"ts"`
	Event        string    `json:"event"`
	LeaseID      string    `json:"lease_id"`
	Repository   string    `json:"repository,omitempty"`
	Permission   string    `json:"permission,omitempty"`
	TTLSeconds   int       `json:"ttl_seconds,omitempty"`
	RevokeError  string    `json:"revoke_error,omitempty"`
}

// Auditor writes Events to an io.Writer with one JSON object per line.
type Auditor struct {
	w   io.Writer
	mu  sync.Mutex
}

// New constructs an Auditor that writes to w. w is typically os.Stderr.
func New(w io.Writer) *Auditor { return &Auditor{w: w} }

// Issued records that a lease was created.
func (a *Auditor) Issued(l *lease.Lease) {
	ev := Event{
		Timestamp: time.Now().UTC(),
		Event:     "lease.issued",
		LeaseID:   l.ID,
		TTLSeconds: int(l.TTL.Seconds()),
	}
	if len(l.Repositories) > 0 {
		ev.Repository = l.Repositories[0]
	}
	if len(l.Permissions) > 0 {
		ev.Permission = l.Permissions[0].String()
	}
	a.write(ev)
}

// Revoked records that a lease was revoked. err may be nil.
func (a *Auditor) Revoked(l *lease.Lease, err error) {
	ev := Event{
		Timestamp: time.Now().UTC(),
		Event:     "lease.revoked",
		LeaseID:   l.ID,
	}
	if err != nil {
		ev.RevokeError = err.Error()
	}
	a.write(ev)
}

func (a *Auditor) write(ev Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := json.Marshal(ev)
	if err != nil {
		return // never panic in audit
	}
	b = append(b, '\n')
	_, _ = a.w.Write(b)
}
