package cli

import (
	"net/http"
	"time"

	"github.com/aconal-com/gh-lease/internal/config"
)

// httpClientFrom returns an *http.Client whose timeout matches the configured
// policy. Kept as a tiny adapter so the cli package doesn't have to import
// the whole config struct just to read one field.
func httpClientFrom(cfg config.Config) *http.Client {
	t := cfg.HTTPClientTimeout
	if t <= 0 {
		t = 10 * time.Second
	}
	return &http.Client{Timeout: t}
}
