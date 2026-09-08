//go:build unix

package cli

import "os"

// os_getenv_all returns the current process environment as a slice. Split out
// for build-tag isolation so Windows can override if needed later.
func os_getenv_all() []string { return os.Environ() }
