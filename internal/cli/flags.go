package cli

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/aconal-com/gh-lease/internal/lease"
)

// parseRequest parses the shared flag set from --repo / --permission / --ttl.
// All three are required at invocation time: defaults are aggressively safe
// (no repository, no permissions, short TTL).
func parseRequest(args []string) (lease.Request, error) {
	var r lease.Request
	r.Repositories = []string{}
	r.Permissions = []lease.Permission{}

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--repo":
			if i+1 >= len(args) {
				return r, errors.New("--repo requires a value")
			}
			r.Repositories = append(r.Repositories, args[i+1])
			i++
		case strings.HasPrefix(a, "--repo="):
			r.Repositories = append(r.Repositories, strings.TrimPrefix(a, "--repo="))
		case a == "--permission", a == "--permissions":
			if i+1 >= len(args) {
				return r, errors.New("--permission requires a value")
			}
			// Accept either a single value or a comma-separated list.
			for _, p := range strings.Split(args[i+1], ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				perm, err := lease.ParsePermission(p)
				if err != nil {
					return r, err
				}
				r.Permissions = append(r.Permissions, perm)
			}
			i++
		case strings.HasPrefix(a, "--permission="), strings.HasPrefix(a, "--permissions="):
			val := strings.SplitN(a, "=", 2)[1]
			for _, p := range strings.Split(val, ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				perm, err := lease.ParsePermission(p)
				if err != nil {
					return r, err
				}
				r.Permissions = append(r.Permissions, perm)
			}
		case a == "--ttl":
			if i+1 >= len(args) {
				return r, errors.New("--ttl requires a value")
			}
			d, err := time.ParseDuration(args[i+1])
			if err != nil {
				return r, fmt.Errorf("invalid --ttl %q: %w", args[i+1], err)
			}
			r.TTL = d
			i++
		case strings.HasPrefix(a, "--ttl="):
			d, err := time.ParseDuration(strings.TrimPrefix(a, "--ttl="))
			if err != nil {
				return r, fmt.Errorf("invalid --ttl %q: %w", a, err)
			}
			r.TTL = d
		default:
			return r, fmt.Errorf("unknown flag %q", a)
		}
	}

	if len(r.Repositories) == 0 {
		return r, errors.New("at least one --repo is required")
	}
	if len(r.Permissions) == 0 {
		return r, errors.New("at least one --permission is required")
	}
	for _, repo := range r.Repositories {
		if !validRepo(repo) {
			return r, fmt.Errorf("invalid --repo %q (expected <owner>/<name>)", repo)
		}
	}
	if r.TTL <= 0 {
		// Aggressive default; only applied when the user supplied the other
		// required flags but forgot --ttl.
		r.TTL = 60 * time.Second
	}
	return r, nil
}

func validRepo(s string) bool {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return false
	}
	if parts[0] == "" || parts[1] == "" {
		return false
	}
	// GitHub owner/name: alphanumeric + dot/dash/underscore.
	for _, p := range parts {
		for _, r := range p {
			if !(r == '.' || r == '-' || r == '_' ||
				(r >= '0' && r <= '9') ||
				(r >= 'a' && r <= 'z') ||
				(r >= 'A' && r <= 'Z')) {
				return false
			}
		}
	}
	return true
}

// runChild exec's the given command with the supplied token injected as
// GH_TOKEN in the child's environment. The rest of the environment is
// inherited from the parent. Returns the child's exit code.
func runChild(cmdArgs []string, token string, stdout, stderr interface{ Write([]byte) (int, error) }) (int, error) {
	if len(cmdArgs) == 0 {
		return 2, errors.New("empty command")
	}
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// Inherit parent env, then override GH_TOKEN. We do NOT clear the rest —
	// agents and tools legitimately need HOME, PATH, etc.
	cmd.Env = append([]string(nil), os_getenv_all()...)
	cmd.Env = append(cmd.Env, "GH_TOKEN="+token, "GITHUB_TOKEN="+token)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), err
		}
		return 1, err
	}
	return 0, nil
}
