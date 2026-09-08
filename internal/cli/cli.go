// Package cli implements the gh-lease command-line interface.
//
// The CLI exposes two primary subcommands:
//
//	gh-lease token  --repo org/repo --permission contents:read --ttl 60s
//	gh-lease exec   --repo org/repo --permission contents:write --ttl 60s -- <cmd> [args...]
//
// All policy decisions (maximum TTL, allowed repositories, allowed permissions)
// are resolved by the policy package and are fail-closed.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/aconal-com/gh-lease/internal/audit"
	"github.com/aconal-com/gh-lease/internal/config"
	"github.com/aconal-com/gh-lease/internal/github"
	"github.com/aconal-com/gh-lease/internal/lease"
	"github.com/aconal-com/gh-lease/internal/policy"
)

// ExitCodeError is returned by Run when the program should exit with a
// specific non-zero code. Wrapping an error with ExitCodeError preserves the
// message while allowing main() to set the process exit status.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string { return e.Err.Error() }
func (e *ExitCodeError) Unwrap() error { return e.Err }

// ExitCode returns the exit code for an error. Unknown errors map to 1.
func ExitCode(err error) int {
	var ec *ExitCodeError
	if errors.As(err, &ec) {
		return ec.Code
	}
	return 1
}

// Run executes the CLI with the given arguments and returns the first error
// encountered. stdout and stderr are passed in for testability.
func Run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return &ExitCodeError{Code: 2, Err: errors.New("no subcommand provided")}
	}

	// Subcommand dispatch. Top-level usage: `gh-lease <subcommand> [flags...]`.
	switch args[0] {
	case "token":
		return runToken(args[1:], stdout, stderr)
	case "exec":
		return runExec(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return &ExitCodeError{Code: 2, Err: fmt.Errorf("unknown subcommand %q", args[0])}
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `gh-lease — Ephemeral, least-privilege GitHub access leases for AI agents.

Usage:
  gh-lease token [flags]
  gh-lease exec   [flags] -- <command> [args...]

Flags (shared):
  --repo REPO            Repository scope (repeatable, required)
  --permission PERM      Permission as '<resource>:<action>' (repeatable, required)
  --ttl DURATION         Lease duration (e.g. 30s, 1m, 5m; default 60s)

Environment (required for issuance):
  GH_LEASE_APP_ID              GitHub App numeric ID
  GH_LEASE_INSTALLATION_ID     Installation ID
  GH_LEASE_PRIVATE_KEY_FILE    Path to the App's PEM private key
  GH_LEASE_MAX_TTL             Maximum allowed lease duration (e.g. 5m)
  GH_LEASE_ALLOWED_PERMISSIONS Comma-separated list (e.g. contents:read,contents:write,pull_requests:write)
  GH_LEASE_ALLOWED_REPOSITORIES Comma-separated list (e.g. myorg/repo-a,myorg/repo-b)

Run "gh-lease help" for the full documentation.`)
}

func runToken(args []string, stdout, stderr io.Writer) error {
	req, err := parseRequest(args)
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return &ExitCodeError{Code: 78, Err: err}
	}
	pol, err := policy.New(cfg)
	if err != nil {
		return &ExitCodeError{Code: 78, Err: err}
	}
	if err := pol.Authorize(req); err != nil {
		return &ExitCodeError{Code: 77, Err: err}
	}

	client := github.NewClient(cfg.GitHubAPI, github.WithHTTPClient(httpClientFrom(cfg)))
	if err := client.SetAppCredentials(cfg.AppID, cfg.InstallationID, cfg.PrivateKeyPEM); err != nil {
		return &ExitCodeError{Code: 78, Err: fmt.Errorf("configure github client: %w", err)}
	}
	manager := lease.NewManager(client, audit.New(os.Stderr))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Forward SIGINT/SIGTERM so we can revoke outstanding leases on shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
		_ = manager.RevokeAll(context.Background())
		os.Exit(130)
	}()

	l, err := manager.Issue(ctx, req)
	if err != nil {
		return &ExitCodeError{Code: 1, Err: err}
	}

	// In token mode, print the token to stdout and let the TTL countdown
	// revoke it asynchronously. The caller owns subprocess lifetime.
	fmt.Fprintln(stdout, l.Token)
	fmt.Fprintf(stderr, "expires: %s\n", l.TTL)

	go func() {
		<-l.Expires()
		_ = manager.Revoke(context.Background(), l.ID)
	}()

	// Block until the TTL fires or the process is signaled.
	<-l.Expires()
	_ = manager.Revoke(context.Background(), l.ID)
	return nil
}

func runExec(args []string, stdout, stderr io.Writer) error {
	// Split flags from command. Anything before the literal `--` is parsed as
	// request flags; everything after is the child command.
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		return &ExitCodeError{Code: 2, Err: errors.New("`exec` requires `--` followed by the command to run")}
	}
	flagArgs := args[:sep]
	cmdArgs := args[sep+1:]
	if len(cmdArgs) == 0 {
		return &ExitCodeError{Code: 2, Err: errors.New("`exec` requires a command after `--`")}
	}

	req, err := parseRequest(flagArgs)
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return &ExitCodeError{Code: 78, Err: err}
	}
	pol, err := policy.New(cfg)
	if err != nil {
		return &ExitCodeError{Code: 78, Err: err}
	}
	if err := pol.Authorize(req); err != nil {
		return &ExitCodeError{Code: 77, Err: err}
	}

	client := github.NewClient(cfg.GitHubAPI, github.WithHTTPClient(httpClientFrom(cfg)))
	if err := client.SetAppCredentials(cfg.AppID, cfg.InstallationID, cfg.PrivateKeyPEM); err != nil {
		return &ExitCodeError{Code: 78, Err: fmt.Errorf("configure github client: %w", err)}
	}
	manager := lease.NewManager(client, audit.New(os.Stderr))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
		_ = manager.RevokeAll(context.Background())
		os.Exit(130)
	}()

	l, err := manager.Issue(ctx, req)
	if err != nil {
		return &ExitCodeError{Code: 1, Err: err}
	}

	// Run the child process with GH_TOKEN injected. We use the github-actions
	// convention (GITHUB_TOKEN / GH_TOKEN) because the GitHub CLI auto-reads
	// either, and so do most gh-aware tools.
	exitCode, runErr := runChild(cmdArgs, l.Token, stdout, stderr)

	// Revoke before returning — even if the child crashed.
	if err := manager.Revoke(context.Background(), l.ID); err != nil {
		fmt.Fprintf(stderr, "warning: token revocation failed: %v\n", err)
	}
	if runErr != nil {
		return &ExitCodeError{Code: exitCode, Err: runErr}
	}
	return nil
}
