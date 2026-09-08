# gh-lease

> **Ephemeral, least-privilege GitHub access leases for AI agents.**

One agent. One repository. Minimum permissions. Seconds of access. Automatically revoked.

`gh-lease` issues a [GitHub App installation token][github-app-tokens] scoped to the
repositories and permissions an agent actually needs, for only as long as it needs them,
and then **revokes** it. The GitHub App's private key never leaves the host that runs
`gh-lease`.

[github-app-tokens]: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation

---

## Why

AI agents and automation that hold long-lived GitHub tokens are a security incident
waiting to happen. A leaked PAT or a misbehaving agent can push to any repo the token
can reach, for as long as the token lives.

`gh-lease` flips the model:

- The token the agent receives is a **normal installation token** that GitHub limits
  to ~1 hour. We then **revoke it** at the end of the requested TTL.
- The token is **scoped** to specific repositories and permissions. The agent cannot
  ask for more than the operator allows.
- The token is **injected** into a child process by `gh-lease exec`, so the agent
  itself never needs to write it to disk.

```text
                 ┌─────────────────┐
                 │ GitHub App       │
                 │ Private Key      │
                 └────────┬────────┘
                          │  (never leaves host)
                          ▼
┌──────────────┐    ┌───────────────┐
│ AI Agent     │───▶│ gh-lease       │
└──────────────┘    │ credential     │
                    │ broker         │
                    └───────┬───────┘
                            ▼
                    GitHub installation
                       access token
                       (revoked after TTL)
```

---

## Quick start

### 1. Configure a GitHub App

Create a [GitHub App][github-app-create] with at least the permissions you intend
to delegate. Note its **App ID**, the **installation ID** for the target org, and
download the **private key** (`.pem`).

[github-app-create]: https://docs.github.com/en/apps/creating-github-apps/setting-up-a-github-app

### 2. Set the environment

```sh
export GH_LEASE_APP_ID=123456
export GH_LEASE_INSTALLATION_ID=12345678
export GH_LEASE_PRIVATE_KEY_FILE=/etc/gh-lease/app.pem

# Aggressive safety defaults — every limit is operator-controlled.
export GH_LEASE_MAX_TTL=5m
export GH_LEASE_ALLOWED_PERMISSIONS=contents:read,contents:write,pull_requests:write
export GH_LEASE_ALLOWED_REPOSITORIES=myorg/repo-a,myorg/repo-b
```

### 3. Run a command with a 60-second lease

```sh
gh-lease exec \
  --repo myorg/repo-a \
  --permission contents:write \
  --ttl 60s \
  -- git push origin main
```

That is the entire workflow. The token exists for ~60 seconds, then GitHub rejects it.

---

## Installation

```sh
go install github.com/aconal-com/gh-lease/cmd/gh-lease@latest
```

Or build from source:

```sh
git clone https://github.com/aconal-com/gh-lease
cd gh-lease
go build -o gh-lease ./cmd/gh-lease
```

---

## Commands

### `gh-lease token`

Print a scoped token to stdout. The TTL countdown begins immediately; the token is
revoked when the TTL elapses or the process is signaled.

```sh
gh-lease token \
  --repo myorg/repo-a \
  --permission contents:read \
  --ttl 60s
```

Output:

```text
ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxx

expires: 1m0s
```

### `gh-lease exec`  *(preferred)*

Run a child process with a scoped token injected as `GH_TOKEN` and `GITHUB_TOKEN`.
The token is revoked as soon as the child exits — even if the child crashes.

```sh
gh-lease exec \
  --repo myorg/repo-a \
  --permission contents:read \
  --permission pull_requests:write \
  --ttl 5m \
  -- make release
```

---

## Security model

### Policy precedence

Every lease request is narrowed against four layers. Scope can only get narrower
as it moves down. Never broader.

```
GitHub App permissions
        ↓
Global max policy (env vars)
        ↓
Repository policy (env vars)
        ↓
Invocation request (CLI flags)
        ↓
Effective permission (issued token)
```

### What is checked at the CLI

| Check | Example failure |
|---|---|
| `requested TTL ≤ GH_LEASE_MAX_TTL` | `ERROR: requested TTL 600s exceeds maximum TTL 300s.` |
| `requested repo ∈ GH_LEASE_ALLOWED_REPOSITORIES` | `ERROR: repository "acme/secrets" is not allowed.` |
| `requested permission ∈ GH_LEASE_ALLOWED_PERMISSIONS` | `ERROR: requested permission "administration:write" exceeds configured maximum.` |
| `repo matches "<owner>/<name>"` | `ERROR: invalid --repo "bad name".` |

If any check fails, the process exits non-zero **without** contacting GitHub.

### Effective lifetime

```
effective = min(
  requested TTL,
  GH_LEASE_MAX_TTL,
  GitHub's native installation-token lifetime  # ~1 hour
)
```

### Hard guarantees (v0.1)

- ✅ GitHub App private key is loaded once at startup and never logged or persisted.
- ✅ Installation tokens are never written to disk by `gh-lease`.
- ✅ Audit logs (stderr) contain lease IDs and TTLs — **never** the token value.
- ✅ `exec` mode revokes the token before returning, even on non-zero child exit.
- ✅ `SIGINT`/`SIGTERM` triggers immediate revocation of every outstanding lease.
- ✅ All policy violations fail closed with a distinct exit code.

### What `gh-lease` is **not**

- ❌ A replacement for proper GitHub App permissioning. The App itself must be
  scoped; `gh-lease` only enforces what the App permits.
- ❌ A vault for secrets. The agent must not write the token to disk in `token`
  mode — use `exec` mode instead.
- ❌ A network proxy. `gh-lease` does not intercept or audit child traffic.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Runtime error (GitHub API failure, etc.) |
| 2 | Usage error (bad flags, missing subcommand) |
| 77 | Policy violation (repo/permission/TTL rejected) |
| 78 | Configuration error (missing or invalid env) |

---

## Benchmarks

All measurements taken on an Apple M4 (arm64), Go 1.27.1, against an
`httptest`-mocked GitHub API. Reproduce with:

```sh
go test -bench=. -benchmem -run=^$ ./...
```

```
BenchmarkIssue-10                 5125294    234.2 ns/op    641 B/op    4 allocs/op
BenchmarkAuthorize_Allowed-10    60240177     19.28 ns/op      0 B/op    0 allocs/op
BenchmarkRevoke_Idle-10         299560209      3.99 ns/op      0 B/op    0 allocs/op
```

What this measures, and what it does not:

- `BenchmarkIssue` is **local bookkeeping** (validation + fake response). The
  real production cost is dominated by RSA-signed JWT generation for the
  GitHub App authentication header and the network round-trip to
  `api.github.com`. Plan on tens of milliseconds end-to-end in production.
- `BenchmarkAuthorize_Allowed` and `BenchmarkRevoke_Idle` are pure CPU.

> Timings depend on the host CPU and the latency to `api.github.com`. Treat
> the numbers above as a sanity floor for the local code, not a contract for
> end-to-end latency.

---

## Limitations

- **Single installation per process.** v0.1 assumes one GitHub App + one
  installation. Multi-installation support is planned for v0.2.
- **No persistent configuration file.** All config is read from environment
  variables. A YAML config file is planned for v0.2.
- **No JSON output.** v0.1 prints human-readable lines. Machine-readable JSON
  output is planned for v0.2.
- **No MCP / HTTP server.** v0.1 is CLI-only. An agent-callable server is
  planned for v0.2.
- **Token TTL cannot extend GitHub's native lifetime.** GitHub installation
  tokens expire after ~1 hour. We can only shorten that window.
- **`token` mode prints the token to stdout.** Anything that captures process
  output (CI logs, shell history, etc.) will record the token. Prefer
  `exec` mode for automated workloads.

---

## Development

```sh
go test ./...              # full unit + integration suite (no network)
go vet ./...               # static checks
go build ./...             # compile
```

The integration tests spin up an `httptest.Server` that mimics the GitHub
endpoints, so no real network or credentials are required.

---

## License

MIT — see [LICENSE](./LICENSE).
