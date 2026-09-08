# Contributing

Thanks for your interest in `gh-lease`.

## Ground rules

- **No new dependencies without discussion.** The binary is intended to be
  trivially auditable; every added dep is an audit liability.
- **Security > features.** If a change weakens the policy enforcement or the
  revocation guarantees, it will be rejected.
- **Tests are required.** Every change to `internal/policy`, `internal/lease`,
  or the GitHub client must include or update tests.

## Development setup

```sh
git clone https://github.com/aconal-com/gh-lease
cd gh-lease
go test ./...
```

No external services are required for the test suite — it uses
`httptest.Server` to mock the GitHub API.

## Code style

- `gofmt` is law.
- Keep the public surface area minimal. `internal/` packages should stay
  internal.
- All policy changes belong in `internal/policy/policy.go` — do not embed
  scope checks anywhere else.

## Pull request checklist

- [ ] `go test ./...` is green.
- [ ] `go vet ./...` is clean.
- [ ] New flags are documented in `README.md` and `internal/cli/cli.go`'s usage.
- [ ] Audit log fields remain credential-free.
