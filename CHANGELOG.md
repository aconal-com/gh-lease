# Changelog

## v0.1.0 — initial release

- `token` and `exec` subcommands.
- GitHub App JWT authentication.
- Installation token creation scoped by repository and permission.
- Environment-driven policy: `GH_LEASE_MAX_TTL`, `GH_LEASE_ALLOWED_PERMISSIONS`,
  `GH_LEASE_ALLOWED_REPOSITORIES`.
- Automatic revocation on TTL expiry, child exit, and `SIGINT`/`SIGTERM`.
- Structured audit logging to stderr (credential-free).
