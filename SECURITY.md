# Security policy

If you discover a vulnerability in `gh-lease`, please report it privately so
we can patch and disclose responsibly.

## Reporting

Email: **aniketkarne@gmail.com**

Please include:

- A description of the issue and its impact.
- Reproduction steps or a proof-of-concept.
- The version/commit hash affected.

We will acknowledge receipt within 72 hours and aim to ship a fix within 30 days
for critical issues.

## Scope

In scope:

- Anything in `internal/`, `cmd/`, and the published `gh-lease` binary.
- The policy enforcement logic in `internal/policy`.
- The audit log format in `internal/audit`.

Out of scope:

- The GitHub REST API itself.
- GitHub App permissioning chosen by the operator.
- Vulnerabilities introduced by operator misconfiguration (e.g. an App with
  `administration:write` in the allow list).

## Out-of-band tokens

If you discover a leaked GitHub App installation token issued by `gh-lease`,
treat it as compromised and notify us immediately. We can correlate the lease
ID with audit logs.
