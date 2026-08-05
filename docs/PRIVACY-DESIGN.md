# Privacy design

QuietShield should minimize collection by default and make every diagnostic or activity feature understandable, optional where possible, bounded, and deletable.

## Data classes

- Program metadata: executable identity, package identity, display name.
- Network metadata: adapter type, cost class, DNS configuration, connection outcome.
- Protection activity: rule decisions and aggregate counters.
- Licensing: opaque device identity, entitlement, trial, grace, and device-pool state.
- Diagnostics: component state, error category, version, and redacted timing.

## Foundation rules

- No traffic content, DNS queries, browsing history, file content, credentials, tokens, licence keys, or raw hardware identity is collected.
- The dashboard shows no fabricated counters.
- Read-only adapter descriptions remain in memory and are not written to logs.
- Test fixtures use invented identifiers.
- Logs contain commands and results needed for development validation, not user activity.

## Future requirements

Before activity logging, request logging, licensing communication, analytics, or update telemetry exists, define purpose, legal basis, retention, redaction, user control, export, deletion, breach impact, and cross-device correlation. Default to aggregate counters and short retention. Private Browser data must be isolated and ephemeral by design.
