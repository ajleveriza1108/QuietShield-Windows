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
- Read-only adapter names/descriptions and DNS server addresses remain in the live UI model and are excluded from diagnostic exports.
- The application inventory cache contains bounded display metadata only; it contains no uninstall command, shortcut arguments, executable hashes, credentials, tokens, browser data, or document contents.
- Diagnostic export happens only after an explicit UI or validation-smoke action and contains counts, types, booleans, versions, capability state, and redacted errors.
- Diagnostic redaction removes user-profile paths, the current username, IPv4/IPv6 addresses, MAC addresses, and common credential/token assignments.
- Test fixtures use invented identifiers.
- Logs contain commands and results needed for development validation, not user activity.

## Phase 2 collection boundaries

Normal discovery does not recurse across drives, hash executables, read uninstall commands, retain shortcut arguments, enumerate detailed unrelated Firewall rules for display, expose public IP addresses, inspect Wi-Fi SSIDs, or collect traffic. Store discovery reads package identity fields accessible to the current user. Start Menu discovery is limited to the two Windows-defined Start Menu roots. Safe executable metadata is read only when a launch target can be resolved confidently.

## Future requirements

Before activity logging, request logging, licensing communication, analytics, or update telemetry exists, define purpose, legal basis, retention, redaction, user control, export, deletion, breach impact, and cross-device correlation. Default to aggregate counters and short retention. Private Browser data must be isolated and ephemeral by design.
