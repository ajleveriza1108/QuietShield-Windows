# QuietShield custom DNS simulation list format

QuietShield Phase 3 imports and exports custom allowlist and blocklist entries as UTF-8 JSON. The format is local, privacy-safe, and simulation-only: importing a document does not change Windows DNS or enforce a rule.

## Schema version 1

```json
{
  "schemaVersion": 1,
  "description": "QuietShield custom DNS simulation entries",
  "entries": [
    {
      "id": "10000000-0000-0000-0000-000000000001",
      "domainPattern": "example.test",
      "matchKind": "DomainAndSubdomains",
      "listKind": "Blocklist",
      "notes": "Non-production sample",
      "createdAtUtc": "2026-01-01T00:00:00+00:00",
      "parentProtected": false
    }
  ]
}
```

`id` must be a non-empty UUID. `domainPattern` is normalized and validated before activation. `matchKind` is `Exact`, `DomainAndSubdomains`, or `SafeWildcard`; wildcards are accepted only in the form `*.example.test`. `listKind` is `Allowlist` or `Blocklist`. `notes` is optional and limited to 500 characters. `createdAtUtc` records the entry creation time. `parentProtected` marks a blocklist entry that receives parent-protected precedence.

The complete document is validated before it atomically replaces the current in-memory custom list. Invalid, malformed, unsupported, or duplicate input leaves the current list unchanged. Exported documents contain domain rules and user-authored notes, so users should review them before sharing. QuietShield does not include browsing history, resolved addresses, page content, credentials, request payloads, keys, or machine identifiers.
