# Security boundaries

## Current privilege boundary

QuietShield runs as the current standard user. The application manifest requests `asInvoker`. Scripts explicitly reject Administrator sessions and contain no self-elevation path. No broker, scheduled task, startup entry, service registration, COM elevation, driver, or privileged helper is created.

## Current system-change boundary

The foundation must not change:

- Windows Firewall profiles or rules;
- DNS client or resolver configuration;
- adapters, routes, network categories, proxies, or connection cost;
- services, scheduled tasks, startup entries, or boot state;
- registry values, certificates, trust stores, or security settings;
- Windows Filtering Platform filters, providers, callouts, or policy;
- files outside the project, except normal read-only toolchain access and NuGet retrieval into the project cache.

The Windows assembly implements safe read-only adapter and DNS discovery. Other capabilities return explicit deferred states. No UI state may imply successful protection without a verified engine result.

## Transactional requirement for future mutators

Any future system change must implement all six stages: preflight, backup, transactional apply, verification, rollback, and last-known-good recovery. A plan must identify ownership, concurrency, crash recovery, partial failure, idempotency, audit events, and user consent.

## Secret boundary

No production endpoint, licence key, administrator key, signing key, certificate, credential, access token, private-key material, or device-fingerprint algorithm belongs in this repository. Secret-bearing files are excluded by `.gitignore`; future secrets require operating-system-backed protected storage and redacted diagnostics.

## Deferred high-risk work

Firewall/DNS enforcement, WFP, drivers, startup recovery, updating, licensing communication, browser isolation, and file safety each require a dedicated threat model and approval. WDK/kernel work is the final option, not a default dependency.
