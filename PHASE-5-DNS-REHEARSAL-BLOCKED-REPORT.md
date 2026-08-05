# Phase 5 DNS activation rehearsal — safely blocked milestone

## Outcome

Phase 5 is finalized as safely blocked. The activation-rehearsal infrastructure, exact and duplicate-preserving DNS backup/restore logic, independent watchdog, deterministic raw DNS checks, regression coverage, and all failed-attempt evidence are preserved. Real DNS activation remains unvalidated and disabled.

No further UAC request or rehearsal was made during finalization. No Visual Studio setup, installation, repair, cleanup, or other system configuration operation was performed.

## Exact blocker

Approved attempt `9d5c7c5e-0b17-4b9a-b474-5d8db24e2e01` stopped in `ResolverStarted` before any DNS change:

- The embedded `quietshield-blocked.test` rule loaded, normalized correctly, and returned the policy decision `Block`.
- The DNS host's internal UDP and TCP raw-wire tests both returned `NXDOMAIN` (RCODE 3) with matching transaction IDs.
- Readiness was issued only after the policy snapshot and both internal tests passed.
- The separate orchestrator UDP probe to `127.0.0.1` timed out/canceled and returned exit code 2.
- The separate TCP orchestration probe was not reached.
- `dnsChanged` remained `false`; the watchdog canceled before arming; the host stopped and released port 53.

The unresolved issue is documented in `docs/DNS-LOOPBACK-ORCHESTRATION-BLOCKER.md`. The independent external UDP/TCP reachability check remains a hard pre-change gate and was not weakened.

## Validation summary

- Windows PowerShell 5.1 parsing passed for every repository PowerShell script.
- Debug x64 and Release x64 builds passed with .NET SDK `10.0.302`.
- Visual Studio Community 2026 `18.8.2 / 18.8.12023.21` MSBuild Release x64 passed.
- Automated tests: **159/159 passed**, 0 failed.
- The dry Phase 5 checks passed for raw UDP NXDOMAIN, raw TCP NXDOMAIN, PowerShell 5.1 RCODE recognition, trailing-dot normalization, allowed `example.com` forwarding, policy-loaded readiness, watchdog failure simulations, transaction recovery, exact ordered duplicate DNS backup round-trips, hash validation, and runtime-only upstream deduplication.
- The WPF launch smoke passed.
- Authoritative final read-only result: `logs/validation-20260806-073301.json`.
- Complete final transcript: `logs/validation-20260806-073301.log`.

## Protected Windows state

The dry pre/post comparison and the final read-only verification found protected state unchanged:

- DNS configuration and adapter IP-interface state
- Firewall profiles and QuietShield-owned Firewall rules
- QuietShield WFP providers, sublayers, filters, and callouts
- QuietShield registry locations and startup entries
- QuietShield services and related service registration
- Certificates and security settings

No QuietShield service, Firewall rule, WFP object, registry state, startup entry, or certificate was created. DNS was never changed during the failed attempt, and normal DNS remained available afterward.

## Evidence preservation

The failed attempt is closed in `artifacts/dns-rehearsal/attempt-records.jsonl` as `FailedBeforeDnsChange` with `dnsChangeBegan=false`. Its evidence is preserved in:

`artifacts/dns-rehearsal/20260806-072632-9d5c7c5e0b174b9ab4745d8db24e2e01/`

The three earlier failed-attempt directories and the legacy attempt marker remain untouched. These ignored local artifacts may contain machine-specific network configuration; they were preserved but not added to Git.

## Safety decision

Real DNS activation is unvalidated and remains disabled. Permanent DNS activation and permanent service registration are prohibited until the separate-process external UDP and TCP probe issue is resolved, the complete safety gate passes, and a future attempt receives explicit approval.

No retry, automatic repair, system change, or push was performed.
