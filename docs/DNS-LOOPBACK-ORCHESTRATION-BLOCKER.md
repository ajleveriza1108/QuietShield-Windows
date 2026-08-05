# DNS loopback orchestration blocker

## Status

Phase 5 is a safely blocked milestone. The temporary DNS host, rollback watchdog, exact DNS backup handling, deterministic DNS-wire checks, and append-only attempt accounting are preserved, but real DNS activation remains unvalidated and disabled.

Do not run another activation rehearsal, enable permanent DNS activation, or register a permanent QuietShield service until the process-boundary loopback probe issue below is understood and resolved. Any future attempt requires a new, explicitly approved scope.

## Exact unresolved blocker

During approved attempt `9d5c7c5e-0b17-4b9a-b474-5d8db24e2e01`:

- The DNS host loaded and normalized the embedded `quietshield-blocked.test` rule, and its policy decision was `Block`.
- The host's internal raw UDP and TCP self-tests both returned valid matching-transaction responses with DNS RCODE 3 (`NXDOMAIN`).
- The host issued readiness only after the policy snapshot was loaded and both internal wire-protocol tests passed.
- A separate orchestrator process then sent the required raw UDP probe to `127.0.0.1`. It timed out/canceled and returned probe exit code 2.
- The required separate TCP orchestration probe was not reached.
- The failure happened before the DNS-change boundary. Windows DNS was never changed, the watchdog was canceled before arming, and the temporary host released port 53.

This is a process-boundary reachability discrepancy: the host can query its own loopback sockets over UDP and TCP, while the separate orchestrator's UDP query does not receive the response. The evidence does not justify attributing the failure to Firewall, WFP, or another Windows subsystem, and those settings must not be changed speculatively.

## Preserved evidence

All failed-attempt material remains local and append-only under `artifacts/dns-rehearsal/`. In particular:

- Final attempt directory: `artifacts/dns-rehearsal/20260806-072632-9d5c7c5e0b174b9ab4745d8db24e2e01/`
- Append-only ledger: `artifacts/dns-rehearsal/attempt-records.jsonl`
- Older attempt directories: `20260806-063709-1495f406cc3c40fdbd2a22e690c5ff10`, `20260806-065110-5836632a78d04d4882348142425dcc81`, and `20260806-070559-c7a4fd58b2de4f19b856a414675389e3`
- Legacy attempt marker: `artifacts/dns-rehearsal/rehearsal-attempted.marker`

The final ledger closes the approved attempt as `FailedBeforeDnsChange` with `dnsChangeBegan=false`. Evidence files may contain machine-specific network configuration and therefore remain ignored local artifacts; they must not be deleted, overwritten, published, or committed.

## Safety invariant

The external resolver-reachability gate remains mandatory and must not be weakened, bypassed, or replaced by the host's internal self-test. Before any future DNS change, a separate orchestrator must prove all of the following through `127.0.0.1`:

1. Raw UDP returns a valid DNS response for exactly `quietshield-blocked.test`, with the matching transaction ID and RCODE exactly 3.
2. Raw TCP independently returns the same validated result.
3. An allowed-domain query succeeds through the configured upstream path.
4. The exact DNS backup, adapter identity, independent watchdog, rollback path, and bounded deadline all remain valid.

Failure or timeout at any gate must stop before changing DNS.

## Investigation backlog

Investigation must remain read-only with respect to Windows configuration until separately approved:

- Reproduce same-process and separate-process UDP/TCP loopback queries against a disposable high port and, only in a separately approved elevated diagnostic, port 53.
- Add bounded socket-level diagnostics for bind addresses, source/destination endpoints, receive deadlines, cancellation origin, and Windows socket error codes without logging browsing domains or DNS payload contents.
- Verify whether the response is emitted and whether it reaches the separate client process. Compare process lifetime, address family, dual-stack behavior, socket sharing/exclusivity, and cancellation timing.
- Compare the DNS host's internal probe implementation with the orchestrator invocation and transport lifecycle, keeping the existing raw DNS validation identical.
- Inspect existing Windows filtering behavior only through read-only supported diagnostics. Do not change Firewall, WFP, security products, registry policy, certificates, adapters, services, or security settings as an experiment.
- Add a non-activation integration test that launches host and probe as separate processes and requires both UDP and TCP success before reporting readiness to the orchestrator.

## Exit criteria

This blocker may be closed only when a separate-process integration test reliably passes raw UDP and TCP loopback validation, the 159-test dry suite and protected-state comparisons still pass, and a new rehearsal receives explicit approval. Until then, permanent DNS activation and service registration are prohibited.
