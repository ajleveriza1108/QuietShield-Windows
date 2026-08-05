# Development roadmap

Every phase requires a written scope, threat review, privacy review, rollback design, test plan, and explicit approval. Capabilities must remain disabled until verification proves the requested state was applied.

## Phase 1 — validated foundation (current)

- WPF/MVVM shell and full navigation map.
- Portable domain and licensing models.
- Read-only adapter and DNS discovery.
- Explicit deferred Windows services.
- Non-registered diagnostic service executable.
- Central packages, scripts, tests, and safety documentation.

## Recommended next phase — read-only inventory and policy simulation

Implement read-only installed-program and Store-identity inventory, richer adapter/cost discovery, in-memory policy evaluation, deterministic simulation output, accessibility refinement, and localization resource extraction. Do not modify Firewall, DNS, adapters, services, startup, registry, certificates, or filtering state. Add privacy redaction and fixture-based tests before reading real program metadata in the UI.

Exit criteria: complete read-only inventory tests, policy-simulation tests, privacy review, zero elevation, no persistent system changes, and an approved design for any later storage format.

## Later separately approved phases

1. User-approved local settings and protection-profile persistence.
2. Transactional user-mode DNS protection prototype with backup, verification, rollback, and last-known-good recovery.
3. Program Connection Lock enforcement design and WFP feasibility study.
4. Licensing server protocol, secure device identity, token storage, offline grace, and device management.
5. Signed policy/update pipeline and installer design.
6. Private Browser architecture, only after browser-engine and isolation review.
7. Advanced WFP implementation and independent security assessment.
8. WDK/kernel work only if a documented requirement cannot be met safely in user mode.

FFmpeg, media tooling, SQLite, WebView2, WDK, and driver signing remain outside this foundation.
