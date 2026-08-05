# Development roadmap

Every phase requires a written scope, threat review, privacy review, rollback design, test plan, and explicit approval. Capabilities must remain disabled until verification proves the requested state was applied.

## Phase 1 — validated foundation (complete)

- WPF/MVVM shell and full navigation map.
- Portable domain and licensing models.
- Read-only adapter and DNS discovery.
- Explicit deferred Windows services.
- Non-registered diagnostic service executable.
- Central packages, scripts, tests, and safety documentation.

## Phase 2 — read-only inventory and policy simulation (complete)

Implemented read-only installed-program and Store-identity inventory, richer adapter/cost/category discovery, DNS/Firewall/WFP/service/power capability reporting, in-memory policy evaluation, deterministic simulation output, refresh/cancel/cache actions, notification/resume refresh, privacy-safe diagnostic export, and fixture/live-smoke coverage. Protection remains inactive and no Firewall, DNS, adapter, service, startup, registry, certificate, or filtering state is changed.

Exit criteria passed: 57/57 tests, Debug and Release builds, Visual Studio MSBuild, WPF and discovery smokes, non-elevated execution, and identical pre/post safety snapshots.

## Exact next recommended phase

Phase 3 should be user-approved local settings and simulation-profile persistence only. Define a versioned, privacy-reviewed schema; keep enforcement disabled; add migration, corruption recovery, atomic writes, explicit reset/export, and parent-protection semantics. Do not combine Phase 3 with DNS changes, Firewall changes, WFP creation, licensing communication, installation, updates, or kernel work.

## Later separately approved phases

1. Transactional user-mode DNS protection prototype with backup, verification, rollback, and last-known-good recovery.
2. Program Connection Lock enforcement design and WFP feasibility study.
3. Licensing server protocol, secure device identity, token storage, offline grace, and device management.
4. Signed policy/update pipeline and installer design.
5. Private Browser architecture, only after browser-engine and isolation review.
6. Advanced WFP implementation and independent security assessment.
7. WDK/kernel work only if a documented requirement cannot be met safely in user mode.

FFmpeg, media tooling, SQLite, WebView2, WDK, and driver signing remain outside this foundation.
