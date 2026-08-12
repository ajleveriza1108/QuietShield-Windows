# QuietShield Windows — AGENTS.md

## Purpose

This file contains persistent operating rules for Codex working on **QuietShield Windows**.

Keep this file concise. Do not duplicate the full project history here. Use the permanent Phase reports for detailed evidence.

---

## Repository

- Repository: `D:\Windows Projects\QuietShield-Windows`
- GitHub: `https://github.com/ajleveriza1108/QuietShield-Windows`
- Published Phase 11 integration branch: `feature/phase-11-integration-stabilization`
- Validated Phase 11D source: `827e4f1369abf68f599038e2c8cf8574248eb100`
- Advance `main` only through the explicitly approved, history-preserving final Phase 11 merge.

Do not merge `main` early.

---

## Current Phase Status

- Phase 10B: **PASSED**
- Phase 11A: **PASSED**
- Phase 11B: **PASSED**
- Phase 11C: **PASSED**
- Phase 11D: **PASSED**
- Phase 11: **COMPLETE**
- Phase 12 static installer milestone: **PASSED**
- Next gate: **Phase 12 controlled install/upgrade/uninstall rehearsal; explicit approval required**

Permanent evidence:

- `PHASE-11-INTEGRATION-REPORT.md`
- `PHASE-11B-TARGET-AUTHORIZATION-DESIGN.md`
- `PHASE-11B-PROGRAM-TARGET-REPORT.md`
- `PHASE-11C-INSTALLED-APP-DESIGN.md`
- `PHASE-11C-INSTALLED-APP-REPORT.md`
- `PHASE-11D-DESKTOP-ACTIVATION-REPORT.md`
- `PHASE-11-COMPLETION-REPORT.md`
- `PHASE-12-BETA-INSTALLER-REPORT.md`

Read only the reports needed for the current task.

---

## Phase 11C Proven State

Validated enforcement source:

`141aad3647e489c0e5aceea0a0ddfc2c93fa10e0`

Final evidence publication:

`ef298992454bc48b2603032f7a913ee0bb314afd`

Validated installed application:

`C:\Program Files\Git\mingw64\bin\curl.exe`

SHA-256:

`0E773709C3A44DB47B88B71351D902027682ED87C3BD3821009E454BACCA8778`

Path-derived identity:

`windows-exe:62922d04051f641dd0f0bf0bc0c85e3a`

Phase 11C proved:

- exact path/SHA binding
- direct proxy-free GitCurl preflight
- `Blocked` enforcement
- `AllowedOnAll` exact-rule removal
- connectivity restoration
- service restart / last-known-good recovery
- exact service stop/uninstall
- selected application unchanged
- zero service residue
- zero Program Lock rule residue
- protected persistent Windows state unchanged

Do not rerun Phase 11C.

---

## Safety Boundaries

### Do not rerun completed real rehearsals

Do **not** rerun:

- Phase 5 DNS activation
- Phase 9 Firewall rehearsal
- Phase 10B service rehearsal
- Phase 11B generalized target rehearsal
- Phase 11C installed-application rehearsal

Existing reports are authoritative evidence.

### DNS

Phase 5 DNS activation remains **blocked** because the orchestration UDP loopback probe failed.

Do not:

- activate permanent system DNS
- retry Phase 5 during Phase 11D
- register permanent DNS service behavior
- claim DNS enforcement is proven

### Persistent Program Connection Lock

Only these persistent policies are currently validated:

- `Blocked`
- `AllowedOnAll`

Network-specific policies remain simulation-only, including:

- Wi-Fi-only
- cellular/mobile-specific behavior
- dynamic runtime network-transition policies

### Windows changes

Do not touch unrelated:

- Firewall rules
- WFP
- network adapters
- startup registry
- certificates
- Windows security settings

unless a future explicitly scoped phase requires it.

### Privilege

- No silent self-elevation.
- Administrative operations must be explicit, narrow, and justified.
- Preserve non-admin status/read behavior where possible.

### Git

Never use:

- `git reset`
- `git clean`
- force-push

Do not restore old one-time validators that were intentionally removed.

Keep `safe.directory` specific:

`git config --global --add safe.directory 'D:/Windows Projects/QuietShield-Windows'`

Never use wildcard `safe.directory`.

---

## Token / API Efficiency Mode

Minimize Codex/API/token usage while preserving correctness.

1. Do not repeatedly scan the whole repository.
2. Inspect only files relevant to the current task.
3. Use targeted search first.
4. Do not reread all Phase reports on every task.
5. Do not repeatedly summarize the full project history.
6. Do not dump complete source files into chat unless requested.
7. Make the smallest correct change.
8. Avoid unrelated refactors.
9. Use targeted tests first.
10. Run full regression only at meaningful milestone/final gates.
11. Avoid repeated Debug + Release + MSBuild + WPF smoke after every small edit.
12. Do not use web research unless external current documentation is actually needed.
13. Ignore generated/output directories during normal discovery unless required:
    - `bin/`
    - `obj/`
    - `artifacts/`
    - `.vs/`
    - generated logs
14. Batch related non-destructive inspections where practical.
15. Stop when the requested milestone is complete.
16. Do not automatically continue into the next phase.
17. Do not ask for information already established in this file or the permanent reports unless the repository contradicts it.

Use this compact status format during implementation:

```text
STATUS: PASS / BLOCKED / NEEDS FIX
CHANGED: <file count and short names>
VALIDATED: <targeted tests/builds>
SYSTEM CHANGES: NONE / exact approved change
NEXT: <one next action>
```

---

## PowerShell 5.1 Rules

PowerShell variables are case-insensitive.

Do not use pairs like:

- `$Branch` / `$branch`
- `$Target` / `$target`

Use distinct names such as:

- `$TargetBranch`
- `$CurrentBranch`

Do not use `$Args` as your own parameter name. `$args` is automatic.

Use names such as:

`$GitArguments`

When native STDERR may contain harmless logging under:

`$ErrorActionPreference = 'Stop'`

prefer:

- `Start-Process`
- separate stdout/stderr
- real process `ExitCode`

When using redirected process output, do not assume `WaitForExit(timeout)` means redirected streams are fully flushed.

For robust capture use `System.Diagnostics.Process` with:

- redirected stdout/stderr
- `ReadToEndAsync()`
- timed `WaitForExit(...)`
- parameterless `WaitForExit()`
- wait for stream tasks before parsing

Do not parse mixed console/build output as JSON. Validate generated files on disk instead.

## Toolchain compatibility

- Honor `global.json` roll-forward semantics. With `10.0.302` and `latestPatch`, a stable SDK such as `10.0.303` in the same `10.0.3xx` feature band is compatible.
- Require Visual Studio 2026 Community from the validated installation path, complete and launchable, with Managed Desktop, NuGet, and MSBuild capabilities.
- Treat Visual Studio `18.8.x` servicing patches as compatible when they are at least the validated `18.8.2` baseline; do not pin the full installation build string.
- Reject incompatible feature lines, missing capabilities, incomplete/unlaunchable instances, prerelease toolchains, or toolchains that fail a real build/test.
- Do not install, downgrade, or modify a toolchain merely to match a historical servicing-patch string.

Avoid broad string replacement. Patch exact anchored blocks.

Do not use `powershell.exe -File` for known problematic `-Confirm:$false` paths. Prefer direct same-process invocation where required.

---

## Program Target Authorization Rules

Preserve:

- exact absolute executable path
- exact SHA-256
- path-derived stable identity
- reparse-point refusal
- Windows/system executable refusal
- QuietShield executable refusal
- approved install-root checks
- exact QuietShield rule ownership
- foreign exact-name collision refusal
- transaction rollback
- last-known-good recovery
- emergency recovery precedence

`AllowedOnAll` means the verified absence of QuietShield-owned blocking rules.

Do not create an Allow Firewall rule merely to represent `AllowedOnAll`.

Historical target identity relaxation is allowed only for cleanup/uninstall of old transactions.

Normal enforcement still requires the live exact target.

---

## Phase 11D Completed Objective

Phase 11D passed and is preserved as completed integration work.

Goal:

Integrate the proven persistent service path into the real desktop customer workflow and lifecycle safely.

### Required Phase 11D behavior

The Program Connection Lock desktop workflow should represent:

- selected installed application
- application identity
- requested policy
- persistent enforcement availability
- QuietShieldService installed/running status
- applied/pending/recovering state
- IPC/service errors
- fallback behavior

Persistent customer-capable policies at this stage:

- `Blocked`
- `AllowedOnAll`

Network-specific choices must remain non-persistent/simulation-only.

### Customer UX

Do not expose developer-style controls such as:

- Install Service
- Start Service
- Raw Firewall Apply
- Force Rule

Normal customer UI should instead:

- detect service availability
- request validated policy changes
- show progress
- show success/failure
- offer safe recovery/retry where appropriate

### Lifecycle

Cover:

- app startup status refresh
- service status refresh
- IPC availability
- target identity revalidation
- saved-policy reconciliation
- app restart reconciliation
- Windows restart reconciliation
- graceful desktop shutdown

Avoid high-frequency polling. Prefer bounded/event-driven refresh where practical.

### LKG / config reconciliation

Define clear precedence between:

- user requested policy
- saved desktop configuration
- service current state
- service last-known-good state
- incomplete/failed transaction
- recovery state

Do not overwrite service LKG blindly from stale UI state.

### Error UX

Distinguish at minimum:

- service unavailable
- service stopped
- IPC failure
- target executable missing
- target hash changed
- unsupported persistent network-specific policy
- transaction rollback
- recovery succeeded
- administrative action required
- persistent protection temporarily unavailable

Do not expose raw internal exceptions to customers.

---

## Phase 11D Validation Strategy

Do not begin by running another real Firewall rehearsal.

First:

1. inspect current architecture
2. design
3. implement
4. add targeted tests
5. run non-system-modifying validation
6. run full Phase 11 regression only at the final gate

Add deterministic tests for:

- desktop view-model/service integration
- `Blocked` request flow
- `AllowedOnAll` request flow
- service unavailable fallback
- service stopped state
- IPC failure
- missing target
- hash mismatch
- LKG/recovery status
- app restart reconciliation
- unsupported network-specific persistence
- DNS activation remaining impossible
- no unrelated Firewall operations
- no self-elevation
- no raw developer service controls in normal UI

Any new real Windows-changing rehearsal requires separate justification and explicit approval.

---

## Resume Procedure

Before editing:

```powershell
git branch --show-current
git rev-parse HEAD
git status --short
git log --oneline --decorate -15
```

Expected after the final Phase 11 publication:

- `main` contains the history-preserving merge of `feature/phase-11-integration-stabilization`
- the feature branch remains available on origin
- the working tree is clean

Verify origin refs non-destructively. Do not assume historical pre-merge commit IDs are current.

If the repository differs:

- stop before destructive action
- report actual branch
- report actual HEAD
- report `git status`
- report relevant commits
- explain exact mismatch

The repository is authoritative.

Do not reset or clean Git merely to make it match this file.

---

## Baseline Validation on Resume

Run a fresh non-system-modifying baseline on the current HEAD.

Use:

- PowerShell 5.1 parser checks where applicable
- targeted/full `dotnet test` as appropriate
- Debug build
- Release x64 build
- VS/MSBuild Release x64 at milestone validation
- WPF architecture/smoke tests that do not install the service
- `git diff --check`

The old Codex Desktop `343/344` test result and whitespace-sensitive assertion are historical unless reproduced on current HEAD.

---

## Phase 11 Completion Gate

Before merging the Phase 11 feature branch to `main`, require:

- Phase 11A preserved
- Phase 11B authorization preserved
- Phase 11C installed-app behavior preserved
- Phase 11D workflow tests passed
- full automated suite passed
- Debug build passed
- Release x64 passed
- VS/MSBuild Release x64 passed where applicable
- WPF smoke passed
- PowerShell 5.1 parser passed
- `git diff --check` passed
- no raw unsafe customer controls
- DNS activation not attempted
- network-specific persistence still gated
- no service/rule residue
- protected persistent Windows state unchanged

Only then merge:

`feature/phase-11-integration-stabilization`

into:

`main`

No force-push.

Create permanent Phase 11 completion evidence.

---

## Later Phases

After Phase 11:

- Phase 12 — Self-contained beta installer
- Phase 13 — Universal licensing
- Phase 14 — Trial/release hardening

Do not start Phase 12 before Phase 11 is fully complete.

Phase 12 static packaging is complete. Do not run the beta installer or perform a production service install, upgrade, repair, or uninstall until a separately approved controlled rehearsal.
