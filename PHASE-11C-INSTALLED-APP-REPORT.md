# Phase 11C Installed Non-System Application Rehearsal

Status: **Passed**

Validated source commit:

`141aad3647e489c0e5aceea0a0ddfc2c93fa10e0`

## Selected installed application

- Application: The curl executable
- Executable: `C:\Program Files\Git\mingw64\bin\curl.exe`
- Probe adapter: `GitCurl`
- Target identity mode: Path-derived
- Stable identity: `windows-exe:62922d04051f641dd0f0bf0bc0c85e3a`
- SHA-256: `0E773709C3A44DB47B88B71351D902027682ED87C3BD3821009E454BACCA8778`

## Direct GitCurl preflight repair

- Default curl configuration disabled with `-q`: Passed
- Proxy bypass forced with `--noproxy *`: Passed
- `proxy_used`: 0
- Exact direct remote IP during validated preflight: `104.20.23.154`
- Exact direct remote port: 443
- Exact direct endpoint verification: Passed

## Controlled persistent enforcement

- Exact path / SHA-256 binding: Passed
- Exact service install/start: Passed
- Installed-service IPC: Passed
- Blocked enforcement against installed application: Passed
- AllowedOnAll exact-rule removal: Passed
- Installed-application connectivity restoration: Passed
- Service restart / last-known-good recovery: Passed
- Exact service stop/uninstall: Passed
- Selected application binary modified: No

## Final state

- `QuietShieldService` remaining: 0
- `D:\QuietShield\Service` remaining: No
- QuietShield Program Lock rules remaining: 0
- Protected persistent Windows state: Unchanged
- Restart required: No

## Still gated / not attempted

- Customer-facing persistent enforcement controls: Not enabled
- DNS activation: Not attempted
- Network-specific persistent enforcement: Not attempted
- WFP changes: Not attempted
- Adapter changes: Not attempted
- Unrelated Firewall changes: Not attempted
- Main-branch merge: Not performed

Phase 11C proves persistent Program Connection Lock against one explicitly selected installed non-system application while preserving exact target authorization, exact-rule ownership, rollback, last-known-good recovery, and zero-residue cleanup.

Phase 11D remains the next integration gate before the full Phase 11 branch can be considered for merge to `main`.
