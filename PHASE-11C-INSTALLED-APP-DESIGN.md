# Phase 11C Installed Non-System Application Rehearsal Design

Status: **Prepared - real rehearsal requires separate explicit approval**

## Objective

Phase 11C moves from the relocated QuietShield-controlled executable proven in Phase 11B to one explicitly selected installed non-system executable already present on the Windows PC.

The purpose is to prove that persistent Program Connection Lock can safely bind to a real installed application without exposing customer-facing enforcement controls yet.

## Candidate classes

Only installed command-line applications with a deterministic bounded network probe are eligible in this phase:

- Base Python `python.exe`
- Git-bundled `curl.exe`
- Node.js `node.exe`

The preparation step discovers candidates locally. It does not silently choose one.

## Mandatory safety gates

A Phase 11C target must:

- exist as one exact regular file;
- not be a reparse point;
- not live under the Windows directory;
- not be a WindowsApps alias;
- not live in `.venv`, `venv`, or `virtualenv`;
- not live in QuietShield service/artifact paths;
- not be a QuietShield executable;
- live under Program Files, Program Files (x86), or LocalAppData\Programs;
- pass a real bounded outbound connectivity probe before selection;
- be explicitly selected by the user;
- have zero pre-existing running processes using that exact executable before the elevated rehearsal;
- remain bound to one exact path, one SHA-256, one path-derived `windows-exe:` identity, and one rehearsal ID.

## Real rehearsal sequence

1. Verify the explicit local selection marker and exact source commit.
2. Verify the selected executable path, hash, identity, and zero pre-existing target processes.
3. Prove the selected executable can connect to a literal IPv4 endpoint before service installation.
4. Install/start the exact owned QuietShieldService using `-AuthorizedProgramPath`.
5. Verify installed-service IPC.
6. Apply `Blocked` through the service transaction path.
7. Verify one exact QuietShield-owned outbound rule targets the selected executable.
8. Prove the selected installed application can no longer reach the same endpoint.
9. Apply `AllowedOnAll` through the service transaction path.
10. Verify the exact rule is absent and connectivity returns.
11. Restart the service and verify last-known-good recovery.
12. Stop/uninstall the exact service.
13. Verify service count 0, `D:\QuietShield\Service` absent, Program Lock rules 0, selected application binary unchanged, connectivity restored, and protected persistent Windows state unchanged.

## Out of scope

Phase 11C does not:

- enable customer Apply/Block buttons;
- target browsers or active user sessions;
- target Windows/system executables;
- modify the selected installed application;
- enforce Wi-Fi-only/mobile-data-specific policies;
- activate DNS;
- modify WFP, adapters, startup, certificates, or unrelated Firewall rules;
- merge the Phase 11 feature branch into `main`.

A successful Phase 11C rehearsal is still a controlled validation step, not customer-facing production activation.
