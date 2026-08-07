# Phase 11B Controlled Program Target Rehearsal

Status: **Passed**

- Authorized target identity: Path-derived
- Authorized target type: Relocated controlled non-system test executable with complete .NET runtime set
- Exact service install/start: Passed
- Local authorized named-pipe IPC: Passed
- Generalized Blocked transaction: Passed
- Exact AllowedOnAll removal: Passed
- Controlled-target connectivity restoration: Passed
- Service restart and last-known-good recovery: Passed
- Exact service stop/uninstall: Passed
- Remaining exact Program Lock rules: 0
- Protected persistent Windows state: Unchanged
- Restart required: No

The rehearsal proved that persistent Program Connection Lock authorization is no longer hard-coded to the literal quietshield.connection-probe stable identity. The original apphost filename was preserved only for .NET runtime resolution; authorization used the relocated path-derived identity. The authorized executable remained bound to one exact path, one exact SHA-256, one path-derived stable identity, and one approved rehearsal ID.

No installed customer application was targeted. No DNS, WFP, adapter, unrelated Firewall rule, startup, certificate, or unrelated security setting was changed.
