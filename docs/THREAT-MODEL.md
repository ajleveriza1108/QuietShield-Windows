# Threat model

## Assets

- User connectivity and recoverable network configuration.
- Protection policy integrity and truthful UI state.
- Licence entitlement and protected tokens.
- Update authenticity and rollback state.
- Program, activity, browsing, file, and device privacy.
- Availability of Windows, third-party security software, and remote access.

## Adversaries and failure sources

- Malicious local process at equal or higher privilege.
- Compromised update, policy, list, or licensing infrastructure.
- Network attacker, captive portal, hostile DNS, or proxy.
- Conflicting VPN, security product, enterprise policy, or administrator action.
- Programming error, partial transaction, crash, power loss, or disk failure.
- UI deception that reports protection not actually enforced.
- Privacy leakage through logs, identifiers, diagnostics, or support bundles.

## Foundation mitigations

- Standard-user `asInvoker` process with no privileged helper.
- Zero active protection and clear inactive messaging.
- Platform-independent policy core and dependency tests.
- Explicit `NotImplemented` and `Unsupported` outcomes.
- Read-only network APIs only.
- Mandatory future transaction lifecycle including last-known-good recovery.
- Central, minimal, stable dependencies.
- No endpoints, secrets, certificates, fingerprint algorithm, browser engine, installer, driver, or system registration.
- Cancellation-aware service heartbeat with clean shutdown.

## Deferred mitigations

Future phases must add authenticated updates and lists, anti-rollback, protected storage, protocol validation, rate limits, secure device identity, policy ownership, WFP isolation, recovery drills, fuzzing, penetration testing, privacy tests, and independent review. Kernel work requires an additional driver-specific threat model.

## Security invariants

1. UI protection state follows verified engine state.
2. A failed or ambiguous transaction rolls back.
3. QuietShield never silently weakens another security control.
4. No secret or sensitive identifier enters normal logs.
5. Uninstall and recovery restore owned state without erasing unrelated configuration.
