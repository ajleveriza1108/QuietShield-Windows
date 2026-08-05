# Licensing design

## Universal entitlement

One universal QuietShield licence covers Android phone/tablet, Android TV, and Windows. Standard licences share one pool of three active devices across all platforms. A private administrator entitlement is unlimited and must be represented by a server-authoritative claim, never a client-embedded key.

## Trial

The full-feature trial lasts seven calendar days and is server controlled. The server owns start, expiry, observation time, and policy version. Reinstalling an application must not create a new trial. The same Windows device should be recognized after reinstall through a future privacy-reviewed opaque identity provider.

The foundation models these rules but deliberately does not define a fingerprint algorithm. Hardware serial-number harvesting, raw identifier upload, and irreversible cross-context identifiers are prohibited without a separate privacy and security decision.

## Offline grace

Temporary offline grace is a signed or otherwise authenticated server policy with a grant time, expiry, and policy version. The client must fail honestly when grace expires and must not extend grace from local clock changes. Details of clock rollback defense and secure persistence are deferred.

## Contracts

- `ILicenseService`: current entitlement snapshot.
- `IDeviceManagementService`: list and deactivate devices.
- `ILicenseRefreshService`: explicit refresh operation.
- `IDeviceIdentityProvider`: stable opaque reinstall identity without prescribing an algorithm.
- `ISecureTokenStore`: protected binary token storage by logical name.

## Security and privacy rules

- No real endpoint or credential in source, tests, logs, or configuration.
- Never log tokens, licence keys, device identifiers, or full server responses.
- Validate server time, signatures, expiry, audience, product, and replay boundaries.
- Provide device-removal recovery without weakening the three-device limit.
- Treat administrator entitlement as sensitive server state.
- Make destructive device-management actions explicit and auditable.
