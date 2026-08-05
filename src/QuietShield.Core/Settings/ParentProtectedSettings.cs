namespace QuietShield.Core.Settings;

public sealed record ParentProtectedSettings(
    bool ChangesRequireParentApproval,
    bool ProtectionDisableIsLocked,
    bool ProfileChangesAreLocked,
    TimeSpan? TemporaryOverrideDuration);

public interface IParentAuthorization
{
    Task<Results.OperationResult> RequestAuthorizationAsync(
        string reason,
        CancellationToken cancellationToken);
}
