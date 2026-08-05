using QuietShield.Core.Results;

namespace QuietShield.Core.Protection;

public sealed record ProtectionState(
    bool IsActive,
    string Status,
    string? ActiveProfileId)
{
    public static ProtectionState Foundation { get; } =
        new(false, "Foundation Mode / Protection Not Yet Activated", null);
}

public interface IProtectionEngine
{
    Task<ProtectionState> GetStateAsync(CancellationToken cancellationToken);

    Task<OperationResult> PreflightAsync(CancellationToken cancellationToken);
}

public interface IProfileRepository
{
    Task<IReadOnlyList<ProtectionProfile>> GetProfilesAsync(CancellationToken cancellationToken);
}
