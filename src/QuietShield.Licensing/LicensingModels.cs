namespace QuietShield.Licensing;

public enum QuietShieldPlatform
{
    AndroidPhoneOrTablet,
    AndroidTv,
    Windows
}

public enum LicenseState
{
    Unknown,
    ServerControlledTrial,
    Licensed,
    TemporaryOfflineGrace,
    Expired,
    DeviceLimitReached,
    PrivateAdministratorUnlimited
}

public sealed record UniversalLicensePolicy(
    int MaximumActiveDevices,
    TimeSpan FullFeatureTrialDuration,
    bool TrialIsServerControlled,
    bool ReinstallationResetsTrial,
    IReadOnlySet<QuietShieldPlatform> SupportedPlatforms)
{
    public static UniversalLicensePolicy Default { get; } = new(
        3,
        TimeSpan.FromDays(7),
        true,
        false,
        new HashSet<QuietShieldPlatform>
        {
            QuietShieldPlatform.AndroidPhoneOrTablet,
            QuietShieldPlatform.AndroidTv,
            QuietShieldPlatform.Windows
        });
}

public sealed record LicensedDevice(
    string OpaqueDeviceId,
    string DisplayName,
    QuietShieldPlatform Platform,
    DateTimeOffset ActivatedAtUtc,
    DateTimeOffset? LastSeenAtUtc,
    bool IsActive);

public sealed record DevicePoolState(
    IReadOnlyList<LicensedDevice> Devices,
    bool IsPrivateAdministratorLicense)
{
    public int ActiveDeviceCount => Devices.Count(static device => device.IsActive);

    public bool CanActivateAnotherDevice(UniversalLicensePolicy policy) =>
        IsPrivateAdministratorLicense || ActiveDeviceCount < policy.MaximumActiveDevices;
}

public sealed record TrialState(
    DateTimeOffset ServerStartedAtUtc,
    DateTimeOffset ServerExpiresAtUtc,
    DateTimeOffset ServerObservedAtUtc,
    bool IsServerControlled)
{
    public bool IsActiveAt(DateTimeOffset serverTimeUtc) =>
        IsServerControlled &&
        serverTimeUtc >= ServerStartedAtUtc &&
        serverTimeUtc < ServerExpiresAtUtc;

    public TimeSpan RemainingAt(DateTimeOffset serverTimeUtc)
    {
        var remaining = ServerExpiresAtUtc - serverTimeUtc;
        return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
    }

    public bool MatchesPolicy(UniversalLicensePolicy policy) =>
        IsServerControlled == policy.TrialIsServerControlled &&
        ServerExpiresAtUtc - ServerStartedAtUtc == policy.FullFeatureTrialDuration;
}

public sealed record OfflineGraceState(
    DateTimeOffset GrantedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string ServerPolicyVersion)
{
    public bool IsActiveAt(DateTimeOffset nowUtc) => nowUtc < ExpiresAtUtc;
}

public sealed record LicenseSnapshot(
    LicenseState State,
    string DisplayStatus,
    DevicePoolState? DevicePool,
    TrialState? Trial,
    OfflineGraceState? OfflineGrace)
{
    public static LicenseSnapshot Foundation { get; } =
        new(LicenseState.Unknown, "Licence state not connected in Foundation Mode", null, null, null);
}
