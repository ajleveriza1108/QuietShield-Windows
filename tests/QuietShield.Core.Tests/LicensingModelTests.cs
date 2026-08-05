using QuietShield.Licensing;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class LicensingModelTests
{
    [TestMethod]
    public void UniversalPolicyUsesOneThreeDevicePoolAcrossAllPlatforms()
    {
        var policy = UniversalLicensePolicy.Default;

        Assert.AreEqual(3, policy.MaximumActiveDevices);
        Assert.AreEqual(TimeSpan.FromDays(7), policy.FullFeatureTrialDuration);
        Assert.IsTrue(policy.TrialIsServerControlled);
        Assert.IsFalse(policy.ReinstallationResetsTrial);
        Assert.HasCount(3, policy.SupportedPlatforms);
    }

    [TestMethod]
    public void StandardLicenceRejectsFourthActiveDevice()
    {
        var pool = new DevicePoolState(CreateThreeActiveDevices(), false);

        Assert.AreEqual(3, pool.ActiveDeviceCount);
        Assert.IsFalse(pool.CanActivateAnotherDevice(UniversalLicensePolicy.Default));
    }

    [TestMethod]
    public void PrivateAdministratorLicenceHasUnlimitedDevicePool()
    {
        var pool = new DevicePoolState(CreateThreeActiveDevices(), true);

        Assert.IsTrue(pool.CanActivateAnotherDevice(UniversalLicensePolicy.Default));
    }

    [TestMethod]
    public void SevenDayTrialUsesServerTimeAndDoesNotImplyReinstallReset()
    {
        var start = new DateTimeOffset(2026, 8, 1, 0, 0, 0, TimeSpan.Zero);
        var trial = new TrialState(start, start.AddDays(7), start, true);

        Assert.IsTrue(trial.MatchesPolicy(UniversalLicensePolicy.Default));
        Assert.IsTrue(trial.IsActiveAt(start.AddDays(6)));
        Assert.IsFalse(trial.IsActiveAt(start.AddDays(7)));
        Assert.AreEqual(TimeSpan.Zero, trial.RemainingAt(start.AddDays(8)));
    }

    private static LicensedDevice[] CreateThreeActiveDevices() =>
        new[]
        {
            CreateDevice("opaque-1", QuietShieldPlatform.AndroidPhoneOrTablet),
            CreateDevice("opaque-2", QuietShieldPlatform.AndroidTv),
            CreateDevice("opaque-3", QuietShieldPlatform.Windows)
        };

    private static LicensedDevice CreateDevice(string id, QuietShieldPlatform platform) =>
        new(id, "Device", platform, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, true);
}
