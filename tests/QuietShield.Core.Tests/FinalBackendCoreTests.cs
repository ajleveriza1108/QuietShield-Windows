// QuietShield Backend Pack 5-8 R1
using System.Security.Cryptography;
using QuietShield.Core.FinalBackends;
using QuietShield.Licensing;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class FinalBackendCoreTests
{
    private static readonly string[] TrackerHosts = ["tracker.example"];

    [TestMethod]
    public void ParentChildPolicyBlocksOutsideSchedule()
    {
        var now = DateTimeOffset.Now;
        var blockedDay = (DayOfWeek)(((int)now.DayOfWeek + 1) % 7);

        var policy = new ChildProtectionPolicy(
            "child-1",
            "Child",
            true,
            Array.Empty<string>(),
            Array.Empty<string>(),
            Array.Empty<string>(),
            new[]
            {
                new DailyAccessWindow(blockedDay, new TimeOnly(0, 0), new TimeOnly(23, 59))
            },
            false,
            false);

        var result = ParentChildPolicyEngine.Evaluate(
            policy,
            new ChildAccessRequest(
                FamilyRole.Child,
                now,
                "sample.app",
                null));

        Assert.IsFalse(result.Allowed);
        Assert.IsFalse(result.ScheduleMatched);
    }

    [TestMethod]
    public void ParentPinUsesSaltedFixedTimeVerification()
    {
        var credential = ParentPinCredential.Create("246810");
        Assert.IsTrue(credential.Verify("246810"));
        Assert.IsFalse(credential.Verify("135791"));
        Assert.AreNotEqual(credential.SaltBase64, credential.HashBase64);
    }

    [TestMethod]
    public void ChildPolicyIntegrityRejectsTampering()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var policy = CreateChildPolicy();
        var envelope = ChildPolicyIntegrity.Protect(policy, key);

        var payload = Convert.FromBase64String(envelope.PayloadBase64);
        payload[0] ^= 0x01;

        var tampered = envelope with
        {
            PayloadBase64 = Convert.ToBase64String(payload)
        };

        Assert.ThrowsExactly<CryptographicException>(
            () => ChildPolicyIntegrity.Unprotect(tampered, key));
    }

    [TestMethod]
    public void PrivateBrowserBlocksTrackerAndClearsIncognito()
    {
        var policy = new PrivateBrowserPolicy(
            RequireHttps: true,
            BlockCredentialInUrl: true,
            BlockPrivateNetworkDestinations: true,
            BlockKnownTrackerHosts: true,
            BlockedHosts: Array.Empty<string>(),
            TrackerHosts: TrackerHosts);

        var session = new PrivateBrowserSession(
            PrivateBrowserMode.Incognito,
            policy);

        var blocked = session.Navigate(new Uri("https://tracker.example/pixel"));
        Assert.AreEqual(BrowserNavigationAction.Block, blocked.Action);

        var allowed = session.Navigate(new Uri("https://example.com/"));
        Assert.AreEqual(BrowserNavigationAction.Allow, allowed.Action);

        session.SetCookie(new(
            "session",
            "opaque",
            "example.com",
            null));

        Assert.HasCount(1, session.GetHistorySnapshot());
        Assert.HasCount(1, session.GetCookieSnapshot());

        session.Close();

        Assert.IsEmpty(session.GetHistorySnapshot());
        Assert.IsEmpty(session.GetCookieSnapshot());
    }

    [TestMethod]
    public void WebsiteSafetyFlagsCredentialUrl()
    {
        var report = WebsiteSafetyEngine.Evaluate(
            new Uri("https://user:password@example.com/login"));

        Assert.AreEqual(WebsiteRiskLevel.High, report.Risk);
        Assert.IsFalse(report.ShouldBlock);
        Assert.IsTrue(report.Signals.Any(static item =>
            item.Contains("credentials", StringComparison.OrdinalIgnoreCase)));
    }

    [TestMethod]
    public void SignedLicenseEnforcesUniversalDevicePolicy()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = key.ExportSubjectPublicKeyInfo();
        var now = DateTimeOffset.UtcNow;
        var opaqueId = "device-opaque-1";

        var payload = new SignedLicensePayload(
            "license-1",
            LicenseState.Licensed,
            now,
            now.AddDays(365),
            opaqueId,
            new[]
            {
                new LicensedDevice("d1", "One", QuietShieldPlatform.Windows, now, now, true),
                new LicensedDevice("d2", "Two", QuietShieldPlatform.AndroidPhoneOrTablet, now, now, true),
                new LicensedDevice("d3", "Three", QuietShieldPlatform.AndroidTv, now, now, true)
            },
            null,
            false,
            "v1");

        var envelope = SignedLicenseBackend.SignForTesting(payload, key);
        var verified = SignedLicenseBackend.Verify(
            envelope,
            publicKey,
            opaqueId,
            now);

        Assert.AreEqual(payload.LicenseId, verified.LicenseId);
        Assert.HasCount(3, verified.Devices);
    }

    [TestMethod]
    public void SignedLicenseRejectsTamperedSignature()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = key.ExportSubjectPublicKeyInfo();
        var now = DateTimeOffset.UtcNow;

        var payload = new SignedLicensePayload(
            "license-2",
            LicenseState.Licensed,
            now,
            now.AddDays(30),
            "device-2",
            Array.Empty<LicensedDevice>(),
            null,
            false,
            "v1");

        var envelope = SignedLicenseBackend.SignForTesting(payload, key);
        var signature = Convert.FromBase64String(envelope.SignatureBase64);
        signature[0] ^= 0x01;

        var tampered = envelope with
        {
            SignatureBase64 = Convert.ToBase64String(signature)
        };

        Assert.ThrowsExactly<CryptographicException>(
            () => SignedLicenseBackend.Verify(
                tampered,
                publicKey,
                "device-2",
                now));
    }

    [TestMethod]
    public void SignedUpdateManifestRejectsNonHttps()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var payload = new SignedUpdatePayload(
            "1.0.1",
            "QuietShield.exe",
            new string('A', 64),
            1024,
            new Uri("http://example.com/QuietShield.exe"),
            DateTimeOffset.UtcNow,
            "1.0.0");

        Assert.ThrowsExactly<InvalidDataException>(
            () => SecureUpdateManifest.SignForTesting(payload, key));
    }

    [TestMethod]
    public void FinalInvariantAuditorPassesOnlySafeState()
    {
        var report = FinalBackendInvariantAuditor.Audit(new(
            ParentChildPolicyValidated: true,
            PrivateBrowserPolicyValidated: true,
            FileSafetyValidated: true,
            LicensingSignatureValidated: true,
            UpdateSignatureValidated: true,
            SystemDnsActivationStillGated: true,
            BroadFirewallMutationDetected: false,
            UnsignedUpdateAccepted: false,
            ChildPolicyTamperAccepted: false));

        Assert.IsTrue(report.Passed);
        Assert.IsEmpty(report.Failures);
    }

    private static ChildProtectionPolicy CreateChildPolicy() =>
        new(
            "child-test",
            "Child test",
            true,
            Array.Empty<string>(),
            Array.Empty<string>(),
            Array.Empty<string>(),
            Array.Empty<DailyAccessWindow>(),
            false,
            true);
}
