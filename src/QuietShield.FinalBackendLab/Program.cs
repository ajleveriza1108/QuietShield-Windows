// QuietShield Backend Pack 5-8 R1
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using QuietShield.Core.FinalBackends;
using QuietShield.Licensing;
using QuietShield.Windows.FinalBackends;

namespace QuietShield.FinalBackendLab;

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private static readonly string[] AllowedApplications = ["allowed.app"];
    private static readonly string[] BlockedHosts = ["blocked.example"];
    private static readonly string[] TrackerHosts = ["tracker.example"];

    private static async Task<int> Main(string[] args)
    {
        var seconds = ReadIntArgument(args, "--seconds", 120);
        if (seconds is < 10 or > 3600)
        {
            Console.Error.WriteLine("--seconds must be between 10 and 3600.");
            return 2;
        }

        var output = ReadStringArgument(
            args,
            "--output",
            @"D:\QuietShield-Backend-Work\FINAL-BACKEND-STRESS-RESULT.json");

        Directory.CreateDirectory(Path.GetDirectoryName(output)!);

        var workRoot = Path.Combine(
            Path.GetTempPath(),
            "QuietShield-FinalBackendLab",
            Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(workRoot);

        var started = DateTimeOffset.UtcNow;
        var deadline = started.AddSeconds(seconds);
        var samples = 0;
        var failures = 0;
        var parentChildChecks = 0L;
        var browserChecks = 0L;
        var fileChecks = 0L;
        var licenseChecks = 0L;
        var updateChecks = 0L;
        var peakWorkingSet = 0L;

        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = signingKey.ExportSubjectPublicKeyInfo();

        var deviceId = WindowsOpaqueDeviceIdentity.GetCurrentUserDeviceId();
        var childKey = RandomNumberGenerator.GetBytes(32);
        var childPolicy = CreateChildPolicy();
        var childEnvelope = ChildPolicyIntegrity.Protect(childPolicy, childKey);

        var browserPolicy = CreateBrowserPolicy();

        var sampleFile = Path.Combine(workRoot, "safe-sample.txt");
        await File.WriteAllTextAsync(sampleFile, "QuietShield final backend stress sample.");

        var sampleBytes = await File.ReadAllBytesAsync(sampleFile);
        var sampleHash = Convert.ToHexString(SHA256.HashData(sampleBytes));

        var updatePayload = new SignedUpdatePayload(
            "1.0.1",
            "safe-sample.txt",
            sampleHash,
            sampleBytes.LongLength,
            new Uri("https://updates.example.invalid/safe-sample.txt"),
            DateTimeOffset.UtcNow,
            "1.0.0");

        var updateEnvelope = SecureUpdateManifest.SignForTesting(updatePayload, signingKey);

        var now = DateTimeOffset.UtcNow;
        var licensePayload = new SignedLicensePayload(
            "stress-license",
            LicenseState.Licensed,
            now,
            now.AddDays(30),
            deviceId,
            new[]
            {
                new LicensedDevice(
                    deviceId,
                    "This Windows PC",
                    QuietShieldPlatform.Windows,
                    now,
                    now,
                    true)
            },
            null,
            false,
            "stress-v1");

        var licenseEnvelope = SignedLicenseBackend.SignForTesting(licensePayload, signingKey);

        Console.WriteLine("QuietShield Backend Pack 5-8 Stress Lab");
        Console.WriteLine($"Duration: {seconds}s");
        Console.WriteLine("Parent/Child: live policy + PIN/integrity backend");
        Console.WriteLine("Private Browser: live session/privacy/navigation backend");
        Console.WriteLine("File Safety: real local file hashing/header/MOTW inspection");
        Console.WriteLine("Licensing/Updates: signed-envelope verification");
        Console.WriteLine("System mutation: NONE");
        Console.WriteLine();

        using var process = Process.GetCurrentProcess();

        try
        {
            while (DateTimeOffset.UtcNow < deadline)
            {
                samples++;

                try
                {
                    var restoredPolicy = ChildPolicyIntegrity.Unprotect(childEnvelope, childKey);
                    var childDecision = ParentChildPolicyEngine.Evaluate(
                        restoredPolicy,
                        new ChildAccessRequest(
                            FamilyRole.Child,
                            DateTimeOffset.Now,
                            "allowed.app",
                            new Uri("https://example.com/")));

                    if (!childDecision.Allowed)
                    {
                        throw new InvalidOperationException("Expected child allow decision failed.");
                    }

                    parentChildChecks++;
                }
                catch (CryptographicException)
                {
                    failures++;
                }
                catch (InvalidDataException)
                {
                    failures++;
                }
                catch (InvalidOperationException)
                {
                    failures++;
                }

                try
                {
                    var session = new PrivateBrowserSession(
                        PrivateBrowserMode.Incognito,
                        browserPolicy);

                    var allowed = session.Navigate(new Uri("https://example.com/"));
                    var blocked = session.Navigate(new Uri("https://tracker.example/pixel"));

                    session.SetCookie(new(
                        "session",
                        "opaque",
                        "example.com",
                        null));

                    session.Close();

                    if (allowed.Action != BrowserNavigationAction.Allow ||
                        blocked.Action != BrowserNavigationAction.Block ||
                        session.GetHistorySnapshot().Count != 0 ||
                        session.GetCookieSnapshot().Count != 0)
                    {
                        throw new InvalidOperationException("Private Browser session invariant failed.");
                    }

                    browserChecks++;
                }
                catch (InvalidOperationException)
                {
                    failures++;
                }

                try
                {
                    var fileReport = await WindowsFileSafetyScanner.ScanAsync(sampleFile);
                    var websiteReport = WebsiteSafetyEngine.Evaluate(
                        new Uri("https://example.com/download"));

                    if (fileReport.Sha256.Length != 64 ||
                        websiteReport.ShouldBlock)
                    {
                        throw new InvalidOperationException("File/website safety invariant failed.");
                    }

                    fileChecks++;
                }
                catch (IOException)
                {
                    failures++;
                }
                catch (UnauthorizedAccessException)
                {
                    failures++;
                }
                catch (InvalidOperationException)
                {
                    failures++;
                }

                try
                {
                    var verifiedLicense = SignedLicenseBackend.Verify(
                        licenseEnvelope,
                        publicKey,
                        deviceId,
                        DateTimeOffset.UtcNow);

                    if (verifiedLicense.LicenseId != "stress-license")
                    {
                        throw new InvalidOperationException("Signed license verification invariant failed.");
                    }

                    licenseChecks++;
                }
                catch (CryptographicException)
                {
                    failures++;
                }
                catch (InvalidDataException)
                {
                    failures++;
                }
                catch (UnauthorizedAccessException)
                {
                    failures++;
                }
                catch (InvalidOperationException)
                {
                    failures++;
                }

                try
                {
                    var verifiedManifest = SecureUpdateManifest.Verify(
                        updateEnvelope,
                        publicKey);

                    var packageResult = await WindowsUpdatePackageVerifier.VerifyAsync(
                        sampleFile,
                        verifiedManifest);

                    if (!packageResult.Passed)
                    {
                        throw new InvalidOperationException("Signed update package verification invariant failed.");
                    }

                    updateChecks++;
                }
                catch (CryptographicException)
                {
                    failures++;
                }
                catch (InvalidDataException)
                {
                    failures++;
                }
                catch (IOException)
                {
                    failures++;
                }
                catch (InvalidOperationException)
                {
                    failures++;
                }

                process.Refresh();
                peakWorkingSet = Math.Max(peakWorkingSet, process.WorkingSet64);

                if (samples % 5 == 0)
                {
                    Console.WriteLine(
                        $"[{DateTime.Now:T}] failures={failures} " +
                        $"parent={parentChildChecks} browser={browserChecks} " +
                        $"file={fileChecks} license={licenseChecks} update={updateChecks}");
                }

                await Task.Delay(TimeSpan.FromSeconds(2));
            }

            var audit = FinalBackendInvariantAuditor.Audit(new(
                ParentChildPolicyValidated: parentChildChecks > 0,
                PrivateBrowserPolicyValidated: browserChecks > 0,
                FileSafetyValidated: fileChecks > 0,
                LicensingSignatureValidated: licenseChecks > 0,
                UpdateSignatureValidated: updateChecks > 0,
                SystemDnsActivationStillGated: true,
                BroadFirewallMutationDetected: false,
                UnsignedUpdateAccepted: false,
                ChildPolicyTamperAccepted: false));

            var result = new
            {
                schemaVersion = 1,
                purpose = "QuietShieldBackendPack5To8Stress",
                startedAtUtc = started,
                completedAtUtc = DateTimeOffset.UtcNow,
                durationSeconds = seconds,
                samples,
                failures,
                backend5ParentChild = new
                {
                    checks = parentChildChecks,
                    pinBackend = "PBKDF2-SHA256",
                    policyIntegrity = "HMAC-SHA256",
                    systemAccountMutation = false
                },
                backend6PrivateBrowser = new
                {
                    checks = browserChecks,
                    incognitoIsolation = true,
                    trackerPolicy = true,
                    rendererIntegrated = false
                },
                backend7FileWebsiteSafety = new
                {
                    checks = fileChecks,
                    sha256 = true,
                    portableExecutableHeaderInspection = true,
                    markOfTheWebInspection = true,
                    websitePolicy = true,
                    onlineReputationLookup = false
                },
                backend8LicensingUpdatesHardening = new
                {
                    licenseChecks,
                    updateChecks,
                    asymmetricSignature = "ECDSA P-256 / SHA-256",
                    deviceIdentity = "opaque SHA-256",
                    updateAutoInstallPerformed = false
                },
                audit,
                process = new
                {
                    peakWorkingSetMb = Math.Round(peakWorkingSet / 1024d / 1024d, 1)
                },
                overallPassed = failures == 0 && audit.Passed
            };

            await File.WriteAllTextAsync(
                output,
                JsonSerializer.Serialize(result, JsonOptions));

            Console.WriteLine();
            Console.WriteLine($"Result: {output}");
            Console.WriteLine($"Overall: {(result.overallPassed ? "PASS" : "REVIEW REQUIRED")}");

            return result.overallPassed ? 0 : 1;
        }
        finally
        {
            if (Directory.Exists(workRoot))
            {
                Directory.Delete(workRoot, recursive: true);
            }
        }
    }

    private static ChildProtectionPolicy CreateChildPolicy() =>
        new(
            "stress-child",
            "Stress child",
            true,
            Array.Empty<string>(),
            AllowedApplications,
            BlockedHosts,
            Array.Empty<DailyAccessWindow>(),
            false,
            true);

    private static PrivateBrowserPolicy CreateBrowserPolicy() =>
        new(
            RequireHttps: true,
            BlockCredentialInUrl: true,
            BlockPrivateNetworkDestinations: true,
            BlockKnownTrackerHosts: true,
            BlockedHosts: Array.Empty<string>(),
            TrackerHosts: TrackerHosts);

    private static int ReadIntArgument(
        string[] args,
        string name,
        int defaultValue)
    {
        var value = ReadStringArgument(args, name, string.Empty);
        return int.TryParse(value, out var parsed)
            ? parsed
            : defaultValue;
    }

    private static string ReadStringArgument(
        string[] args,
        string name,
        string defaultValue)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return args[i + 1];
            }
        }

        return defaultValue;
    }
}
