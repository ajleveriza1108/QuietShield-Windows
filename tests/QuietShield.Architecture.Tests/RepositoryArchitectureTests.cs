using System.Xml.Linq;

namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class RepositoryArchitectureTests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void CoreProjectIsPlatformIndependentAndDependencyFree()
    {
        var projectPath = Path.Combine(RepositoryRoot, "src", "QuietShield.Core", "QuietShield.Core.csproj");
        var document = XDocument.Load(projectPath);
        var targetFramework = document.Descendants("TargetFramework").Single().Value;

        Assert.AreEqual("net10.0", targetFramework);
        Assert.IsFalse(document.Descendants("UseWPF").Any());
        Assert.IsFalse(document.Descendants("UseWindowsForms").Any());
        Assert.IsFalse(document.Descendants("ProjectReference").Any());
        Assert.IsFalse(document.Descendants("PackageReference").Any());
    }

    [TestMethod]
    public void CoreSourceContainsNoPlatformSpecificDependency()
    {
        var coreDirectory = Path.Combine(RepositoryRoot, "src", "QuietShield.Core");
        var forbiddenFragments = new[]
        {
            "System.Windows",
            "Microsoft.Win32",
            "System.ServiceProcess",
            "System.Net.NetworkInformation",
            "System.Management",
            "Windows.Win32",
            "RegistryKey",
            "Firewall"
        };

        foreach (var file in Directory.EnumerateFiles(coreDirectory, "*.cs", SearchOption.AllDirectories))
        {
            var source = File.ReadAllText(file);
            foreach (var fragment in forbiddenFragments)
            {
                Assert.IsFalse(
                    source.Contains(fragment, StringComparison.Ordinal),
                    $"{Path.GetRelativePath(RepositoryRoot, file)} contains forbidden Core dependency '{fragment}'.");
            }
        }
    }

    [TestMethod]
    public void ProductionProjectReferencesFollowTheApprovedDirection()
    {
        var expected = new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["QuietShield.App"] = new[] { "QuietShield.Core", "QuietShield.Licensing", "QuietShield.Windows" },
            ["QuietShield.Core"] = Array.Empty<string>(),
            ["QuietShield.Licensing"] = Array.Empty<string>(),
            ["QuietShield.Service"] = new[] { "QuietShield.Core", "QuietShield.Windows" },
            ["QuietShield.Windows"] = new[] { "QuietShield.Core" },
            ["QuietShield.DnsHost"] = new[] { "QuietShield.Core", "QuietShield.Windows" },
            ["QuietShield.DnsWatchdog"] = new[] { "QuietShield.Core" }
        };

        foreach (var projectPath in Directory.EnumerateFiles(
                     Path.Combine(RepositoryRoot, "src"),
                     "*.csproj",
                     SearchOption.AllDirectories))
        {
            var projectName = Path.GetFileNameWithoutExtension(projectPath);
            var document = XDocument.Load(projectPath);
            var references = document.Descendants("ProjectReference")
                .Select(static element => element.Attribute("Include")?.Value)
                .Where(static include => !string.IsNullOrWhiteSpace(include))
                .Select(include => Path.GetFileNameWithoutExtension(
                    Path.GetFullPath(Path.Combine(Path.GetDirectoryName(projectPath)!, include!))))
                .OrderBy(static name => name, StringComparer.Ordinal)
                .ToArray();

            CollectionAssert.AreEqual(
                expected[projectName].OrderBy(static name => name, StringComparer.Ordinal).ToArray(),
                references,
                $"Unexpected dependency direction in {projectName}.");
        }
    }

    [TestMethod]
    public void CentralPackageInventoryContainsOnlyApprovedPackages()
    {
        var document = XDocument.Load(Path.Combine(RepositoryRoot, "Directory.Packages.props"));
        var packages = document.Descendants("PackageVersion")
            .Select(static element => new
            {
                Name = element.Attribute("Include")?.Value,
                Version = element.Attribute("Version")?.Value
            })
            .OrderBy(static package => package.Name, StringComparer.Ordinal)
            .ToArray();

        Assert.HasCount(2, packages);
        var hosting = packages.Single(static package => package.Name == "Microsoft.Extensions.Hosting");
        var testFramework = packages.Single(static package => package.Name == "MSTest");
        Assert.AreEqual("10.0.10", hosting.Version);
        Assert.AreEqual("4.0.2", testFramework.Version);

        foreach (var project in Directory.EnumerateFiles(RepositoryRoot, "*.csproj", SearchOption.AllDirectories))
        {
            var projectDocument = XDocument.Load(project);
            Assert.IsFalse(
                projectDocument.Descendants("PackageReference").Any(
                    static reference => reference.Attribute("Version") is not null),
                $"Package version must be centralized: {Path.GetRelativePath(RepositoryRoot, project)}");
        }
    }

    [TestMethod]
    public void ApplicationManifestRequestsNoElevation()
    {
        var manifest = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "app.manifest"));

        StringAssert.Contains(manifest, "level=\"asInvoker\"");
        Assert.IsFalse(manifest.Contains("requireAdministrator", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(manifest.Contains("highestAvailable", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void ScriptsContainNoElevationOrSystemMutationCommand()
    {
        var forbiddenFragments = new[]
        {
            "-Verb RunAs",
            "Set-NetFirewall",
            "New-NetFirewall",
            "Remove-NetFirewall",
            "Set-DnsClient",
            "Disable-NetAdapter",
            "Enable-NetAdapter",
            "New-Service",
            "Set-Service",
            "sc.exe create",
            "Set-ItemProperty",
            "New-ItemProperty",
            "Import-Certificate",
            "Remove-Item Cert:",
            "dotnet dev-certs"
        };

        foreach (var script in Directory.EnumerateFiles(
                     Path.Combine(RepositoryRoot, "scripts"),
                     "*.ps1",
                     SearchOption.AllDirectories))
        {
            var content = File.ReadAllText(script);
            foreach (var fragment in forbiddenFragments)
            {
                if (new[] { "Restore-OriginalDns.ps1", "Restore-RehearsalDns.ps1", "Invoke-DnsActivationRehearsal.ps1" }
                        .Contains(Path.GetFileName(script), StringComparer.OrdinalIgnoreCase) &&
                    fragment.Equals("Set-DnsClient", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                Assert.IsFalse(
                    content.Contains(fragment, StringComparison.OrdinalIgnoreCase),
                    $"{Path.GetRelativePath(RepositoryRoot, script)} contains forbidden command fragment '{fragment}'.");
            }
        }
    }

    [TestMethod]
    public void EmergencyDnsRestoreIsNarrowValidatedManualAndNeverSelfElevates()
    {
        var restore = File.ReadAllText(Path.Combine(RepositoryRoot, "scripts", "Restore-OriginalDns.ps1"));
        foreach (var required in new[]
        {
            "SupportsShouldProcess = $true", "Test-QuietShieldDnsBackup", "Test-QuietShieldDnsAdapterIdentities",
            "ExplicitUserApproval", "Test-QuietShieldAdministrator", "Set-DnsClientServerAddress", "ResetServerAddresses",
            "ServerAddresses $originalServers", "never self-elevates"
        })
        {
            StringAssert.Contains(restore, required);
        }
        Assert.IsFalse(restore.Contains("-Verb RunAs", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(restore.Contains("Start-Process", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(restore.Contains("New-NetFirewall", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(restore.Contains("Set-NetIPInterface", StringComparison.OrdinalIgnoreCase));

        var launcher = File.ReadAllText(Path.Combine(RepositoryRoot, "Emergency-Restore-Dns.bat"));
        StringAssert.Contains(launcher, "Restore-OriginalDns.ps1");
        StringAssert.Contains(launcher, "Manual emergency entry point only");
        foreach (var automaticLauncher in new[] { "Build-QuietShield.bat", "Test-QuietShield.bat", "Run-QuietShield.bat", "Validate-QuietShield.bat" })
        {
            var source = File.ReadAllText(Path.Combine(RepositoryRoot, automaticLauncher));
            Assert.IsFalse(source.Contains("Emergency-Restore-Dns", StringComparison.OrdinalIgnoreCase));
            Assert.IsFalse(source.Contains("Restore-OriginalDns", StringComparison.OrdinalIgnoreCase));
        }
    }

    [TestMethod]
    public void ServiceProjectHasNoRegistrationPackageOrConfiguration()
    {
        var projectPath = Path.Combine(RepositoryRoot, "src", "QuietShield.Service", "QuietShield.Service.csproj");
        var content = File.ReadAllText(projectPath);

        Assert.IsFalse(content.Contains("WindowsServices", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(content.Contains("ServiceName", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(content.Contains("UseWindowsService", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void RehearsalHostAndWatchdogCannotRegisterPermanentServices()
    {
        foreach (var project in new[] { "QuietShield.DnsHost", "QuietShield.DnsWatchdog" })
        {
            var directory = Path.Combine(RepositoryRoot, "src", project);
            var content = string.Join(Environment.NewLine,
                Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
                    .Where(static path => Path.GetExtension(path) is ".cs" or ".csproj")
                    .Select(File.ReadAllText));
            foreach (var forbidden in new[] { "UseWindowsService", "WindowsServices", "ServiceInstaller", "ServiceName", "sc.exe", "New-Service" })
            {
                Assert.IsFalse(content.Contains(forbidden, StringComparison.OrdinalIgnoreCase), $"{project} contains permanent service-registration fragment '{forbidden}'.");
            }
        }
    }

    [TestMethod]
    public void RehearsalMutationSurfaceIsNarrowAndNeverSelfElevates()
    {
        var invoke = File.ReadAllText(Path.Combine(RepositoryRoot, "scripts", "Invoke-DnsActivationRehearsal.ps1"));
        var restore = File.ReadAllText(Path.Combine(RepositoryRoot, "scripts", "Restore-RehearsalDns.ps1"));
        var launcher = File.ReadAllText(Path.Combine(RepositoryRoot, "Run-DnsActivationRehearsal.bat"));
        foreach (var source in new[] { invoke, restore, launcher })
        {
            Assert.IsFalse(source.Contains("-Verb RunAs", StringComparison.OrdinalIgnoreCase));
            Assert.IsFalse(source.Contains("Start-Process powershell", StringComparison.OrdinalIgnoreCase));
            foreach (var forbidden in new[] { "Set-NetFirewall", "New-NetFirewall", "Remove-NetFirewall", "Set-NetIPInterface", "Disable-NetAdapter", "Enable-NetAdapter", "Set-ItemProperty", "New-ItemProperty" })
            {
                Assert.IsFalse(source.Contains(forbidden, StringComparison.OrdinalIgnoreCase), $"Rehearsal source contains unrelated mutation '{forbidden}'.");
            }
        }
        StringAssert.Contains(invoke, "-ApprovedTemporaryActivation");
        StringAssert.Contains(invoke, "Set-DnsClientServerAddress");
        StringAssert.Contains(restore, "Test-QuietShieldRehearsalBackup");
        StringAssert.Contains(restore, "Test-QuietShieldAdapterIsExactRehearsalMatch");
    }

    [TestMethod]
    public void RehearsalAdapterBindingLookupIsPowerShell51CompatibleAndIdentityChecked()
    {
        var invoke = File.ReadAllText(Path.Combine(RepositoryRoot, "scripts", "Invoke-DnsActivationRehearsal.ps1"));
        Assert.IsFalse(
            System.Text.RegularExpressions.Regex.IsMatch(
                invoke,
                @"Get-NetAdapterBinding\s+-InterfaceIndex",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase),
            "Get-NetAdapterBinding must never be invoked with the unsupported -InterfaceIndex parameter.");
        foreach (var required in new[]
        {
            "[string]::IsNullOrWhiteSpace($adapterName)",
            "Get-NetAdapter -Name $adapterName",
            "$namedAdapters.Count -ne 1",
            "$namedAdapters[0].InterfaceIndex -ne [int]$selected.Adapter.InterfaceIndex",
            "Get-NetAdapterBinding -Name $adapterName -ComponentID 'ms_tcpip6'"
        })
        {
            StringAssert.Contains(invoke, required);
        }
    }

    [TestMethod]
    public void RehearsalRestorationComparisonPreservesDuplicatesAndOrder()
    {
        var commonPath = Path.Combine(RepositoryRoot, "scripts", "DnsTransaction.Script.Common.ps1").Replace("'", "''", StringComparison.Ordinal);
        var command = $". '{commonPath}'; " +
            "if (-not (Test-QuietShieldStringArrayExact -Expected @('a','b','a') -Actual @('a','b','a'))) { exit 1 }; " +
            "if (Test-QuietShieldStringArrayExact -Expected @('a','b','a') -Actual @('a','b')) { exit 2 }; " +
            "if (Test-QuietShieldStringArrayExact -Expected @('a','b','a') -Actual @('a','a','b')) { exit 3 }; exit 0";
        var start = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-Command");
        start.ArgumentList.Add(command);
        using var process = System.Diagnostics.Process.Start(start);
        Assert.IsNotNull(process);
        Assert.IsTrue(process.WaitForExit(10_000), "PowerShell restoration comparison regression test timed out.");
        Assert.AreEqual(0, process.ExitCode, process.StandardError.ReadToEnd());

        var restore = File.ReadAllText(Path.Combine(RepositoryRoot, "scripts", "Restore-RehearsalDns.ps1"));
        StringAssert.Contains(restore, "$servers = @($family.serverAddresses");
        StringAssert.Contains(restore, "-ServerAddresses $servers");
        StringAssert.Contains(restore, "Test-QuietShieldStringArrayExact -Expected @($family.serverAddresses) -Actual @($current[0].ServerAddresses)");
    }

    [TestMethod]
    public void PowerShell51BackupValidatorAcceptsAndHashesOrderedDuplicateDnsValues()
    {
        var commonPath = Path.Combine(RepositoryRoot, "scripts", "DnsTransaction.Script.Common.ps1").Replace("'", "''", StringComparison.Ordinal);
        var fixturePath = Path.Combine(RepositoryRoot, "tests", "Fixtures", "phase5-duplicate-backup.json").Replace("'", "''", StringComparison.Ordinal);
        var command = $". '{commonPath}'; " +
            $"$validated = Test-QuietShieldRehearsalBackup -BackupPath '{fixturePath}'; " +
            "$ipv4 = @($validated.Backup.adapter.families | Where-Object { [string]$_.addressFamily -ceq 'IPv4' })[0]; " +
            "$ipv6 = @($validated.Backup.adapter.families | Where-Object { [string]$_.addressFamily -ceq 'IPv6' })[0]; " +
            "if (@($ipv4.serverAddresses).Count -ne 3) { exit 1 }; " +
            "if ([string]$ipv4.serverAddresses[0] -cne [string]$ipv4.serverAddresses[2]) { exit 2 }; " +
            "if (-not [bool]$ipv6.automatic -or @($ipv6.serverAddresses).Count -ne 2) { exit 3 }; " +
            "if ([string]$ipv6.serverAddresses[0] -cne [string]$ipv6.serverAddresses[1]) { exit 4 }; exit 0";
        var start = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-Command");
        start.ArgumentList.Add(command);
        using var process = System.Diagnostics.Process.Start(start);
        Assert.IsNotNull(process);
        Assert.IsTrue(process.WaitForExit(10_000), "PowerShell duplicate-backup validator regression test timed out.");
        Assert.AreEqual(0, process.ExitCode, process.StandardError.ReadToEnd());
    }

    [TestMethod]
    public void PowerShell51RawRcodeRecognitionRequiresExactNxdomainResponse()
    {
        var commonPath = Path.Combine(RepositoryRoot, "scripts", "DnsTransaction.Script.Common.ps1").Replace("'", "''", StringComparison.Ordinal);
        var command = $". '{commonPath}'; " +
            "$valid = [pscustomobject]@{ protocol='Udp'; queriedName='quietshield-blocked.test'; responseQuestionName='quietshield-blocked.test'; expectedTransactionId=4660; responseTransactionId=4660; isResponse=$true; responseCode=3; validationSucceeded=$true; passed=$true }; " +
            "if (-not (Test-QuietShieldRawDnsProbeResult -Result $valid -Protocol 'Udp')) { exit 1 }; " +
            "$invalid = $valid.PSObject.Copy(); $invalid.responseCode = 2; " +
            "try { [void](Test-QuietShieldRawDnsProbeResult -Result $invalid -Protocol 'Udp'); exit 2 } catch { exit 0 }";
        var start = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-Command");
        start.ArgumentList.Add(command);
        using var process = System.Diagnostics.Process.Start(start);
        Assert.IsNotNull(process);
        Assert.IsTrue(process.WaitForExit(10_000), "PowerShell raw-RCODE recognition regression test timed out.");
        Assert.AreEqual(0, process.ExitCode, process.StandardError.ReadToEnd());
    }

    [TestMethod]
    public void HostReadinessRequiresLoadedPolicyAndRawUdpTcpSelfTests()
    {
        var host = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.DnsHost", "Program.cs"));
        foreach (var required in new[]
        {
            "PolicySnapshotLoaded", "policySnapshot.Loaded", "EnsureBlockedSelfTest(udpSelfTest)",
            "EnsureBlockedSelfTest(tcpSelfTest)", "policySnapshotLoaded = policySnapshot.Loaded",
            "udpBlockedRcode", "tcpBlockedRcode", "NormalizedBlockedTestDomain"
        })
        {
            StringAssert.Contains(host, required);
        }
        Assert.IsLessThan(host.IndexOf("purpose = \"DnsRehearsalHostReady\"", StringComparison.Ordinal), host.IndexOf("EnsureBlockedSelfTest(tcpSelfTest)", StringComparison.Ordinal));
    }

    [TestMethod]
    public void RehearsalAttemptsAreAppendOnlyConcurrentSafeAndPreChangeFailureIsNotCompletion()
    {
        var invoke = File.ReadAllText(Path.Combine(RepositoryRoot, "scripts", "Invoke-DnsActivationRehearsal.ps1"));
        StringAssert.Contains(invoke, "Global\\QuietShieldDnsActivationRehearsal");
        StringAssert.Contains(invoke, "ApprovedTemporaryActivation");
        StringAssert.Contains(invoke, "attempt-records.jsonl");
        StringAssert.Contains(invoke, "Add-Content -LiteralPath $script:attemptRecordsPath");
        StringAssert.Contains(invoke, "FailedBeforeDnsChange");
        StringAssert.Contains(invoke, "CompletedActivationRehearsal");
        Assert.IsFalse(invoke.Contains("rehearsal-attempted.marker", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(invoke.Contains("Set-Content -LiteralPath $attemptRecordsPath", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void RehearsalDnsHostUsesExplicitOriginalUpstreamsAndNoSystemResolver()
    {
        var host = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.DnsHost", "Program.cs"));
        StringAssert.Contains(host, "Original adapter DNS");
        StringAssert.Contains(host, "ApprovedTemporaryPort53Rehearsal");
        StringAssert.Contains(host, "IPAddress.Loopback");
        Assert.IsFalse(host.Contains("System.Net.Dns", StringComparison.Ordinal));
        Assert.IsFalse(host.Contains("GetHostAddresses", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Phase2DependencyInjectionRegistersOnlyReadOnlyDiscoveryImplementations()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "App.xaml.cs"));
        foreach (var required in new[]
        {
            "ApplicationInventoryService", "ReadOnlyNetworkEnvironmentDiscovery", "ReadOnlyDnsConfigurationDiscovery",
            "ReadOnlyFirewallStateDiscovery", "ReadOnlyFilteringPlatformCapabilityDiscovery",
            "ReadOnlyWindowsServiceStateDiscovery", "ReadOnlyPowerStateDiscovery", "ReadOnlyDiscoveryCoordinator"
        })
        {
            StringAssert.Contains(source, required);
        }

        foreach (var forbidden in new[]
        {
            "DeferredInstalledApplicationDiscovery", "DeferredFirewallStateDiscovery", "DeferredFilteringPlatformCapabilityDiscovery",
            "ITransactionalWindowsChange<", "InstallCleanup", "Set-NetFirewall", "Set-DnsClient"
        })
        {
            Assert.IsFalse(source.Contains(forbidden, StringComparison.OrdinalIgnoreCase), $"App dependency injection contains forbidden implementation or mutation fragment '{forbidden}'.");
        }
    }

    [TestMethod]
    public void Phase3DependencyInjectionRegistersOnlyInMemoryDnsSimulationServices()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "App.xaml.cs"));
        foreach (var required in new[]
        {
            "NonProductionSampleSignatureVerifier", "InMemoryProtectionListStore", "ProtectionListActivator",
            "InMemoryCustomDomainListService", "InMemoryDnsDecisionCache"
        })
        {
            StringAssert.Contains(source, required);
        }

        foreach (var forbidden in new[]
        {
            "LoopbackDiagnosticDnsListener", "ReadOnlySystemDnsResolver", "DeferredUpstreamDnsResolver",
            "FoundationDnsOverHttpsCapabilityProvider", "IDiagnosticDnsListener", "ISystemDnsResolver",
            "IUpstreamDnsResolver", "Set-DnsClient", "DnsClientServerAddress"
        })
        {
            Assert.IsFalse(
                source.Contains(forbidden, StringComparison.OrdinalIgnoreCase),
                $"App dependency injection contains a diagnostic, resolver, or modifying DNS implementation '{forbidden}'.");
        }
    }

    [TestMethod]
    public void DiagnosticDnsListenerSourceIsLoopbackOnlyDynamicAndNeverPort53()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.Windows", "Dns", "ResolverFoundations.cs"));

        StringAssert.Contains(source, "IPAddress.Loopback, 0");
        Assert.IsFalse(source.Contains("IPAddress.Any", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("IPAddress.IPv6Any", StringComparison.Ordinal));
        Assert.IsFalse(source.Contains("Loopback, 53", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Phase4RuntimeIsLoopbackBoundedAndNotStartedByApplicationComposition()
    {
        var runtime = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.Windows", "Dns", "LocalDnsRuntime.cs"));
        StringAssert.Contains(runtime, "IPAddress.IsLoopback");
        StringAssert.Contains(runtime, "ListenPort is > 0 and <= 1023");
        StringAssert.Contains(runtime, "MaximumConcurrentRequests");
        StringAssert.Contains(runtime, "QueryTimeout");
        Assert.IsFalse(runtime.Contains("System.Net.Dns", StringComparison.Ordinal));
        Assert.IsFalse(runtime.Contains("GetHostAddresses", StringComparison.Ordinal));

        var composition = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "App.xaml.cs"));
        foreach (var forbidden in new[]
        {
            "AddSingleton<ILocalDnsRuntime,", "AddHostedService<DnsRuntimeServiceCoordinator", "SafeDnsUpstreamResolver",
            "SocketDnsUpstreamTransport", "IDnsConfigurationMutator", "DnsTransactionCoordinator"
        })
        {
            Assert.IsFalse(composition.Contains(forbidden, StringComparison.Ordinal), $"Application composition starts or registers forbidden Phase 4 runtime component '{forbidden}'.");
        }
        StringAssert.Contains(composition, "ILocalDnsRuntimeDiagnostic, LocalDnsRuntimeDiagnostic");
    }

    [TestMethod]
    public void NoProductionDnsMutatorImplementationOrActivationControlExists()
    {
        foreach (var project in new[] { "QuietShield.App", "QuietShield.Windows", "QuietShield.Service" })
        {
            foreach (var file in Directory.EnumerateFiles(Path.Combine(RepositoryRoot, "src", project), "*.cs", SearchOption.AllDirectories))
            {
                var source = File.ReadAllText(file);
                Assert.IsFalse(source.Contains(": IDnsConfigurationMutator", StringComparison.Ordinal), $"A production DNS mutator implementation exists in {Path.GetRelativePath(RepositoryRoot, file)}.");
                Assert.IsFalse(source.Contains("IWindowsDnsChangeApplier", StringComparison.Ordinal), $"A modifying Windows DNS applier exists in {Path.GetRelativePath(RepositoryRoot, file)}.");
            }
        }

        var xaml = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "MainWindow.xaml"));
        Assert.IsFalse(xaml.Contains("Content=\"Activate\"", StringComparison.OrdinalIgnoreCase));
        StringAssert.Contains(xaml, "Preview activation plan");

        var serviceProgram = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.Service", "Program.cs"));
        Assert.IsFalse(serviceProgram.Contains("DnsRuntimeServiceCoordinator", StringComparison.Ordinal));
        Assert.IsFalse(serviceProgram.Contains("UseWindowsService", StringComparison.Ordinal));
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "QuietShield.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate the QuietShield repository root.");
    }
}
