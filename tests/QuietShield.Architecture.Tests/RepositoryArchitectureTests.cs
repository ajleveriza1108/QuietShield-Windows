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
            "NetFwTypeLib",
            "INetFw",
            "WindowsFirewallHelper",
            "Set-NetFirewall",
            "New-NetFirewall",
            "Remove-NetFirewall"
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
            ["QuietShield.ConnectionProbe"] = Array.Empty<string>(),
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
                if (Path.GetFileName(script).Equals("Invoke-ProgramLockFirewallRehearsal.ps1", StringComparison.OrdinalIgnoreCase) &&
                    fragment.Equals("New-NetFirewall", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                if (Path.GetFileName(script).Equals("Restore-ProgramLockRehearsal.ps1", StringComparison.OrdinalIgnoreCase) &&
                    fragment.Equals("Remove-NetFirewall", StringComparison.OrdinalIgnoreCase))
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

        var xaml = string.Join(Environment.NewLine,
            Directory.EnumerateFiles(Path.Combine(RepositoryRoot, "src", "QuietShield.App"), "*.xaml", SearchOption.AllDirectories)
                .Select(File.ReadAllText));
        Assert.IsFalse(xaml.Contains("Content=\"Activate\"", StringComparison.OrdinalIgnoreCase));
        StringAssert.Contains(xaml, "Preview activation plan");

        var serviceProgram = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.Service", "Program.cs"));
        Assert.IsFalse(serviceProgram.Contains("DnsRuntimeServiceCoordinator", StringComparison.Ordinal));
        Assert.IsFalse(serviceProgram.Contains("UseWindowsService", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Phase6ShellUsesSharedResponsiveResourcesWithoutCanvasOrPositioningTricks()
    {
        var appDirectory = Path.Combine(RepositoryRoot, "src", "QuietShield.App");
        var mainWindow = File.ReadAllText(Path.Combine(appDirectory, "MainWindow.xaml"));
        var shell = File.ReadAllText(Path.Combine(appDirectory, "Controls", "ResponsivePageShell.xaml"));
        var allXaml = string.Join(Environment.NewLine,
            Directory.EnumerateFiles(appDirectory, "*.xaml", SearchOption.AllDirectories).Select(File.ReadAllText));

        StringAssert.Contains(mainWindow, "controls:ResponsivePageShell");
        StringAssert.Contains(mainWindow, "MinWidth=\"960\"");
        StringAssert.Contains(mainWindow, "MinHeight=\"600\"");
        StringAssert.Contains(shell, "HorizontalScrollBarVisibility=\"Disabled\"");
        StringAssert.Contains(shell, "VerticalScrollBarVisibility=\"Auto\"");
        Assert.IsFalse(allXaml.Contains("<Canvas", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(System.Text.RegularExpressions.Regex.IsMatch(allXaml, "Margin=\\\"\\s*-", System.Text.RegularExpressions.RegexOptions.IgnoreCase));
    }

    [TestMethod]
    public void SharedThemeCoversRequiredControlAndStateStyles()
    {
        var theme = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "Themes", "Controls.xaml"));
        foreach (var required in new[]
        {
            "PageTitleStyle", "SectionTitleStyle", "BodyTextStyle", "ExplanatoryTextStyle",
            "StatusBannerStyle", "CardStyle", "IconButtonStyle", "NavigationItemStyle",
            "DialogWindowStyle", "WarningBannerStyle", "SuccessBannerStyle", "InformationBannerStyle",
            "DisabledBannerStyle", "TargetType=\"Button\"", "TargetType=\"TextBox\"",
            "TargetType=\"ComboBox\"", "TargetType=\"ToggleButton\"", "TargetType=\"CheckBox\"",
            "TargetType=\"ListView\"", "TargetType=\"DataGrid\"", "TargetType=\"TabControl\"",
            "TargetType=\"ToolTip\""
        })
        {
            StringAssert.Contains(theme, required);
        }
    }

    [TestMethod]
    public void EveryPlannedPhase6PageIsPresentWithConsistentTerminology()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "ViewModels", "Phase2MainViewModel.cs"));
        foreach (var title in new[]
        {
            "Dashboard", "Protection", "Program Connection Lock", "Protection Profiles", "Schedules",
            "Metered and Cellular Data Watch", "Aggressive Program Watch", "Compatibility Guard",
            "DNS Protection", "Allowlist and Blocklist", "Activity and Statistics", "Parent and Child Controls",
            "Private Browser", "File Safety", "Licensing", "Updates", "Settings"
        })
        {
            StringAssert.Contains(source, $"new(\"{title}\"");
        }
        Assert.IsFalse(source.Contains("Android", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void InventoryAndFutureTablesUseVirtualizationAndLongTextAffordances()
    {
        var appDirectory = Path.Combine(RepositoryRoot, "src", "QuietShield.App");
        var inventory = File.ReadAllText(Path.Combine(appDirectory, "Pages", "ProgramConnectionLockPage.xaml"));
        var theme = File.ReadAllText(Path.Combine(appDirectory, "Themes", "Controls.xaml"));

        foreach (var required in new[]
        {
            "VirtualizingPanel.IsVirtualizing=\"True\"", "VirtualizingPanel.VirtualizationMode=\"Recycling\"",
            "VirtualizingStackPanel", "TrimmedValueTextStyle", "ToolTip=\"{Binding DisplayName}\"",
            "ToolTip=\"{Binding Publisher}\"", "No matching applications were found."
        })
        {
            StringAssert.Contains(inventory, required);
        }
        StringAssert.Contains(theme, "EnableRowVirtualization");
        StringAssert.Contains(theme, "EnableColumnVirtualization");
        StringAssert.Contains(theme, "Property=\"TextTrimming\" Value=\"CharacterEllipsis\"");
    }

    [TestMethod]
    public void DpiWindowPlacementAndDialogConstraintsAreDeclaredWithoutRegistryStorage()
    {
        var appDirectory = Path.Combine(RepositoryRoot, "src", "QuietShield.App");
        var manifest = File.ReadAllText(Path.Combine(appDirectory, "app.manifest"));
        var placement = File.ReadAllText(Path.Combine(appDirectory, "Windowing", "WindowPlacementServices.cs"));

        StringAssert.Contains(manifest, "PerMonitorV2");
        StringAssert.Contains(placement, "ConstrainWindowPlacement");
        StringAssert.Contains(placement, "ConstrainDialogSize");
        StringAssert.Contains(placement, "EnumDisplayMonitors");
        StringAssert.Contains(placement, "GetWindowPlacement");
        StringAssert.Contains(placement, "SetWindowPlacement");
        Assert.IsFalse(placement.Contains("Registry", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void Phase6GuiSmokeCoversResolutionsScalingLongTextKeyboardAndAllPages()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "Phase6GuiValidator.cs"));
        foreach (var required in new[]
        {
            "(1024d, 640d)", "(1366d, 768d)", "(1920d, 1080d)",
            "100, 125, 150, 200", "WindowState.Maximized", "ApplyPhase6LongTextScenario",
            "ValidateKeyboardReachability", "ScrollableWidth", "InventoryVirtualized", "UiResponsive"
        })
        {
            StringAssert.Contains(source, required);
        }
    }

    [TestMethod]
    public void Phase5BlockedRestrictionsRemainVisibleAcrossTheHardenedGui()
    {
        var appDirectory = Path.Combine(RepositoryRoot, "src", "QuietShield.App");
        var allXaml = string.Join(Environment.NewLine,
            Directory.EnumerateFiles(appDirectory, "*.xaml", SearchOption.AllDirectories).Select(File.ReadAllText));
        var dns = File.ReadAllText(Path.Combine(appDirectory, "Pages", "DnsProtectionPage.xaml"));

        StringAssert.Contains(dns, "DNS activation remains blocked");
        StringAssert.Contains(dns, "Permanent activation and service registration are prohibited");
        StringAssert.Contains(dns, "Real DNS activation remains unvalidated and disabled");
        Assert.IsFalse(System.Text.RegularExpressions.Regex.IsMatch(allXaml, "Content=\\\"_?Activate\\\"", System.Text.RegularExpressions.RegexOptions.IgnoreCase));
    }

    [TestMethod]
    public void ActionGroupsWrapAndInactiveStatesUseExplicitTextBanners()
    {
        var pages = Path.Combine(RepositoryRoot, "src", "QuietShield.App", "Pages");
        var dns = File.ReadAllText(Path.Combine(pages, "DnsProtectionPage.xaml"));
        var lists = File.ReadAllText(Path.Combine(pages, "DnsListsPage.xaml"));
        var foundation = File.ReadAllText(Path.Combine(pages, "FoundationStatusPages.xaml"));

        StringAssert.Contains(dns, "<WrapPanel");
        StringAssert.Contains(lists, "<WrapPanel");
        StringAssert.Contains(foundation, "<WrapPanel");
        StringAssert.Contains(dns, "activation remains blocked");
        StringAssert.Contains(lists, "simulation only");
        StringAssert.Contains(foundation, "Not yet active");
    }

    [TestMethod]
    public void Phase7RegistersNoModifyingWindowsEnforcementImplementation()
    {
        var appComposition = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "App.xaml.cs"));
        var phase7ViewModel = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "ViewModels", "Phase7ProgramConnectionLockViewModel.cs"));
        var planner = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.Windows", "Planning", "WindowsProgramEnforcementPlanner.cs"));
        foreach (var forbidden in new[]
        {
            "Set-NetFirewall", "New-NetFirewall", "Remove-NetFirewall", "Set-DnsClient",
            "FwpmFilterAdd", "INetFwRule", "netsh advfirewall", "CanExecute: true"
        })
        {
            Assert.IsFalse(appComposition.Contains(forbidden, StringComparison.OrdinalIgnoreCase), $"App composition contains prohibited Phase 7 mutator '{forbidden}'.");
            Assert.IsFalse(phase7ViewModel.Contains(forbidden, StringComparison.OrdinalIgnoreCase), $"Phase 7 view model contains prohibited mutator '{forbidden}'.");
            Assert.IsFalse(planner.Contains(forbidden, StringComparison.OrdinalIgnoreCase), $"Phase 7 planner contains prohibited mutator '{forbidden}'.");
        }
        Assert.IsFalse(appComposition.Contains("IReadOnlyWindowsProgramEnforcementPlanner", StringComparison.Ordinal));
        StringAssert.Contains(planner, "false");
        StringAssert.Contains(planner, "Administrator approval would be required");
    }

    [TestMethod]
    public void Phase7PagesAreResponsiveVirtualizedAndNeverExposeEnforcementButtons()
    {
        var pages = Path.Combine(RepositoryRoot, "src", "QuietShield.App", "Pages");
        var names = new[] { "ProgramConnectionLockPage.xaml", "ProtectionProfilesPage.xaml", "SchedulesPage.xaml", "CompatibilityGuardPage.xaml" };
        var source = string.Join(Environment.NewLine, names.Select(name => File.ReadAllText(Path.Combine(pages, name))));
        StringAssert.Contains(source, "SIMULATION ONLY");
        StringAssert.Contains(source, "AdaptiveGridPanel");
        StringAssert.Contains(source, "VirtualizingPanel.IsVirtualizing=\"True\"");
        StringAssert.Contains(source, "ToolTip=");
        foreach (var prohibited in new[] { "Content=\"Apply\"", "Content=\"Activate\"", "Content=\"Enforce\"" })
        {
            Assert.IsFalse(source.Contains(prohibited, StringComparison.OrdinalIgnoreCase));
        }
    }

    [TestMethod]
    public void Phase7GuiSmokeExtendsTheEntirePhase6ResponsiveBaseline()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "Phase7GuiValidator.cs"));
        foreach (var required in new[]
        {
            "Phase6GuiValidator.ValidateAsync", "Program Connection Lock", "Protection Profiles", "Schedules",
            "Compatibility Guard", "ApplicationInventorySmokePassed", "ProfileAndPolicySimulationPassed",
            "PlannerSmokePassed", "UpdatedTablesVirtualized", "MisleadingEnforcementControlsAbsent",
            "1024d, 640d", "ScrollableWidth"
        })
        {
            StringAssert.Contains(source, required);
        }
    }

    [TestMethod]
    public void Phase7ApplicationIdentityNeverUsesDisplayNameAlone()
    {
        var identity = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.Core", "ConnectionLock", "ProgramIdentity.cs"));
        var inventory = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.Windows", "Discovery", "Applications", "ApplicationInventoryService.cs"));
        StringAssert.Contains(identity, "display name alone is never sufficient");
        StringAssert.Contains(identity, "package family name");
        StringAssert.Contains(identity, "canonical executable path");
        StringAssert.Contains(inventory, "CreateStableId");
        Assert.IsFalse(identity.Contains("StableId = DisplayName", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void Phase8RegistersOnlyReadOnlyWindowsProgramLockCapability()
    {
        var windowsDirectory = Path.Combine(RepositoryRoot, "src", "QuietShield.Windows");
        var windowsSource = string.Join(Environment.NewLine,
            Directory.EnumerateFiles(windowsDirectory, "*.cs", SearchOption.AllDirectories).Select(File.ReadAllText));
        var appComposition = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "App.xaml.cs"));
        foreach (var modifyingContract in new[]
                 {
                     "IProgramLockRuleCreator", "IProgramLockRuleUpdater", "IProgramLockRuleRemover",
                     "IProgramLockRollback", "IProgramLockInterruptedTransactionRecovery"
                 })
        {
            Assert.IsFalse(windowsSource.Contains(modifyingContract, StringComparison.Ordinal),
                $"QuietShield.Windows contains a modifying Program Lock contract: {modifyingContract}.");
            Assert.IsFalse(appComposition.Contains(modifyingContract, StringComparison.Ordinal),
                $"Application composition registered a modifying Program Lock contract: {modifyingContract}.");
        }
        StringAssert.Contains(windowsSource, "IReadOnlyProgramLockWindowsCapability");
        StringAssert.Contains(windowsSource, "ModifyingImplementationRegistered");
        StringAssert.Contains(windowsSource, "false");
        StringAssert.Contains(appComposition, "AddSingleton<IReadOnlyProgramLockWindowsCapability, ReadOnlyProgramLockWindowsCapability>");
    }

    [TestMethod]
    public void Phase8RecoveryScriptsArePowerShell51WhatIfOnlyAndNeverSelfElevate()
    {
        var scripts = Path.Combine(RepositoryRoot, "scripts");
        var restore = File.ReadAllText(Path.Combine(scripts, "Restore-ProgramLockRules.ps1"));
        var common = File.ReadAllText(Path.Combine(scripts, "ProgramLockTransaction.Script.Common.ps1"));
        var test = File.ReadAllText(Path.Combine(scripts, "Test-ProgramLockTransaction.ps1"));
        foreach (var required in new[]
                 {
                     "SupportsShouldProcess = $true", "ExplicitUserApproval", "Test-QuietShieldProgramLockAdministrator",
                     "Test-QuietShieldProgramLockBackup", "$WhatIfPreference", "no modifying Windows implementation"
                 })
        {
            StringAssert.Contains(restore, required);
        }
        foreach (var source in new[] { restore, common, test })
        {
            Assert.IsFalse(source.Contains("-Verb RunAs", StringComparison.OrdinalIgnoreCase));
            Assert.IsFalse(source.Contains("Start-Process", StringComparison.OrdinalIgnoreCase));
            Assert.IsFalse(source.Contains("netsh", StringComparison.OrdinalIgnoreCase));
            Assert.IsFalse(source.Contains("Fwpm", StringComparison.OrdinalIgnoreCase));
        }
        StringAssert.Contains(common, "SHA256");
        StringAssert.Contains(test, "canExecute = $false");
    }

    [TestMethod]
    public void Phase8LaunchersUsePowerShell51SafetyFlagsAndNoElevation()
    {
        foreach (var launcherName in new[]
                 {
                     "Test-ProgramLockTransaction.bat", "Show-ProgramLockTransactionState.bat", "Emergency-Restore-ProgramLock.bat"
                 })
        {
            var launcher = File.ReadAllText(Path.Combine(RepositoryRoot, launcherName));
            StringAssert.Contains(launcher, "powershell.exe -NoProfile -ExecutionPolicy Bypass -File");
            Assert.IsFalse(launcher.Contains("RunAs", StringComparison.OrdinalIgnoreCase));
        }
    }

    [TestMethod]
    public void Phase8ProgramLockPageIsResponsiveVirtualizedAndExposesOnlyPreviewAndExportActions()
    {
        var xaml = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "Pages", "ProgramConnectionLockPage.xaml"));
        foreach (var required in new[]
                 {
                     "Enforcement is not active. No Windows Firewall or WFP rule has been changed.",
                     "ProgramLockTransactionPlanList", "AdaptiveGridPanel", "VirtualizingPanel.IsVirtualizing=\"True\"",
                     "VirtualizingPanel.VirtualizationMode=\"Recycling\"", "TrimmedValueTextStyle",
                     "ToolTip=\"{Binding Application}\"", "ToolTip=\"{Binding Reason}\"",
                     "Content=\"_Preview Enforcement Plan\"", "Content=\"_Export Plan\""
                 })
        {
            StringAssert.Contains(xaml, required);
        }
        foreach (var prohibited in new[] { "Content=\"Apply\"", "Content=\"Activate\"", "Content=\"Enforce\"", "Content=\"Administrator\"" })
        {
            Assert.IsFalse(xaml.Contains(prohibited, StringComparison.OrdinalIgnoreCase));
        }
    }

    [TestMethod]
    public void Phase8GuiSmokeExtendsPhase7AndValidatesPlanSafety()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "Phase8GuiValidator.cs"));
        foreach (var required in new[]
                 {
                     "Phase7GuiValidator.ValidateAsync", "Program Connection Lock", "TransactionPlanSmokePassed",
                     "PlanExportSmokePassed", "BackupRollbackReadinessPassed", "PlanViewerVirtualized",
                     "MisleadingEnforcementControlsAbsent", "InactiveBannerPassed", "LongTextAffordancesPassed",
                     "1024d, 640d", "ScrollableWidth"
                 })
        {
            StringAssert.Contains(source, required);
        }
    }

    [TestMethod]
    public void Phase8StrategyDocumentsExactPolicyLimitsAndDeferredKernelLayer()
    {
        var strategy = File.ReadAllText(Path.Combine(RepositoryRoot, "docs", "PROGRAM-LOCK-ENFORCEMENT-STRATEGY.md"));
        foreach (var policy in new[]
                 {
                     "Blocked", "Allowed on All", "Wi-Fi Only", "Ethernet Only", "Cellular Only", "Metered Only", "Unmetered Only"
                 })
        {
            StringAssert.Contains(strategy, policy);
        }
        StringAssert.Contains(strategy, "user-mode Windows Filtering Platform");
        StringAssert.Contains(strategy, "kernel callout drivers deferred");
        StringAssert.Contains(strategy, "QuietShield.ProgramLock.<stable-rule-id>");
    }

    [TestMethod]
    public void Phase8EmergencyRestoreWhatIfValidatesBackupWithoutChangingWindows()
    {
        var script = Path.Combine(RepositoryRoot, "scripts", "Restore-ProgramLockRules.ps1");
        var fixture = Path.Combine(RepositoryRoot, "tests", "Fixtures", "phase8-program-lock-backup.json");
        var start = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(script);
        start.ArgumentList.Add("-BackupPath");
        start.ArgumentList.Add(fixture);
        start.ArgumentList.Add("-WhatIf");
        using var process = System.Diagnostics.Process.Start(start);
        Assert.IsNotNull(process);
        Assert.IsTrue(process.WaitForExit(10_000), "Phase 8 restore -WhatIf timed out.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        Assert.AreEqual(0, process.ExitCode, error);
        StringAssert.Contains(output, "WhatIfPassed");
        StringAssert.Contains(output, "ModifyingImplementationAvailable");
        StringAssert.Contains(output, "False");
    }

    [TestMethod]
    public void Phase9ProbeAcceptsOnlyLiteralIpAndOneTcpAttemptWithoutContentCollection()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.ConnectionProbe", "Program.cs"));
        foreach (var required in new[] { "IPAddress.TryParse", "TcpClient", "ConnectAsync", "ConnectionSucceeded = 0", "ConnectionBlockedOrTimedOut = 10", "InvalidArguments = 20", "InternalError = 30" })
            StringAssert.Contains(source, required);
        foreach (var forbidden in new[] { "Dns.", "GetHost", "HttpClient", "HttpRequest", "Cookie", "Credential", "Authorization", "while (", "for (;;" })
            Assert.IsFalse(source.Contains(forbidden, StringComparison.OrdinalIgnoreCase), $"The dedicated probe contains prohibited behavior: {forbidden}.");
    }

    [TestMethod]
    public void Phase9FirewallMutationSurfaceIsNarrowExactAndNeverSelfElevates()
    {
        var scripts = Path.Combine(RepositoryRoot, "scripts");
        var invoke = File.ReadAllText(Path.Combine(scripts, "Invoke-ProgramLockFirewallRehearsal.ps1"));
        var restore = File.ReadAllText(Path.Combine(scripts, "Restore-ProgramLockRehearsal.ps1"));
        var watchdog = File.ReadAllText(Path.Combine(scripts, "Watch-ProgramLockFirewallRehearsal.ps1"));
        var watchdogCommon = File.ReadAllText(Path.Combine(scripts, "ProgramLockRehearsal.Script.Common.ps1"));
        foreach (var source in new[] { invoke, restore, watchdog })
        {
            Assert.IsFalse(source.Contains("-Verb RunAs", StringComparison.OrdinalIgnoreCase));
            Assert.IsFalse(source.Contains("requireAdministrator", StringComparison.OrdinalIgnoreCase));
            foreach (var forbidden in new[] { "Set-DnsClient", "Set-NetAdapter", "Fwpm", "New-Service", "Set-Service", "Registry", "Certificate" })
                Assert.IsFalse(source.Contains(forbidden, StringComparison.OrdinalIgnoreCase), $"The Phase 9 rehearsal contains unrelated mutation: {forbidden}.");
        }
        StringAssert.Contains(invoke, "ApprovedTemporaryFirewallRehearsal");
        StringAssert.Contains(invoke, "Test-QuietShieldProgramLockRehearsalDescription -Description $description -TransactionId $transactionId");
        StringAssert.Contains(invoke, "New-NetFirewallRule -Name $ruleName -DisplayName $ruleName");
        StringAssert.Contains(invoke, "-Direction Outbound -Action Block -Enabled True -Profile Any -Program $probePath -Protocol TCP");
        StringAssert.Contains(invoke, "-RemotePort 443 -LocalAddress Any -LocalPort Any -EdgeTraversalPolicy Block");
        Assert.AreEqual(1, System.Text.RegularExpressions.Regex.Count(invoke, "New-NetFirewallRule", System.Text.RegularExpressions.RegexOptions.IgnoreCase));
        StringAssert.Contains(restore, "Remove-NetFirewallRule -Name ([string]$state.rule.name)");
        StringAssert.Contains(restore, "[switch]$ApprovedWatchdogCleanup");
        StringAssert.Contains(restore, "ApprovedOrchestratorRollback or ApprovedWatchdogCleanup");
        StringAssert.Contains(restore, "$ConfirmPreference = 'None'");
        StringAssert.Contains(restore, "Remove-NetFirewallRule -Name ([string]$state.rule.name) -Confirm:$false");
        StringAssert.Contains(restore, "Local\\QuietShield.ProgramLock.Rehearsal.");
        StringAssert.Contains(restore, "$rollbackMutex.WaitOne");
        Assert.AreEqual(2, System.Text.RegularExpressions.Regex.Count(restore, "Test-QuietShieldProgramLockRehearsalState -StatePath \\$StatePath"),
            "Exact rollback must revalidate transaction state after acquiring exclusive ownership.");
        Assert.IsFalse(restore.Contains("Remove-NetFirewallRule -DisplayName", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(restore.Contains("Get-NetFirewallRule -DisplayName", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(System.Text.RegularExpressions.Regex.IsMatch(restore, @"Remove-NetFirewallRule[^\r\n]*\*", System.Text.RegularExpressions.RegexOptions.IgnoreCase));
        StringAssert.Contains(watchdog + watchdogCommon, "ParentProcessLost");
        StringAssert.Contains(watchdog + watchdogCommon, "HeartbeatLost");
        StringAssert.Contains(watchdog + watchdogCommon, "DeadlineExpired");
    }

    [TestMethod]
    public void Phase9WatchdogCannotRegisterAServiceOrRemoveBroadRules()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot, "scripts", "Watch-ProgramLockFirewallRehearsal.ps1"));
        foreach (var forbidden in new[] { "UseWindowsService", "ServiceInstaller", "sc.exe", "New-Service", "Get-NetFirewallRule -DisplayName", "Remove-NetFirewallRule" })
            Assert.IsFalse(source.Contains(forbidden, StringComparison.OrdinalIgnoreCase));
        StringAssert.Contains(source, "Restore-ProgramLockRehearsal.ps1");
        StringAssert.Contains(source, "ApprovedWatchdogCleanup");
        Assert.IsFalse(source.Contains("-Confirm:$false", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Phase9WatchdogUsesExplicitUtcDateTimeOffsetAndPassesReadOnlySimulations()
    {
        var scripts = Path.Combine(RepositoryRoot, "scripts");
        var watchdog = File.ReadAllText(Path.Combine(scripts, "Watch-ProgramLockFirewallRehearsal.ps1"));
        var common = File.ReadAllText(Path.Combine(scripts, "ProgramLockRehearsal.Script.Common.ps1"));
        var invoke = File.ReadAllText(Path.Combine(scripts, "Invoke-ProgramLockFirewallRehearsal.ps1"));
        StringAssert.Contains(watchdog, "Get-QuietShieldProgramLockWatchdogTrigger");
        Assert.IsFalse(watchdog.Contains("(Get-Date).ToUniversalTime() -ge [DateTimeOffset]", StringComparison.Ordinal));
        StringAssert.Contains(common, "function ConvertTo-QuietShieldUtcDateTimeOffset");
        StringAssert.Contains(common, "[DateTimeKind]::Unspecified");
        StringAssert.Contains(common, "[DateTimeKind]::Utc");
        StringAssert.Contains(common, "function Get-QuietShieldProgramLockWatchdogTrigger");
        StringAssert.Contains(common, "function Test-QuietShieldProgramLockWatchdogCompletionEvidence");
        StringAssert.Contains(invoke, "Watchdog did not exit within the bounded cleanup timeout");
        StringAssert.Contains(watchdog, "-ApprovedWatchdogCleanup -EvidencePath $EvidencePath");
        StringAssert.Contains(invoke, "-ApprovedOrchestratorRollback -EvidencePath $evidencePath");
        Assert.IsFalse(watchdog.Contains("-Confirm:$false", StringComparison.Ordinal));
        Assert.IsFalse(System.Text.RegularExpressions.Regex.IsMatch(watchdog, @"powershell\.exe[^\r\n]*-File[^\r\n]*-Confirm", System.Text.RegularExpressions.RegexOptions.IgnoreCase));
        Assert.IsFalse(System.Text.RegularExpressions.Regex.IsMatch(invoke, @"powershell\.exe[^\r\n]*-File[^\r\n]*-Confirm", System.Text.RegularExpressions.RegexOptions.IgnoreCase));
        var waitIndex = invoke.IndexOf("$watchdog.WaitForExit(15000)", StringComparison.Ordinal);
        var refreshIndex = invoke.IndexOf("$watchdog.Refresh()", waitIndex, StringComparison.Ordinal);
        var hasExitedIndex = invoke.IndexOf("$watchdog.HasExited", refreshIndex, StringComparison.Ordinal);
        var exitCodeIndex = invoke.IndexOf("$watchdog.ExitCode", hasExitedIndex, StringComparison.Ordinal);
        Assert.IsTrue(waitIndex >= 0 && refreshIndex > waitIndex && hasExitedIndex > refreshIndex && exitCodeIndex > hasExitedIndex,
            "Watchdog ExitCode must only be read after bounded WaitForExit, Refresh, and HasExited verification.");
        StringAssert.Contains(invoke, "Test-QuietShieldProgramLockWatchdogCompletionEvidence");
        StringAssert.Contains(invoke, "One or more QuietShield rehearsal rules remain after watchdog cleanup.");

        var start = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(Path.Combine(scripts, "Test-ProgramLockWatchdogSimulations.ps1"));
        using var process = System.Diagnostics.Process.Start(start);
        Assert.IsNotNull(process);
        Assert.IsTrue(process.WaitForExit(15_000), "Phase 9 watchdog simulations timed out.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        Assert.AreEqual(0, process.ExitCode, error);
        foreach (var required in new[]
                 {
                     "utcDateTimeConversion", "localDateTimeConversion", "unspecifiedDateTimeConversion",
                     "subSecondDeadlineCleanup", "heartbeatLossCleanup", "orchestratorLossCleanup", "explicitWatchdogApprovalRequired",
                     "malformedTransactionRefused", "foreignTransactionRefused", "exitCodeUnavailableBeforeExit",
                     "successfulExitAfterBoundedWait", "boundedProcessExitTimeout", "validWatchdogCleanupEvidence",
                     "nonzeroWatchdogExit", "zeroRemainingRehearsalRules", "exactRuleRemovalOnly"
                 })
            StringAssert.Contains(output, required);
    }

    [TestMethod]
    public void Phase9ProtectedStateSeparatesOnlyOperationalStatusAndKeepsConfigurationStrict()
    {
        var scripts = Path.Combine(RepositoryRoot, "scripts");
        var common = File.ReadAllText(Path.Combine(scripts, "QuietShield.Script.Common.ps1"));
        var configurationStart = common.IndexOf("function ConvertTo-QuietShieldCanonicalAdapterConfigurationData", StringComparison.Ordinal);
        var operationalStart = common.IndexOf("function ConvertTo-QuietShieldCanonicalAdapterOperationalData", configurationStart, StringComparison.Ordinal);
        Assert.IsTrue(configurationStart >= 0 && operationalStart > configurationStart);
        var configuration = common[configurationStart..operationalStart];
        Assert.IsFalse(configuration.Contains("ConnectionState", StringComparison.Ordinal));
        foreach (var required in new[] { "InterfaceIndex", "AddressFamily", "Dhcp", "RouterDiscovery", "NlMtu" })
            StringAssert.Contains(configuration, required);
        foreach (var required in new[]
                 {
                     "AdapterIdentityHash", "AdapterConfigurationHash", "AdapterOperationalHash", "AdapterOperationalState",
                     "QuietShieldFirewallRuleHash", "EnvironmentalAdapterOperationalTransition", "VpnOrVirtual",
                     "Surfshark/OpenVPN must remain disconnected", "PersistentDifferences"
                 })
            StringAssert.Contains(common, required);

        var simulation = File.ReadAllText(Path.Combine(scripts, "Test-ProgramLockWatchdogSimulations.ps1"));
        foreach (var required in new[]
                 {
                     "vpnOperationalTransitionReporting", "persistentAdapterConfigurationValidation",
                     "dnsConfigurationValidation", "quietShieldFirewallRuleValidation"
                 })
            StringAssert.Contains(simulation, required);
    }

    [TestMethod]
    public void Phase9RootLaunchersUsePowerShell51AndNeverElevate()
    {
        foreach (var launcherName in new[] { "Run-ProgramLock-Rehearsal.bat", "Show-ProgramLock-Rehearsal-State.bat", "Emergency-Restore-ProgramLock-Rehearsal.bat" })
        {
            var launcher = File.ReadAllText(Path.Combine(RepositoryRoot, launcherName));
            StringAssert.Contains(launcher, "powershell.exe -NoProfile -ExecutionPolicy Bypass -File");
            Assert.IsFalse(launcher.Contains("RunAs", StringComparison.OrdinalIgnoreCase));
        }
    }

    [TestMethod]
    public void Phase9PowerShellUsesFrameworkCompatiblePathValidation()
    {
        var common = File.ReadAllText(Path.Combine(RepositoryRoot, "scripts", "ProgramLockRehearsal.Script.Common.ps1"));
        StringAssert.Contains(common, "[IO.Path]::IsPathRooted");
        Assert.IsFalse(common.Contains("IsPathFullyQualified", StringComparison.Ordinal));
        StringAssert.Contains(common, "Get-QuietShieldProgramLockRehearsalHash");
        StringAssert.Contains(common, "Test-QuietShieldProgramLockRehearsalState");
    }

    [TestMethod]
    public void Phase9DnsSafetySnapshotCanonicalizesRowsWithoutChangingServerOrderOrDuplicates()
    {
        var common = File.ReadAllText(Path.Combine(RepositoryRoot, "scripts", "QuietShield.Script.Common.ps1"));
        var start = common.IndexOf("function ConvertTo-QuietShieldCanonicalDnsSnapshotData", StringComparison.Ordinal);
        var end = common.IndexOf("function Get-QuietShieldSafetySnapshot", start, StringComparison.Ordinal);
        Assert.IsTrue(start >= 0 && end > start, "The DNS snapshot canonicalizer was not found.");
        var canonicalizer = common[start..end];

        StringAssert.Contains(canonicalizer, "Sort-Object -Property InterfaceIndex, AddressFamily");
        StringAssert.Contains(canonicalizer, "foreach ($serverAddress in @($row.ServerAddresses))");
        StringAssert.Contains(canonicalizer, "ServerAddresses = $serverAddresses");
        Assert.IsFalse(canonicalizer.Contains("Select-Object -Unique", StringComparison.OrdinalIgnoreCase));
        Assert.IsFalse(canonicalizer.Contains("Sort-Object $serverAddresses", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void Phase9GuiStatusIsResponsiveExplicitAndHasNoPermanentEnforcementAction()
    {
        var page = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "Pages", "ProgramConnectionLockPage.xaml"));
        foreach (var required in new[]
                 {
                     "Temporary dedicated test only. No installed application will be blocked.", "Controlled Firewall rehearsal status",
                     "Firewall capability", "Test executable readiness", "Reachable endpoint readiness", "Backup readiness", "Watchdog readiness",
                     "Last rehearsal result", "Last rollback result", "Permanent enforcement", "AdaptiveGridPanel"
                 })
            StringAssert.Contains(page, required);
        foreach (var prohibited in new[] { "Content=\"Apply\"", "Content=\"Enforce\"", "Content=\"Run Rehearsal\"" })
            Assert.IsFalse(page.Contains(prohibited, StringComparison.OrdinalIgnoreCase));

        var validator = File.ReadAllText(Path.Combine(RepositoryRoot, "src", "QuietShield.App", "Phase9GuiValidator.cs"));
        foreach (var required in new[]
                 {
                     "Phase8GuiValidator.ValidateAsync", "RehearsalStatusSectionPassed", "DedicatedTestBannerPassed",
                     "PermanentEnforcementInactive", "MisleadingPermanentControlsAbsent", "1024d, 640d", "ScrollableWidth"
                 })
            StringAssert.Contains(validator, required);
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
