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
            ["QuietShield.Windows"] = new[] { "QuietShield.Core" }
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
                Assert.IsFalse(
                    content.Contains(fragment, StringComparison.OrdinalIgnoreCase),
                    $"{Path.GetRelativePath(RepositoryRoot, script)} contains forbidden command fragment '{fragment}'.");
            }
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
