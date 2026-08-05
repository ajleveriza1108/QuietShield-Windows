using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;
using QuietShield.Core.Results;
using QuietShield.Windows.Integration;

namespace QuietShield.Windows.Discovery;

public sealed class ReadOnlyFirewallStateDiscovery : IFirewallStateDiscovery
{
    private const string Script = "$svc=Get-Service -Name mpssvc -ErrorAction SilentlyContinue; $profiles=@(Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Name=$_.Name.ToString(); Enabled=[bool]$_.Enabled } }); $owned=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'QuietShield*' -or $_.Group -eq 'QuietShield' -or $_.DisplayGroup -eq 'QuietShield' }).Count; [pscustomobject]@{ ServiceAvailable=($null-ne $svc); Profiles=$profiles; QuietShieldOwnedRuleCount=[int]$owned } | ConvertTo-Json -Depth 4 -Compress";
    private readonly IPowerShellJsonRunner _runner;

    public ReadOnlyFirewallStateDiscovery(IPowerShellJsonRunner runner) => _runner = runner;

    public async Task<OperationResult<FirewallStateSnapshot>> DiscoverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = await _runner.RunAsync(Script, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StandardOutput))
        {
            return OperationResult.Failure<FirewallStateSnapshot>("Read-only firewall discovery returned no usable result.");
        }

        try
        {
            using var document = JsonDocument.Parse(result.StandardOutput);
            var root = document.RootElement;
            var profiles = new List<FirewallProfileState>();
            if (root.TryGetProperty("Profiles", out var profileElement))
            {
                var items = profileElement.ValueKind == JsonValueKind.Array ? profileElement.EnumerateArray().ToArray() : new[] { profileElement };
                foreach (var item in items)
                {
                    var name = JsonDiscovery.GetString(item, "Name");
                    if (TryMapProfile(name, out var profile))
                    {
                        profiles.Add(new FirewallProfileState(profile, JsonDiscovery.GetBoolean(item, "Enabled")));
                    }
                }
            }

            var snapshot = new FirewallStateSnapshot(
                JsonDiscovery.GetBoolean(root, "ServiceAvailable"),
                profiles.OrderBy(static item => item.Profile).ToArray(),
                JsonDiscovery.GetInt32(root, "QuietShieldOwnedRuleCount"),
                DateTimeOffset.UtcNow);
            return OperationResult.Success(snapshot, "Read-only Windows Firewall discovery completed; no rule or profile was changed.");
        }
        catch (JsonException exception)
        {
            return OperationResult.Failure<FirewallStateSnapshot>($"Read-only firewall output could not be parsed: {exception.Message}");
        }
    }

    public static bool TryMapProfile(string? value, out FirewallProfileKind profile)
    {
        if (Enum.TryParse(value, true, out profile)) return true;
        profile = default;
        return false;
    }
}

public sealed class ReadOnlyWindowsServiceStateDiscovery : IWindowsServiceStateDiscovery
{
    private const string Script = "$items=@(Get-Service -Name 'QuietShield','QuietShield.Service','BFE','mpssvc','netprofm' -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Name=$_.Name; Status=$_.Status.ToString() } }); $items | ConvertTo-Json -Depth 3 -Compress";
    private readonly IPowerShellJsonRunner _runner;

    public ReadOnlyWindowsServiceStateDiscovery(IPowerShellJsonRunner runner) => _runner = runner;

    public async Task<OperationResult<ServiceStateSnapshot>> DiscoverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = await _runner.RunAsync(Script, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            return OperationResult.Failure<ServiceStateSnapshot>("Read-only service discovery failed.");
        }

        try
        {
            var states = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!string.IsNullOrWhiteSpace(result.StandardOutput))
            {
                using var document = JsonDocument.Parse(result.StandardOutput);
                var items = document.RootElement.ValueKind == JsonValueKind.Array
                    ? document.RootElement.EnumerateArray().ToArray()
                    : new[] { document.RootElement };
                foreach (var item in items)
                {
                    var name = JsonDiscovery.GetString(item, "Name");
                    if (!string.IsNullOrWhiteSpace(name)) states[name] = JsonDiscovery.GetString(item, "Status") ?? "Unknown";
                }
            }

            var quietShield = states.ContainsKey("QuietShield") ? "QuietShield" : states.ContainsKey("QuietShield.Service") ? "QuietShield.Service" : "QuietShield";
            var snapshot = new ServiceStateSnapshot(
                Create(quietShield, states),
                Create("BFE", states),
                Create("mpssvc", states),
                Create("netprofm", states),
                DateTimeOffset.UtcNow);
            return OperationResult.Success(snapshot, "Read-only service discovery completed; no service was changed.");
        }
        catch (JsonException exception)
        {
            return OperationResult.Failure<ServiceStateSnapshot>($"Read-only service output could not be parsed: {exception.Message}");
        }
    }

    private static ServiceStateInfo Create(string name, Dictionary<string, string> states)
    {
        var registered = states.TryGetValue(name, out var status);
        return new ServiceStateInfo(name, registered, registered && string.Equals(status, "Running", StringComparison.OrdinalIgnoreCase), registered ? status! : "Not registered");
    }
}

public sealed class ReadOnlyFilteringPlatformCapabilityDiscovery : IFilteringPlatformCapabilityDiscovery
{
    internal static readonly Guid QuietShieldProviderKey = new("f79d8c43-a343-4a05-bf03-4da61bdf8498");
    internal static readonly Guid QuietShieldSublayerKey = new("5d56c870-cf61-4ba7-b59e-89b4b2364a03");

    public Task<OperationResult<FilteringPlatformCapability>> DiscoverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var apiAvailable = NativeLibrary.TryLoad("fwpuclnt.dll", out var library);
        if (!apiAvailable)
        {
            return Task.FromResult(OperationResult.Success(
                new FilteringPlatformCapability(false, true, false, false, 0, false, "WFP user-mode API is unavailable; no WFP object was created."),
                "Read-only WFP capability discovery completed."));
        }

        try
        {
            var open = LoadDelegate<FwpmEngineOpen>(library, "FwpmEngineOpen0");
            var close = LoadDelegate<FwpmEngineClose>(library, "FwpmEngineClose0");
            var getProvider = LoadDelegate<FwpmObjectGetByKey>(library, "FwpmProviderGetByKey0");
            var getSublayer = LoadDelegate<FwpmObjectGetByKey>(library, "FwpmSubLayerGetByKey0");
            var free = LoadDelegate<FwpmFreeMemory>(library, "FwpmFreeMemory0");
            var openResult = open(null, 10, IntPtr.Zero, IntPtr.Zero, out var engine);
            if (openResult != 0 || engine == IntPtr.Zero)
            {
                var unavailable = new FilteringPlatformCapability(true, true, false, false, 0, DetectCalloutService(), $"WFP engine read failed with code {openResult}; no WFP object was created.");
                return Task.FromResult(OperationResult.Success(unavailable, "Read-only WFP capability discovery completed with limited access."));
            }

            try
            {
                var providerExists = ObjectExists(engine, QuietShieldProviderKey, getProvider, free);
                var sublayerExists = ObjectExists(engine, QuietShieldSublayerKey, getSublayer, free);
                var capability = new FilteringPlatformCapability(
                    true,
                    true,
                    providerExists,
                    sublayerExists,
                    providerExists ? -1 : 0,
                    DetectCalloutService(),
                    providerExists
                        ? "QuietShield provider exists; filter count is not enumerated during this bounded capability check."
                        : "No QuietShield provider, sublayer, filters, or callout service were detected; no WFP object was created.");
                return Task.FromResult(OperationResult.Success(capability, "Read-only WFP capability discovery completed."));
            }
            finally
            {
                _ = close(engine);
            }
        }
        catch (EntryPointNotFoundException)
        {
            var capability = new FilteringPlatformCapability(false, true, false, false, 0, DetectCalloutService(), "Required WFP entry points are unavailable; no WFP object was created.");
            return Task.FromResult(OperationResult.Success(capability, "Read-only WFP capability discovery completed with limited API support."));
        }
        finally
        {
            NativeLibrary.Free(library);
        }
    }

    private static bool ObjectExists(IntPtr engine, Guid key, FwpmObjectGetByKey getter, FwpmFreeMemory free)
    {
        var result = getter(engine, ref key, out var pointer);
        if (pointer != IntPtr.Zero) free(ref pointer);
        return result == 0;
    }

    private static bool DetectCalloutService()
    {
        foreach (var name in new[] { "QuietShieldWfpCallout", "QuietShield.Callout", "QuietShieldDriver" })
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{name}", false);
            if (key is not null) return true;
        }

        return false;
    }

    private static T LoadDelegate<T>(IntPtr library, string export) where T : Delegate =>
        Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, export));

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint FwpmEngineOpen(string? serverName, uint authenticationService, IntPtr authenticationIdentity, IntPtr session, out IntPtr engineHandle);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint FwpmEngineClose(IntPtr engineHandle);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint FwpmObjectGetByKey(IntPtr engineHandle, ref Guid key, out IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void FwpmFreeMemory(ref IntPtr value);
}

public sealed class ReadOnlyPowerStateDiscovery : IPowerStateDiscovery
{
    public Task<OperationResult<PowerStateSnapshot>> DiscoverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!NativeLibrary.TryLoad("kernel32.dll", out var library))
        {
            return Task.FromResult(OperationResult.Failure<PowerStateSnapshot>("Windows power-state API is unavailable."));
        }

        try
        {
            var getPowerStatus = Marshal.GetDelegateForFunctionPointer<GetSystemPowerStatus>(NativeLibrary.GetExport(library, "GetSystemPowerStatus"));
            if (!getPowerStatus(out var status))
            {
                return Task.FromResult(OperationResult.Failure<PowerStateSnapshot>("Windows power-state API returned no data."));
            }

            var batteryPresent = (status.BatteryFlag & 128) == 0 && (status.BatteryFlag & 255) != 255;
            int? percentage = status.BatteryLifePercent <= 100 ? status.BatteryLifePercent : null;
            var snapshot = new PowerStateSnapshot(
                status.AcLineStatus == 1,
                batteryPresent,
                batteryPresent ? percentage : null,
                status.SystemStatusFlag == 1,
                status.AcLineStatus == 1 ? "AC power" : status.AcLineStatus == 0 ? "Battery" : "Unknown",
                DateTimeOffset.UtcNow);
            return Task.FromResult(OperationResult.Success(snapshot, "Read-only power discovery completed; no power plan was changed."));
        }
        finally
        {
            NativeLibrary.Free(library);
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool GetSystemPowerStatus(out SystemPowerStatus status);

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemPowerStatus
    {
        public byte AcLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public uint BatteryLifeTime;
        public uint BatteryFullLifeTime;
    }
}

public sealed class WindowsNetworkRefreshNotificationSource : INetworkRefreshNotificationSource
{
    private bool _started;
    public event EventHandler? RefreshRequested;

    public void Start()
    {
        if (_started) return;
        NetworkChange.NetworkAddressChanged += OnRefreshRequested;
        _started = true;
    }

    public void Dispose()
    {
        if (!_started) return;
        NetworkChange.NetworkAddressChanged -= OnRefreshRequested;
        _started = false;
    }

    private void OnRefreshRequested(object? sender, EventArgs args) => RefreshRequested?.Invoke(this, EventArgs.Empty);
}

internal static class JsonDiscovery
{
    public static string? GetString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    public static bool GetBoolean(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False && value.GetBoolean();

    public static int GetInt32(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.TryGetInt32(out var number) ? number : 0;
}
