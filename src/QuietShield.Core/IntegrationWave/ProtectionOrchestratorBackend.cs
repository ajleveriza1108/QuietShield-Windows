// QuietShield Backend Integration 01 R1
using QuietShield.Core.DataSaving;

namespace QuietShield.Core.IntegrationWave;

public enum IntegratedProtectionModule
{
    ProgramConnectionLock = 0,
    DataSaving = 1,
    DnsProtection = 2,
    ParentChild = 3,
    PrivateBrowser = 4,
    FileSafety = 5,
    SecureUpdates = 6
}

public sealed record ProtectionModuleHealth(
    IntegratedProtectionModule Module,
    bool Ready,
    bool Degraded,
    string Message);

public enum ProtectionProfilePreset
{
    Balanced = 0,
    Strict = 1,
    DataSaving = 2
}

public sealed record ProtectionOrchestrationRequest(
    ProtectionProfilePreset Profile,
    OperatingModeState OperatingMode,
    IReadOnlyList<DataSavingApplicationDescriptor> Applications,
    IReadOnlyList<ProtectionModuleHealth> ModuleHealth);

public sealed record ProtectionOrchestrationPlan(
    ProtectionProfilePreset Profile,
    bool CanActivate,
    IReadOnlyList<IntegratedProtectionModule> RequiredModules,
    IReadOnlyList<string> BlockingReasons,
    DataSavingPolicyPlan DataSavingPlan,
    bool MachineMutationRequested);

public static class IntegratedProtectionOrchestrator
{
    public static ProtectionOrchestrationPlan Build(
        ProtectionOrchestrationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        IntegratedProtectionModule[] required = request.Profile switch
        {
            ProtectionProfilePreset.Balanced => new[]
            {
                IntegratedProtectionModule.ProgramConnectionLock,
                IntegratedProtectionModule.FileSafety,
                IntegratedProtectionModule.SecureUpdates
            },
            ProtectionProfilePreset.Strict => new[]
            {
                IntegratedProtectionModule.ProgramConnectionLock,
                IntegratedProtectionModule.DnsProtection,
                IntegratedProtectionModule.ParentChild,
                IntegratedProtectionModule.FileSafety,
                IntegratedProtectionModule.SecureUpdates
            },
            ProtectionProfilePreset.DataSaving => new[]
            {
                IntegratedProtectionModule.ProgramConnectionLock,
                IntegratedProtectionModule.DataSaving,
                IntegratedProtectionModule.FileSafety,
                IntegratedProtectionModule.SecureUpdates
            },
            _ => throw new ArgumentOutOfRangeException(nameof(request))
        };

        var reasons = new List<string>();
        foreach (var module in required)
        {
            var health = request.ModuleHealth.FirstOrDefault(item => item.Module == module);
            if (health is null || !health.Ready)
            {
                reasons.Add(module + " is not ready.");
            }
            else if (health.Degraded)
            {
                reasons.Add(module + " is degraded: " + health.Message);
            }
        }

        var mode = request.Profile == ProtectionProfilePreset.DataSaving
            ? request.OperatingMode with { Mode = QuietShieldOperatingMode.DataSaving }
            : request.OperatingMode;

        var dataPlan = DataSavingPolicyPlanner.Build(
            request.Applications,
            mode.Normalize());

        return new(
            request.Profile,
            reasons.Count == 0,
            required,
            reasons,
            dataPlan,
            MachineMutationRequested: false);
    }
}
