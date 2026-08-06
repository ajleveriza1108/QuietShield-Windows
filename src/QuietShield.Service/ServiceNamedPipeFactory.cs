using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace QuietShield.Service;

public static class ServiceNamedPipeFactory
{
    public static Func<NamedPipeServerStream>? Create(DiagnosticServiceOptions options)
    {
        if (!options.ServiceMode) return null;
        var activation = options.ActivationConfiguration ?? throw new InvalidOperationException("Service pipe security requires validated activation configuration.");
        return () => CreateProductionPipe(options.PipeName, activation.AuthorizedUserSid);
    }

    private static NamedPipeServerStream CreateProductionPipe(string pipeName, string authorizedUserSid)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("The production service pipe requires Windows.");
        var security = new PipeSecurity();
        const PipeAccessRights readWrite = PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance;
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), readWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(authorizedUserSid), readWrite, AccessControlType.Allow));
        security.SetAccessRuleProtection(true, false);
        return NamedPipeServerStreamAcl.Create(
            pipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            0,
            0,
            security,
            HandleInheritability.None,
            PipeAccessRights.ChangePermissions);
    }
}
