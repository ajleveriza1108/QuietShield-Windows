using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using QuietShield.Core.ServiceFoundation;
using QuietShield.Service;

return await QuietShieldServiceProgram.RunAsync(args).ConfigureAwait(false);

namespace QuietShield.Service
{
    public static class QuietShieldServiceProgram
    {
        public static async Task<int> RunAsync(string[] args)
        {
            var options = DiagnosticServiceOptions.Parse(args);
            if (options.RunClientSmoke) return await DiagnosticIpcSmoke.RunAsync(options, CancellationToken.None).ConfigureAwait(false);
            if (options.ControlRequestPath is not null) return await DiagnosticServiceControlClient.RunAsync(options, CancellationToken.None).ConfigureAwait(false);

            var builder = Host.CreateApplicationBuilder(args);
            builder.Services.AddWindowsService(service => service.ServiceName = QuietShieldServiceIdentity.ServiceName);
            builder.Logging.AddProvider(new JsonLineFileLoggerProvider(options.StateRoot));
            builder.Services.Configure<HostOptions>(host => host.ShutdownTimeout = TimeSpan.FromSeconds(10));
            builder.Services.AddSingleton(options);
            builder.Services.AddSingleton<IHeartbeatDelay, SystemHeartbeatDelay>();
            builder.Services.AddSingleton<DiagnosticHeartbeat>();
            builder.Services.AddSingleton<AtomicJsonStateStore<PersistentServiceState>>(_ => new(PersistentServiceRuntime.CurrentSchemaVersion));
            builder.Services.AddSingleton<ReadOnlyPersistentPolicyPreflight>();
            builder.Services.AddSingleton<IPersistentPolicyPreflight>(services => services.GetRequiredService<ReadOnlyPersistentPolicyPreflight>());
            builder.Services.AddSingleton<IPersistentPolicyCoordinator, ReadOnlyPersistentPolicyCoordinator>();
            builder.Services.AddSingleton<IPersistentPolicyBackup, InMemoryPolicyBackup>();
            builder.Services.AddSingleton<IPersistentPolicyApplicator, InMemoryPolicyApplicator>();
            builder.Services.AddSingleton<IPersistentPolicyVerifier, InMemoryPolicyVerifier>();
            builder.Services.AddSingleton<IPersistentPolicyRollback, InMemoryPolicyRollback>();
            builder.Services.AddSingleton<PersistentServiceRuntime>();
            builder.Services.AddSingleton<PersistentFirewallTransactionStore>();
            if (options.ServiceMode)
            {
                var activation = options.ActivationConfiguration ?? throw new InvalidDataException("The controlled service activation configuration is missing.");
                builder.Services.AddSingleton(activation);
                builder.Services.AddSingleton<IPersistentFirewallBackend, PowerShellPersistentFirewallBackend>();
                builder.Services.AddSingleton<IServiceProgramPolicyCoordinator, PersistentProgramPolicyCoordinator>();
            }
            else
            {
                builder.Services.AddSingleton<IPersistentFirewallBackend, InMemoryPersistentFirewallBackend>();
                builder.Services.AddSingleton<IServiceProgramPolicyCoordinator, InactiveServiceProgramPolicyCoordinator>();
            }
            builder.Services.AddSingleton<IQuietShieldServiceRequestHandler, DiagnosticServiceRequestHandler>();
            builder.Services.AddSingleton(services => new NamedPipeQuietShieldServer(
                options.PipeName,
                services.GetRequiredService<IQuietShieldServiceRequestHandler>(),
                options.RequestTimeout,
                ServiceNamedPipeFactory.Create(options)));
            builder.Services.AddHostedService<ServiceFoundationWorker>();
            builder.Services.AddHostedService<ServiceIpcWorker>();
            if (options.Duration > TimeSpan.Zero) builder.Services.AddHostedService<DiagnosticDurationWorker>();
            await builder.Build().RunAsync().ConfigureAwait(false);
            return 0;
        }
    }
}
