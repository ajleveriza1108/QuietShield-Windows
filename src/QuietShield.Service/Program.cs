using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using QuietShield.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddSingleton<IHeartbeatDelay, SystemHeartbeatDelay>();
builder.Services.AddSingleton<DiagnosticHeartbeat>();
builder.Services.AddHostedService<HeartbeatWorker>();

await builder.Build().RunAsync().ConfigureAwait(false);
