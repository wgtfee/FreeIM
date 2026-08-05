using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Industrial.Health;
using System;
using System.Text;

namespace imServer
{

    public class Startup
    {

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration;

        public void ConfigureServices(IServiceCollection services)
        {
        }

        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Console.OutputEncoding = Encoding.GetEncoding("GB2312");
            Console.InputEncoding = Encoding.GetEncoding("GB2312");
            
            app.UseDeveloperExceptionPage();

            // Keep liveness/readiness separate from the WebSocket endpoint so
            // YARP can monitor this independent IM business service.
            app.Use(async (context, next) =>
            {
                if (HttpMethods.IsGet(context.Request.Method)
                    && (context.Request.Path.Equals("/health/live", StringComparison.OrdinalIgnoreCase)
                        || context.Request.Path.Equals("/health/ready", StringComparison.OrdinalIgnoreCase)
                        || context.Request.Path.Equals("/health/dependencies", StringComparison.OrdinalIgnoreCase)
                        || context.Request.Path.Equals("/health/traffic", StringComparison.OrdinalIgnoreCase)
                        || context.Request.Path.Equals("/healthz", StringComparison.OrdinalIgnoreCase)))
                {
                    context.Response.StatusCode = StatusCodes.Status200OK;
                    context.Response.ContentType = "application/json; charset=utf-8";
                    var now = DateTimeOffset.UtcNow;
                    var snapshot = HealthSnapshotEvaluator.Evaluate("im", Environment.MachineName, Array.Empty<DependencyHealthItem>(), checkedAt: now);
                    if (context.Request.Path.Equals("/health/traffic", StringComparison.OrdinalIgnoreCase))
                        await context.Response.WriteAsJsonAsync(HealthSnapshotEvaluator.ToTrafficHealth(snapshot));
                    else if (context.Request.Path.Equals("/health/dependencies", StringComparison.OrdinalIgnoreCase))
                        await context.Response.WriteAsJsonAsync(snapshot);
                    else
                        await context.Response.WriteAsJsonAsync(new
                        {
                            service = "im",
                            instance = Environment.MachineName,
                            status = ServiceStatus.Healthy,
                            application = snapshot.Application,
                            checkedAt = now
                        });
                    return;
                }

                await next();
            });

            app.UseFreeImServer(new ImServerOptions
            {
                Redis = new FreeRedis.RedisClient(Configuration["ImServerOption:RedisClient"]),
                Servers = Configuration["ImServerOption:Servers"].Split(";"),
                Server = Configuration["ImServerOption:Server"]
            });
        }
    }
}
