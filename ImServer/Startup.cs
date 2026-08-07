using System.Text;
using FreeRedis;
using Industrial.Health;
using Industrial.Security.Abstractions;
using Industrial.Security.AspNetCore;
using imServer.IndustrialSecurity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace imServer
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddHttpContextAccessor();
            services.AddIndustrialSecurity(Configuration);
            services.AddScoped<IShadowUserResolver, FreeImNoLocalShadowUserResolver>();
            services.AddScoped<ILocalPermissionSource, FreeImDenyLocalPermissionSource>();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddIndustrialJwt(Configuration);
            services.AddAuthorization();
            services.AddControllers();

            var redisConnection = Configuration["ImServerOption:RedisClient"]
                ?? throw new InvalidOperationException("ImServerOption:RedisClient is required.");
            var redis = new RedisClient(redisConnection);
            services.AddSingleton(redis);
            services.AddSingleton(sp => new ImClient(new ImClientOptions
            {
                Redis = sp.GetRequiredService<RedisClient>(),
                Servers = GetServers(Configuration),
                PathMatch = "/ws"
            }));
            services.AddSingleton<FreeImIdentityService>();
        }

        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Console.OutputEncoding = Encoding.GetEncoding("GB2312");
            Console.InputEncoding = Encoding.GetEncoding("GB2312");

            app.UseDeveloperExceptionPage();

            // Health remains public so YARP can make routing decisions even when IAM is down.
            // Liveness describes only the process. Traffic/dependency health also probes Redis,
            // because FreeIM cannot mint/consume connection tickets without that critical store.
            app.Use(async (context, next) =>
            {
                if (HttpMethods.IsGet(context.Request.Method)
                    && (context.Request.Path.Equals("/health/live", StringComparison.OrdinalIgnoreCase)
                        || context.Request.Path.Equals("/health/ready", StringComparison.OrdinalIgnoreCase)
                        || context.Request.Path.Equals("/health/dependencies", StringComparison.OrdinalIgnoreCase)
                        || context.Request.Path.Equals("/health/traffic", StringComparison.OrdinalIgnoreCase)
                        || context.Request.Path.Equals("/healthz", StringComparison.OrdinalIgnoreCase)))
                {
                    context.Response.ContentType = "application/json; charset=utf-8";
                    var now = DateTimeOffset.UtcNow;
                    var isLiveness = context.Request.Path.Equals("/health/live", StringComparison.OrdinalIgnoreCase)
                        || context.Request.Path.Equals("/healthz", StringComparison.OrdinalIgnoreCase);

                    if (isLiveness)
                    {
                        context.Response.StatusCode = StatusCodes.Status200OK;
                        await context.Response.WriteAsJsonAsync(new
                        {
                            service = "im",
                            instance = Environment.MachineName,
                            status = ServiceStatus.Healthy,
                            application = new ApplicationHealth(ServiceStatus.Healthy, true, now),
                            checkedAt = now
                        });
                        return;
                    }

                    var redis = context.RequestServices.GetRequiredService<RedisClient>();
                    var redisHealthy = ProbeRedis(redis, TimeSpan.FromSeconds(1));
                    var dependencies = new[]
                    {
                        new DependencyHealthItem(
                            "Redis",
                            redisHealthy ? DependencyStatus.Healthy : DependencyStatus.Unhealthy,
                            DependencyCriticality.Critical,
                            redisHealthy ? null : "REDIS_CONNECTION_FAILED",
                            redisHealthy ? null : "FreeIM Redis is unavailable",
                            redisHealthy ? null : now,
                            redisHealthy ? null : "Realtime ticket issuance and delivery are unavailable",
                            FallbackAvailable: false)
                    };
                    var snapshot = HealthSnapshotEvaluator.Evaluate("im", Environment.MachineName, dependencies, checkedAt: now);
                    var traffic = HealthSnapshotEvaluator.ToTrafficHealth(snapshot);

                    if (context.Request.Path.Equals("/health/traffic", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.StatusCode = traffic.Status == TrafficStatus.Allowed
                            ? StatusCodes.Status200OK
                            : StatusCodes.Status503ServiceUnavailable;
                        await context.Response.WriteAsJsonAsync(traffic);
                    }
                    else if (context.Request.Path.Equals("/health/dependencies", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.StatusCode = snapshot.ServiceStatus == ServiceStatus.Unavailable
                            ? StatusCodes.Status503ServiceUnavailable
                            : StatusCodes.Status200OK;
                        await context.Response.WriteAsJsonAsync(snapshot);
                    }
                    else
                    {
                        // /health/ready follows traffic eligibility for load-balancer readiness.
                        context.Response.StatusCode = traffic.Status == TrafficStatus.Allowed
                            ? StatusCodes.Status200OK
                            : StatusCodes.Status503ServiceUnavailable;
                        await context.Response.WriteAsJsonAsync(traffic);
                    }
                    return;
                }

                await next();
            });

            app.UseRouting();
            app.UseAuthentication();
            app.UseIndustrialSecurity();
            app.UseAuthorization();

            // The long-lived IAM access token is used only to mint the native FreeIM
            // ticket. Before the legacy /ws handler consumes it, reject any same-node
            // replay so the 10-second ticket is effectively single-use in the current
            // single-backend deployment.
            app.UseMiddleware<FreeImHandshakeReplayGuardMiddleware>();
            app.UseFreeImServer(new ImServerOptions
            {
                Redis = app.ApplicationServices.GetRequiredService<RedisClient>(),
                Servers = GetServers(Configuration),
                Server = Configuration["ImServerOption:Server"]
                    ?? throw new InvalidOperationException("ImServerOption:Server is required.")
            });

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                endpoints.MapIndustrialSecurityCacheInvalidation();
                endpoints.MapIndustrialLocalUserManagementInfo();
            });
        }

        private static bool ProbeRedis(RedisClient redis, TimeSpan timeout)
        {
            try
            {
                // GET of a dedicated non-business key is read-only: null means the probe
                // reached Redis successfully, while connection failures throw.
                var task = Task.Run(() => redis.Get("industrial:health:probe"));
                return task.Wait(timeout) && task.IsCompletedSuccessfully;
            }
            catch
            {
                return false;
            }
        }

        private static string[] GetServers(IConfiguration configuration)
            => (configuration["ImServerOption:Servers"]
                ?? throw new InvalidOperationException("ImServerOption:Servers is required."))
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}