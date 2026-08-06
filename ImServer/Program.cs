using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace imServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((hostingContext, configuration) =>
                {
                    var profile = Environment.GetEnvironmentVariable("INDUSTRIAL_SECURITY_PROFILE")?.Trim();
                    if (!string.IsNullOrWhiteSpace(profile))
                    {
                        if (!new[] { "IamPrepare", "Centralized" }.Contains(profile, StringComparer.OrdinalIgnoreCase))
                            throw new InvalidOperationException($"Unsupported INDUSTRIAL_SECURITY_PROFILE '{profile}'.");
                        configuration.AddJsonFile($"appsettings.{profile}.json", optional: false, reloadOnChange: true);
                    }

                    configuration.AddEnvironmentVariables();
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
