using System.Collections.Concurrent;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace imServer.IndustrialSecurity;

/// <summary>
/// Host-level replay guard for FreeIM's native 10-second websocket ticket.
/// The current platform deployment routes one FreeIM backend node at :6001, so an
/// in-process atomic token set is sufficient to make that ticket single-use without
/// changing the legacy FreeIM message loop. Multi-node FreeIM will require a Redis
/// atomic GETDEL/sticky-routing design before horizontal scale-out.
/// </summary>
public sealed class FreeImHandshakeReplayGuardMiddleware(RequestDelegate next)
{
    private static readonly ConcurrentDictionary<string, DateTimeOffset> Consumed = new(StringComparer.Ordinal);
    private static readonly TimeSpan Retention = TimeSpan.FromSeconds(15);

    public async Task InvokeAsync(HttpContext context, ILogger<FreeImHandshakeReplayGuardMiddleware> logger)
    {
        if (!context.Request.Path.StartsWithSegments("/ws", StringComparison.OrdinalIgnoreCase)
            || !context.WebSockets.IsWebSocketRequest)
        {
            await next(context);
            return;
        }

        var token = context.Request.Query["token"].ToString();
        if (string.IsNullOrWhiteSpace(token))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        CleanupExpired();
        var now = DateTimeOffset.UtcNow;
        if (!Consumed.TryAdd(token, now.Add(Retention)))
        {
            logger.LogWarning(
                "Rejected replayed FreeIM websocket ticket. RemoteIp={RemoteIp}; TraceId={TraceId}",
                context.Connection.RemoteIpAddress,
                context.TraceIdentifier);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        await next(context);
    }

    private static void CleanupExpired()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var entry in Consumed)
            if (entry.Value <= now)
                Consumed.TryRemove(entry.Key, out _);
    }
}
