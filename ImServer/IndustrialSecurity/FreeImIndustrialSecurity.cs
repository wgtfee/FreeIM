using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FreeRedis;
using Industrial.Security.Abstractions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace imServer.IndustrialSecurity;

public static class FreeImPermissionCodes
{
    public const string SessionAccess = "im.session.access";
    public const string BroadcastSend = "im.broadcast.send";
    public const string AdministrationManage = "im.administration.manage";
}

/// <summary>
/// FreeIM has no separate business-user master record. Central IAM identity is used
/// directly and no synthetic Shadow User is persisted.
/// </summary>
public sealed class FreeImNoLocalShadowUserResolver : IShadowUserResolver
{
    public Task<ShadowUserSnapshot?> ResolveAsync(string iamUserId, CancellationToken cancellationToken = default)
        => Task.FromResult<ShadowUserSnapshot?>(null);

    public Task<ShadowUserSnapshot?> EnsureAsync(
        string iamUserId,
        string? userName,
        string? displayName,
        CancellationToken cancellationToken = default)
        => Task.FromResult<ShadowUserSnapshot?>(null);
}

/// <summary>Preparation mode has no local IM entitlement source, so local permission checks deny.</summary>
public sealed class FreeImDenyLocalPermissionSource : ILocalPermissionSource
{
    public Task<bool> HasPermissionAsync(string userId, string permissionCode, CancellationToken cancellationToken = default)
        => Task.FromResult(false);
}

public sealed record FreeImConnectionTicket(
    long ClientId,
    string WebSocketPath,
    int ExpiresInSeconds,
    string GlobalUserId);

/// <summary>
/// Maps the stable IAM global user id to the long client id required by the legacy
/// FreeIM wire protocol. The mapping is deterministic, while Redis detects the
/// astronomically unlikely 63-bit hash collision before a ticket is issued.
/// </summary>
public sealed class FreeImIdentityService(
    RedisClient redis,
    ImClient imClient,
    IConfiguration configuration,
    ILogger<FreeImIdentityService> logger)
{
    private const string IdentityKeyPrefix = "industrial:im:identity:v1:";

    public FreeImConnectionTicket CreateConnectionTicket(
        string globalUserId,
        string? userName,
        string? remoteIp,
        string traceId)
    {
        if (string.IsNullOrWhiteSpace(globalUserId))
            throw new InvalidOperationException("IAM global_user_id is required.");

        var clientId = ComputeClientId(globalUserId);
        var identityKey = IdentityKeyPrefix + clientId;
        var existing = redis.Get(identityKey);
        if (string.IsNullOrWhiteSpace(existing))
        {
            redis.Set(identityKey, globalUserId);
        }
        else if (!string.Equals(existing, globalUserId, StringComparison.Ordinal))
        {
            logger.LogCritical(
                "FreeIM client-id collision detected. ClientId={ClientId}; ExistingGlobalUserId={ExistingGlobalUserId}; RequestedGlobalUserId={RequestedGlobalUserId}",
                clientId,
                existing,
                globalUserId);
            throw new InvalidOperationException("IM identity mapping collision detected.");
        }

        var metadata = JsonSerializer.Serialize(new
        {
            globalUserId,
            userName,
            remoteIp,
            traceId,
            issuedAt = DateTimeOffset.UtcNow
        });
        var internalUrl = imClient.PrevConnectServer(clientId, metadata);
        var token = ExtractInternalToken(internalUrl);
        var publicPath = configuration["ImServerOption:PublicWebSocketPath"];
        if (string.IsNullOrWhiteSpace(publicPath)) publicPath = "/im/ws";
        if (!publicPath.StartsWith('/')) publicPath = "/" + publicPath;

        logger.LogInformation(
            "FreeIM connection ticket issued. ClientId={ClientId}; GlobalUserId={GlobalUserId}; TraceId={TraceId}",
            clientId,
            globalUserId,
            traceId);

        return new FreeImConnectionTicket(
            clientId,
            $"{publicPath}?token={Uri.EscapeDataString(token)}",
            10,
            globalUserId);
    }

    public static long ComputeClientId(string globalUserId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(globalUserId);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(globalUserId.Trim()));
        var value = BitConverter.ToUInt64(hash, 0) & long.MaxValue;
        return value == 0 ? 1 : (long)value;
    }

    private static string ExtractInternalToken(string internalUrl)
    {
        if (!Uri.TryCreate(internalUrl, UriKind.Absolute, out var uri))
            throw new InvalidOperationException("FreeIM returned an invalid websocket URL.");

        var query = uri.Query.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2))
            .FirstOrDefault(pair => pair.Length == 2 && string.Equals(pair[0], "token", StringComparison.OrdinalIgnoreCase));
        if (query is null || string.IsNullOrWhiteSpace(query[1]))
            throw new InvalidOperationException("FreeIM did not return a websocket token.");
        return Uri.UnescapeDataString(query[1]);
    }
}

[ApiController]
[Route("api/im")]
public sealed class FreeImConnectionController(
    FreeImIdentityService identities,
    ImClient imClient,
    ICurrentUser currentUser) : ControllerBase
{
    [HttpPost("connect")]
    [Authorize]
    [Permission(FreeImPermissionCodes.SessionAccess)]
    public ActionResult<FreeImConnectionTicket> Connect()
    {
        if (!currentUser.IsAuthenticated || string.IsNullOrWhiteSpace(currentUser.GlobalUserId))
            return Unauthorized();

        return Ok(identities.CreateConnectionTicket(
            currentUser.GlobalUserId,
            currentUser.UserName,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            HttpContext.TraceIdentifier));
    }

    [HttpGet("me")]
    [Authorize]
    [Permission(FreeImPermissionCodes.SessionAccess)]
    public IActionResult Me()
    {
        if (!currentUser.IsAuthenticated || string.IsNullOrWhiteSpace(currentUser.GlobalUserId))
            return Unauthorized();
        return Ok(new
        {
            systemCode = IndustrialSystemCodes.Im,
            globalUserId = currentUser.GlobalUserId,
            currentUser.UserName,
            clientId = FreeImIdentityService.ComputeClientId(currentUser.GlobalUserId)
        });
    }

    [HttpGet("online")]
    [Authorize]
    [Permission(FreeImPermissionCodes.AdministrationManage)]
    public IActionResult Online()
        => Ok(new { clientIds = imClient.GetClientListByOnline().ToArray() });

    [HttpPost("broadcast")]
    [Authorize]
    [Permission(FreeImPermissionCodes.BroadcastSend)]
    public IActionResult Broadcast([FromBody] FreeImBroadcastRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Content))
            return BadRequest(new { error = "Content cannot be empty." });
        imClient.SendBroadcastMessage(new
        {
            type = request.Type ?? "platform",
            content = request.Content,
            senderGlobalUserId = currentUser.GlobalUserId,
            sentAt = DateTimeOffset.UtcNow
        });
        return Accepted();
    }
}

public sealed record FreeImBroadcastRequest(string Content, string? Type = null);
