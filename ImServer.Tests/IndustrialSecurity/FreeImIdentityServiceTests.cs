using Industrial.Security.Abstractions;
using imServer.IndustrialSecurity;

namespace ImServer.Tests.IndustrialSecurity;

public sealed class FreeImIdentityServiceTests
{
    [Fact]
    public void ComputeClientId_IsStablePositiveAndInputSensitive()
    {
        var first = FreeImIdentityService.ComputeClientId("iam-user-001");
        var same = FreeImIdentityService.ComputeClientId("iam-user-001");
        var other = FreeImIdentityService.ComputeClientId("iam-user-002");

        Assert.True(first > 0);
        Assert.Equal(first, same);
        Assert.NotEqual(first, other);
    }

    [Theory]
    [InlineData(FreeImPermissionCodes.SessionAccess)]
    [InlineData(FreeImPermissionCodes.BroadcastSend)]
    [InlineData(FreeImPermissionCodes.AdministrationManage)]
    public void PlatformImPermissions_FollowCanonicalConvention(string code)
    {
        Assert.True(PermissionCodeConvention.IsValid(code));
    }

    [Fact]
    public async Task NoLocalShadowResolver_NeverCreatesSyntheticBusinessUser()
    {
        var resolver = new FreeImNoLocalShadowUserResolver();

        Assert.Null(await resolver.ResolveAsync("iam-user-001"));
        Assert.Null(await resolver.EnsureAsync("iam-user-001", "user", "User"));
    }
}
