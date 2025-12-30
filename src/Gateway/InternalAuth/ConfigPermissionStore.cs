namespace Gateway.InternalAuth;

public sealed class ConfigPermissionStore(IConfiguration cfg) : IInternalPermissionStore
{
    public Task<string[]> GetAllowedScopesAsync(
        InternalScopeRequest request,
        ClaimsPrincipal user,
        CancellationToken ct)
    {
        // TEMP: read from config (same map you already use).
        // Later: replace with DB (roles/permissions).
        var scopes = cfg
            .GetSection($"{GatewayScope}:{request.RouteId}:{request.HttpMethod}")
            .Get<string[]>() ?? new string[] { };

        return Task.FromResult(scopes);
    }
}