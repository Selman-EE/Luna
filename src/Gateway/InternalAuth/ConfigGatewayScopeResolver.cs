namespace Gateway.InternalAuth;

public sealed class ConfigGatewayScopeResolver(IConfiguration cfg) : IGatewayScopeResolver
{
    public string[] ResolveScopes(string routeId, string httpMethod)
        => cfg.GetSection($"{GatewayScope}:{routeId}:{httpMethod.ToUpperInvariant()}")
            .Get<string[]>() ?? [];
}