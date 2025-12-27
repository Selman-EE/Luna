namespace Gateway.InternalAuth;

public interface IGatewayScopeResolver
{
    string[] ResolveScopes(string routeId, string httpMethod);
}
