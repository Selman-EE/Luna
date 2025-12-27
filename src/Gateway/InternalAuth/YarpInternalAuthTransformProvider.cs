using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;

namespace Gateway.InternalAuth;

public sealed class YarpInternalAuthTransformProvider : ITransformProvider
{
    public void Apply(TransformBuilderContext context)
    {
        if (!context.Route.Metadata.TryGetValue("InternalAudience", out var audObj))
            return;

        var audience = audObj?.ToString();
        if (string.IsNullOrWhiteSpace(audience))
            return;

        var routeId = context.Route.RouteId;

        context.AddRequestTransform(transformContext =>
        {
            var http = transformContext.HttpContext;

            // must be authenticated (user JWT validated at gateway)
            if (!(http.User?.Identity?.IsAuthenticated ?? false))
            {
                transformContext.ProxyRequest.Headers.Remove("Authorization");
                http.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return ValueTask.CompletedTask;
            }

            var scopeResolver = http.RequestServices.GetRequiredService<IGatewayScopeResolver>();
            var scopes = scopeResolver.ResolveScopes(routeId, http.Request.Method);

            // deny-by-default if no mapping exists
            if (scopes.Length == 0)
            {
                transformContext.ProxyRequest.Headers.Remove("Authorization");
                http.Response.StatusCode = StatusCodes.Status403Forbidden;
                return ValueTask.CompletedTask;
            }

            var issuer = http.RequestServices.GetRequiredService<InternalTokenIssuer>();
            var internalJwt = issuer.MintForService(http.User, audience!, scopes, actorService: "api-gateway");

            // replace external token with internal token
            transformContext.ProxyRequest.Headers.Remove("Authorization");
            transformContext.ProxyRequest.Headers.Add("Authorization", $"Bearer {internalJwt}");

            transformContext.ProxyRequest.Headers.Remove("X-Trace-Id");
            transformContext.ProxyRequest.Headers.Add("X-Trace-Id", http.TraceIdentifier);

            return ValueTask.CompletedTask;
        });
    }

    public void ValidateRoute(TransformRouteValidationContext context) { }
    public void ValidateCluster(TransformClusterValidationContext context) { }
}
