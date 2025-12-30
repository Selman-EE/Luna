using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;

namespace Gateway.InternalAuth;

public sealed class YarpInternalAuthTransformProvider : ITransformProvider
{
    public const string ConfigName = "ReverseProxy";

    public void Apply(TransformBuilderContext context)
    {
        if (context.Route.Metadata is null || !context.Route.Metadata.TryGetValue("InternalAudience", out var audObj))
            return;

        if (string.IsNullOrWhiteSpace(audObj))
            return;

        var routeId = context.Route.RouteId;

        context.AddRequestTransform(async transformContext =>
        {
            var http = transformContext.HttpContext;

            // 1) user must be authenticated at gateway
            if (!(http.User?.Identity?.IsAuthenticated ?? false))
            {
                transformContext.ProxyRequest.Headers.Remove("Authorization");
                http.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }

            // 2) build request for scope resolution (tenant optional)
            var tenantId = http.Request.Headers["X-Tenant-Id"].FirstOrDefault();

            var req = new InternalScopeRequest(
                RouteId: routeId,
                Audience: audObj!,
                HttpMethod: http.Request.Method.ToUpperInvariant(),
                Path: http.Request.Path.Value ?? "/",
                TenantId: tenantId
            );

            // 3) resolve scopes (deny-by-default)
            var resolver = http.RequestServices.GetRequiredService<IInternalScopeResolver>();
            var scopes = await resolver.ResolveAsync(req, http.User, http.RequestAborted);

            if (scopes.Length == 0)
            {
                transformContext.ProxyRequest.Headers.Remove("Authorization");
                http.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }

            // 4) mint internal JWT & replace Authorization
            var issuer = http.RequestServices.GetRequiredService<InternalTokenIssuer>();
            var internalJwt = issuer.MintForService(http.User, audObj!, scopes, actorService: "api-gateway");

            transformContext.ProxyRequest.Headers.Remove("Authorization");
            transformContext.ProxyRequest.Headers.Add("Authorization", $"Bearer {internalJwt}");

            // optional: pass tenant downstream too
            if (!string.IsNullOrWhiteSpace(tenantId))
            {
                transformContext.ProxyRequest.Headers.Remove("X-Tenant-Id");
                transformContext.ProxyRequest.Headers.Add("X-Tenant-Id", tenantId);
            }

            transformContext.ProxyRequest.Headers.Remove("X-Trace-Id");
            transformContext.ProxyRequest.Headers.Add("X-Trace-Id", http.TraceIdentifier);
        });
    }

    public void ValidateRoute(TransformRouteValidationContext context)
    {
    }

    public void ValidateCluster(TransformClusterValidationContext context)
    {
    }
}