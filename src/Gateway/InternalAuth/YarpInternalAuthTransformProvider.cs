using Microsoft.AspNetCore.Http;
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

        var scopes = Array.Empty<string>();
        if (context.Route.Metadata.TryGetValue("InternalScopes", out var scopesObj))
        {
            scopes = (scopesObj?.ToString() ?? "")
                .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        context.AddRequestTransform(transformContext =>
        {
            var http = transformContext.HttpContext;

            if (!(http.User?.Identity?.IsAuthenticated ?? false))
            {
                transformContext.ProxyRequest.Headers.Remove("Authorization");
                return ValueTask.CompletedTask;
            }

            var issuer = http.RequestServices.GetRequiredService<InternalTokenIssuer>();

            // NOTE: later you can compute scopes dynamically per user/route/action.
            var internalJwt = issuer.MintForService(http.User, audience!, scopes, actorService: "api-gateway");

            // Replace external Authorization with internal one
            transformContext.ProxyRequest.Headers.Remove("Authorization");
            transformContext.ProxyRequest.Headers.Add("Authorization", $"Bearer {internalJwt}");

            // Optional correlation
            transformContext.ProxyRequest.Headers.Remove("X-Trace-Id");
            transformContext.ProxyRequest.Headers.Add("X-Trace-Id", http.TraceIdentifier);

            return ValueTask.CompletedTask;
        });
    }

    public void ValidateRoute(TransformRouteValidationContext context) { }
    public void ValidateCluster(TransformClusterValidationContext context) { }
}
