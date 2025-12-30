using Carter;

namespace Gateway.Modules.HealthCheck;

public sealed class HealthCheckModule : ICarterModule
{
    public void AddRoutes(IEndpointRouteBuilder app)
    {
        // GET /health
        app.MapGet("/health", () => Results.Ok(new { ok = true }));

        // GET /debug/headers  (DEV only recommended)
        app.MapGet("/debug/headers", (HttpRequest req, IHostEnvironment env) =>
        {
            if (!env.IsDevelopment())
                return Results.NotFound();

            var headers = req.Headers.ToDictionary(h => h.Key, h => h.Value.ToString());
            return Results.Ok(headers);
        });
    }
}