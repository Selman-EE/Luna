using Carter;

namespace Gateway.Modules.Dev;

public sealed class DevAuthModule : ICarterModule
{
    public void AddRoutes(IEndpointRouteBuilder app)
    {
        // POST /dev/token  (DEV only)
        app.MapPost("/dev/token", (DevTokenRequest req, IConfiguration cfg, IHostEnvironment env) =>
        {
            if (!env.IsDevelopment())
                return Results.NotFound();

            var ext = cfg.GetSection("ExternalAuth");

            var issuer = ext["Issuer"];
            var audience = ext["Audience"];
            var signingKey = ext["SigningKey"];

            if (string.IsNullOrWhiteSpace(issuer) ||
                string.IsNullOrWhiteSpace(audience) ||
                string.IsNullOrWhiteSpace(signingKey))
            {
                return Results.Problem("ExternalAuth is not configured correctly (Issuer/Audience/SigningKey).");
            }

            var sub = string.IsNullOrWhiteSpace(req.Sub) ? "user-123" : req.Sub.Trim();

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, sub),
                new(ClaimTypes.NameIdentifier, sub),
            };

            if (req.Roles is { Length: > 0 })
                claims.AddRange(req.Roles.Where(r => !string.IsNullOrWhiteSpace(r))
                    .Select(r => new Claim(ClaimTypes.Role, r.Trim())));

            if (req.Permissions is { Length: > 0 })
                claims.AddRange(req.Permissions.Where(p => !string.IsNullOrWhiteSpace(p))
                    .Select(p => new Claim("perm", p.Trim())));

            var now = DateTimeOffset.UtcNow;
            var ttl = req.TtlMinutes <= 0 ? 60 : req.TtlMinutes;
            var expires = now.AddMinutes(ttl);

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                notBefore: now.UtcDateTime.AddSeconds(-5),
                expires: expires.UtcDateTime,
                signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return Results.Ok(new
            {
                access_token = jwt,
                token_type = "Bearer",
                expires_at_utc = expires.UtcDateTime
            });
        });

        // (DEV only, requires auth)
        app.MapGet("/dev/whoami", (HttpContext ctx, IHostEnvironment env) =>
            {
                if (!env.IsDevelopment())
                    return Results.NotFound();

                var claims = ctx.User.Claims.Select(c => new { c.Type, c.Value });
                return Results.Ok(new
                {
                    authenticated = ctx.User.Identity?.IsAuthenticated == true,
                    claims
                });
            })
            .RequireAuthorization();
    }
}