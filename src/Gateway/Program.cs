using Gateway.InternalAuth;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Internal token issuer
builder.Services.Configure<InternalTokenOptions>(builder.Configuration.GetSection("InternalTokens"));
builder.Services.AddSingleton<InternalTokenIssuer>();

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var ext = builder.Configuration.GetSection("ExternalAuth");

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = ext["Issuer"],
            ValidateAudience = true,
            ValidAudience = ext["Audience"],
            ValidateIssuerSigningKey = true,

            // DEV ONLY (symmetric). Replace with your real signing validation.
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(ext["SigningKey"] ?? "dev-dev")),

            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(10)
        };
    });

builder.Services.AddAuthorization();

// YARP + internal auth header transform
builder.Services
    .AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms<YarpInternalAuthTransformProvider>();

var app = builder.Build();

app.MapInternalJwks();
app.UseAuthentication();
app.UseAuthorization();

// Require auth for all proxied routes (you can allow-list some paths if needed)
app.MapReverseProxy(proxyPipeline =>
{
    proxyPipeline.Use(async (context, next) =>
    {
        if (!(context.User?.Identity?.IsAuthenticated ?? false))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        await next();
    });
});

app.MapGet("/health", () => Results.Ok(new { ok = true }));
app.MapGet("/{**any}", (HttpRequest req) =>
{
    return Results.Ok(req.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()));
});

app.Run();
