var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCarter();

// Internal token issuer
builder.Services.Configure<InternalTokenOptions>(builder.Configuration.GetSection(InternalTokenOptions.ConfigName));
builder.Services.AddSingleton<InternalTokenIssuer>();
builder.Services.AddJwtBearerAuth(builder.Configuration);
builder.Services.AddAuthorization();

// YARP + internal auth header transform
builder.Services
    .AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection(YarpInternalAuthTransformProvider.ConfigName))
    .AddTransforms<YarpInternalAuthTransformProvider>();

builder.Services.AddSingleton<IGatewayScopeResolver, ConfigGatewayScopeResolver>();

builder.Services.AddGatewayScopesFusionCacheWithRedis(builder.Configuration);
// Permission store lives in Gateway (DB later)
builder.Services.AddSingleton<IInternalPermissionStore, ConfigPermissionStore>();
builder.Services.AddGatewayScopeResolution(opt =>
{
    opt.CacheKeyPrefix = "luna:internalscopes:";
    opt.CacheTtl = TimeSpan.FromSeconds(30);
});

var app = builder.Build();

app.MapInternalJwks();
app.UseAuthentication();
app.UseAuthorization();
app.MapCarter();

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

app.Run();