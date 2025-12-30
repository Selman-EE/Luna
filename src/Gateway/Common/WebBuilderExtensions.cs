using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Gateway.Common;

public static class WebBuilderExtensions
{
    private const string ExternalAuth = "ExternalAuth";

    public static IServiceCollection AddJwtBearerAuth(this IServiceCollection services, IConfiguration configuration)
    {
        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                var ext = configuration.GetSection(ExternalAuth);

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

        return services;
    }
}