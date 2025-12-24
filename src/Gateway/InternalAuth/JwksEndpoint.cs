using Microsoft.AspNetCore.Builder;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;

namespace Gateway.InternalAuth;

public static class JwksEndpoint
{
    public static void MapInternalJwks(this WebApplication app)
    {
        app.MapGet("/.well-known/internal-jwks.json", (InternalTokenIssuer issuer) =>
        {
            var key = issuer.GetPublicSigningKey();
            var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(key);
            jwk.Alg = SecurityAlgorithms.RsaSha256;

            var payload = new
            {
                keys = new object[]
                {
                    new
                    {
                        kty = jwk.Kty,
                        use = "sig",
                        alg = jwk.Alg,
                        kid = jwk.Kid,
                        n = jwk.N,
                        e = jwk.E
                    }
                }
            };

            return Results.Json(payload, new JsonSerializerOptions { WriteIndented = true });
        });
    }
}
