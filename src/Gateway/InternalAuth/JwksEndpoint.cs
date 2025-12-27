using Microsoft.IdentityModel.Tokens;
using System.Text.Json;

namespace Gateway.InternalAuth;

public static class JwksEndpoint
{
    public static void MapInternalJwks(this WebApplication app)
    {
        app.MapGet("/.well-known/internal-jwks.json", (InternalTokenIssuer issuer) =>
        {
            var keys = issuer.GetAllPublicKeys()
                .Select(k =>
                {
                    var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(k);
                    jwk.Alg = SecurityAlgorithms.RsaSha256;

                    return new
                    {
                        kty = jwk.Kty,
                        use = "sig",
                        alg = jwk.Alg,
                        kid = jwk.Kid,
                        n = jwk.N,
                        e = jwk.E
                    };
                })
                .ToArray();

            return Results.Json(new { keys }, new JsonSerializerOptions { WriteIndented = true });
        });
    }
}