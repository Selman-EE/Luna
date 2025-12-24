using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Gateway.InternalAuth;

public sealed class InternalTokenIssuer
{
    private readonly InternalTokenOptions _opt;
    private readonly RsaSecurityKey _signingKey;
    private readonly SigningCredentials _creds;

    public InternalTokenIssuer(IOptionsMonitor<InternalTokenOptions> opt)
    {
        _opt = opt.CurrentValue;

        var rsa = PemKeyLoader.LoadRsaPrivateKeyFromPem(_opt.PrivateKeyPemPath);
        _signingKey = new RsaSecurityKey(rsa) { KeyId = _opt.KeyId };

        _creds = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);
    }

    public string MintForService(
        ClaimsPrincipal user,
        string audience,
        IReadOnlyCollection<string> scopes,
        string actorService = "api-gateway")
    {
        var userId =
            user.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? user.FindFirstValue("sub")
            ?? "user:unknown";

        var now = DateTimeOffset.UtcNow;
        var expires = now.AddSeconds(_opt.TtlSeconds);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new("act", actorService),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };
        
        claims.AddRange(scopes.Select(scp => new Claim("scp", scp)));

        var token = new JwtSecurityToken(
            issuer: _opt.Issuer,
            audience: audience,
            claims: claims,
            notBefore: now.UtcDateTime.AddSeconds(-5),
            expires: expires.UtcDateTime,
            signingCredentials: _creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public RsaSecurityKey GetPublicSigningKey()
    {
        var rsaPublic = PemKeyLoader.LoadRsaPublicKeyFromPem(_opt.PublicKeyPemPath);
        return new RsaSecurityKey(rsaPublic) { KeyId = _opt.KeyId };
    }

    public string Issuer => _opt.Issuer;
    public string KeyId => _opt.KeyId;
}