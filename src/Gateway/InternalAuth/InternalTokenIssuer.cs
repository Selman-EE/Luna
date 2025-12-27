using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Gateway.InternalAuth;

public sealed class InternalTokenIssuer
{
    private readonly InternalTokenOptions _opt;

    private readonly Dictionary<string, SigningCredentials> _signingCredsByKid = new(StringComparer.Ordinal);
    private readonly Dictionary<string, RsaSecurityKey> _publicKeysByKid = new(StringComparer.Ordinal);

    public InternalTokenIssuer(IOptions<InternalTokenOptions> opt)
    {
        _opt = opt.Value;

        if (_opt.Keys.Count == 0)
            throw new InvalidOperationException("InternalTokens.Keys must contain at least one key.");

        foreach (var k in _opt.Keys)
        {
            if (string.IsNullOrWhiteSpace(k.KeyId))
                throw new InvalidOperationException("InternalTokens.Keys[].KeyId is required.");

            var rsaPriv = PemKeyLoader.LoadRsaPrivateKeyFromPem(k.PrivateKeyPemPath);
            var signingKey = new RsaSecurityKey(rsaPriv) { KeyId = k.KeyId };
            _signingCredsByKid[k.KeyId] = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);

            var rsaPub = PemKeyLoader.LoadRsaPublicKeyFromPem(k.PublicKeyPemPath);
            _publicKeysByKid[k.KeyId] = new RsaSecurityKey(rsaPub) { KeyId = k.KeyId };
        }

        if (!_signingCredsByKid.ContainsKey(_opt.ActiveKeyId))
            throw new InvalidOperationException($"ActiveKeyId '{_opt.ActiveKeyId}' not found in InternalTokens.Keys.");
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

        foreach (var scp in scopes)
            claims.Add(new("scp", scp));

        var token = new JwtSecurityToken(
            issuer: _opt.Issuer,
            audience: audience,
            claims: claims,
            notBefore: now.UtcDateTime.AddSeconds(-5),
            expires: expires.UtcDateTime,
            signingCredentials: _signingCredsByKid[_opt.ActiveKeyId]
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public IReadOnlyCollection<RsaSecurityKey> GetAllPublicKeys()
        => _publicKeysByKid.Values.ToArray();
}
