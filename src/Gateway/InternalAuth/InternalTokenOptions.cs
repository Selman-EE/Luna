namespace Gateway.InternalAuth;

public sealed class InternalTokenOptions
{
    public string Issuer { get; init; } = "company-gateway";
    public string KeyId { get; init; } = "gw-1";
    public int TtlSeconds { get; init; } = 120;
    public string PrivateKeyPemPath { get; init; } = "keys/internal-signing-private.pem";
    public string PublicKeyPemPath { get; init; } = "keys/internal-signing-public.pem";
}
