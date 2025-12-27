namespace Gateway.InternalAuth;

public sealed class InternalTokenOptions
{
    public string Issuer { get; init; } = "company-gateway";
    public int TtlSeconds { get; init; } = 120;

    // which key signs new tokens
    public string ActiveKeyId { get; init; } = "gw-2025-01";

    public List<InternalSigningKey> Keys { get; init; } = new();
}

public sealed class InternalSigningKey
{
    public string KeyId { get; init; } = "";
    public string PrivateKeyPemPath { get; init; } = "";
    public string PublicKeyPemPath { get; init; } = "";
}

