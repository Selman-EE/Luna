using System.Security.Cryptography;

namespace Gateway.InternalAuth;

public static class PemKeyLoader
{
    public static RSA LoadRsaPrivateKeyFromPem(string pemPath)
    {
        var pem = File.ReadAllText(pemPath);
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }

    public static RSA LoadRsaPublicKeyFromPem(string pemPath)
    {
        var pem = File.ReadAllText(pemPath);
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }
}