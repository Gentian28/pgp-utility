namespace PgpUtility.Models;

public class PgpKeyInfo
{
    public string KeyId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string Fingerprint { get; set; } = string.Empty;
    public string Algorithm { get; set; } = string.Empty;
    public int KeySize { get; set; }
    public DateTime CreationDate { get; set; }
    public DateTime? ExpirationDate { get; set; }
    public bool HasPrivateKey { get; set; }
    public bool IsRevoked { get; set; }
    public bool CanEncrypt { get; set; }
    public bool CanSign { get; set; }
    public string StatusText => IsRevoked ? "Revoked. Historical decryption remains available."
        : ExpirationDate < DateTime.UtcNow ? "Expired. Historical decryption remains available."
        : $"{(HasPrivateKey ? "Private key available" : "Public key only")}. {(CanEncrypt ? "Can receive encrypted messages. " : "")}{(CanSign ? "Can sign." : "")}";
    public bool HasPublicKey => !string.IsNullOrEmpty(PublicKeyFile);
    public string PublicKeyFile { get; set; } = string.Empty;
    public string? PrivateKeyFile { get; set; }
}
