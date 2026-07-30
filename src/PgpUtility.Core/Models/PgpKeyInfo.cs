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
    public bool HasPublicKey => !string.IsNullOrEmpty(PublicKeyFile);
    public string PublicKeyFile { get; set; } = string.Empty;
    public string? PrivateKeyFile { get; set; }
}
