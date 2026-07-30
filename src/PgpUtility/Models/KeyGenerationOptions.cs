namespace PgpUtility.Models;

public class KeyGenerationOptions
{
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Passphrase { get; set; } = string.Empty;
    public int KeySize { get; set; } = 2048;
    public DateTime? ExpirationDate { get; set; }

    public string Identity => string.IsNullOrWhiteSpace(Email)
        ? Name
        : $"{Name} <{Email}>";
}
