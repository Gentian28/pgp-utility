namespace PgpUtility.Services;

public interface IClipboardService
{
    Task SetTextAsync(string text);
    Task<string?> GetTextAsync();
}
