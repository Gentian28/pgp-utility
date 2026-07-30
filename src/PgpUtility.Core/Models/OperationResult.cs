namespace PgpUtility.Models;

public class OperationResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? OutputPath { get; set; }

    /// <summary>
    /// Set when the operation completed but something about it is worth telling the user, the one
    /// case today being a message that carried no integrity protection. A separate field rather
    /// than a prefix on <see cref="Message"/> so the UI can present it differently to a plain
    /// success and a caller can assert on it.
    /// </summary>
    public string? Warning { get; set; }

    public static OperationResult Succeeded(string message, string? outputPath = null, string? warning = null) =>
        new() { Success = true, Message = message, OutputPath = outputPath, Warning = warning };

    public static OperationResult Failed(string message) =>
        new() { Success = false, Message = message };
}
