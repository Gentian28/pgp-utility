namespace PgpUtility.Models;

public class OperationResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? OutputPath { get; set; }

    public static OperationResult Succeeded(string message, string? outputPath = null) =>
        new() { Success = true, Message = message, OutputPath = outputPath };

    public static OperationResult Failed(string message) =>
        new() { Success = false, Message = message };
}
