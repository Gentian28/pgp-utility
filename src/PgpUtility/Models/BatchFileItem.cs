using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PgpUtility.Models;

public partial class BatchFileItem : ObservableObject
{
    [ObservableProperty]
    private string _filePath = string.Empty;

    [ObservableProperty]
    private string _fileName = string.Empty;

    [ObservableProperty]
    private string _status = "Pending";

    [ObservableProperty]
    private string? _errorMessage;

    [ObservableProperty]
    private bool _isProcessing;

    [ObservableProperty]
    private bool _isCompleted;

    public BatchFileItem(string filePath)
    {
        FilePath = filePath;
        FileName = Path.GetFileName(filePath);
    }
}
