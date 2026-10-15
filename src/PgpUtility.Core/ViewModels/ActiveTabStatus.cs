using System.ComponentModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PgpUtility.ViewModels;

/// <summary>Keeps the footer tied to the current operation rather than the last log entry.</summary>
public sealed class ActiveTabStatus : ObservableObject
{
    private ViewModelBase? _active;

    public string StatusMessage => _active?.StatusMessage ?? string.Empty;

    public void Follow(ViewModelBase viewModel)
    {
        if (ReferenceEquals(_active, viewModel)) return;
        if (_active is not null) _active.PropertyChanged -= OnActivePropertyChanged;
        _active = viewModel;
        _active.PropertyChanged += OnActivePropertyChanged;
        OnPropertyChanged(nameof(StatusMessage));
    }

    private void OnActivePropertyChanged(object? sender, PropertyChangedEventArgs args)
    {
        if (args.PropertyName is null or "" or nameof(ViewModelBase.StatusMessage))
            OnPropertyChanged(nameof(StatusMessage));
    }
}
