namespace PgpUtility.Models;

/// <summary>Prevents an asynchronous result from describing superseded input.</summary>
public sealed class OperationRevision
{
    private int _revision;
    public int Next() => Interlocked.Increment(ref _revision);
    public bool IsCurrent(int revision) => Volatile.Read(ref _revision) == revision;
}
