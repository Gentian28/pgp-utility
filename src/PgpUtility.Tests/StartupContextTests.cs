using PgpUtility.Services;

namespace PgpUtility.Tests;

public class StartupContextTests
{
    [Fact]
    public async Task Store_initialization_never_needs_a_callback_on_its_blocked_calling_context()
    {
        using var work = new TempWorkspace();
        string directory = work.Path("store");
        Directory.CreateDirectory(directory);
        // Force asynchronous index copying, as happens during a desktop startup or refresh.
        File.WriteAllText(Path.Combine(directory, "index.json"), "[" + new string(' ', 1024 * 1024) + "]");
        var context = new RecordingContext();
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            SynchronizationContext.SetSynchronizationContext(context);
            try
            {
                var store = new KeyStoreService(new PgpService(), directory);
                store.GetAllKeys().Should().BeEmpty();
                finished.SetResult();
            }
            catch (Exception exception) { finished.SetException(exception); }
            finally { SynchronizationContext.SetSynchronizationContext(null); }
        }) { IsBackground = true };
        thread.Start();
        await finished.Task.WaitAsync(TimeSpan.FromSeconds(15));
        context.Posts.Should().Be(0, "the desktop thread blocks until initialization returns and cannot pump callbacks");
        Directory.GetFiles(directory, ".pgputility-*.partial").Should().BeEmpty();
        File.ReadAllText(Path.Combine(directory, "index.json")).Should().Be("[]");
    }

    private sealed class RecordingContext : SynchronizationContext
    {
        private int _posts;
        public int Posts => Volatile.Read(ref _posts);
        public override void Post(SendOrPostCallback callback, object? state)
        {
            Interlocked.Increment(ref _posts);
            // Let a broken implementation finish so the test reports capture without hanging.
            ThreadPool.QueueUserWorkItem(_ => callback(state));
        }
    }
}
