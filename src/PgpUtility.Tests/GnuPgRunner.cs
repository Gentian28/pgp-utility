using System.Diagnostics;

namespace PgpUtility.Tests;

/// <summary>
/// Runs gpg against a throwaway home directory.
/// </summary>
/// <remarks>
/// The home directory is never the caller's real one. Importing test keys into a developer's own
/// keyring, or worse writing to their trustdb, is not something a test suite should be able to do
/// by accident.
/// </remarks>
public sealed class GnuPgRunner : IDisposable
{
    private readonly TempWorkspace _work = new();

    public string Home { get; }

    public GnuPgRunner()
    {
        Home = _work.Path("gnupg");
        Directory.CreateDirectory(Home);
    }

    public sealed record Result(int ExitCode, string StandardOutput, string StandardError)
    {
        public bool Ok => ExitCode == 0;

        /// <summary>Both streams together, for assertions that do not care which one it landed on.</summary>
        public string All => StandardOutput + "\n" + StandardError;
    }

    public Result Run(params string[] arguments)
    {
        var psi = new ProcessStartInfo("gpg")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        psi.ArgumentList.Add("--batch");
        psi.ArgumentList.Add("--yes");
        psi.ArgumentList.Add("--homedir");
        psi.ArgumentList.Add(Home);
        foreach (string argument in arguments)
            psi.ArgumentList.Add(argument);

        using Process process = Process.Start(psi)
            ?? throw new InvalidOperationException("could not start gpg");

        // Read both streams before waiting. gpg is chatty on stderr and a full pipe buffer would
        // deadlock a wait-then-read.
        Task<string> stdout = process.StandardOutput.ReadToEndAsync();
        Task<string> stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();

        return new Result(process.ExitCode, stdout.Result, stderr.Result);
    }

    /// <summary>
    /// Set this environment variable on any machine where gpg is expected to work, and a probe
    /// failure throws instead of skipping.
    /// </summary>
    /// <remarks>
    /// CI sets it. Interoperability is the claim most worth checking, so a suite that quietly
    /// skips those tests when gpg breaks would report green while proving nothing, which is worse
    /// than having no interoperability tests at all: it looks like evidence.
    /// </remarks>
    public const string RequireVariable = "PGPUTILITY_REQUIRE_GPG";

    /// <summary>
    /// True when the gpg binary responds. Enough for anything that only touches public keys:
    /// importing a public key, listing keys, encrypting to a recipient, inspecting packets.
    /// </summary>
    public static bool IsUsable => BinaryWorks.Value;

    /// <summary>
    /// True when gpg-agent can also start, which everything involving a secret key needs.
    /// </summary>
    /// <remarks>
    /// Split from <see cref="IsUsable"/> deliberately. The agent cannot start in some sandboxes
    /// even where the binary is fine, and folding both into one flag would skip the public key
    /// half of the interoperability evidence for a reason that does not apply to it.
    /// </remarks>
    public static bool CanUseSecretKeys => AgentWorks.Value;

    private static readonly Lazy<bool> BinaryWorks = new(() => Gate("gpg", ProbeBinary));

    private static readonly Lazy<bool> AgentWorks = new(() => BinaryWorks.Value && Gate("gpg-agent", ProbeAgent));

    private static bool Gate(string what, Func<(bool Ok, string Reason)> probe)
    {
        (bool ok, string reason) = probe();

        if (!ok && !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(RequireVariable)))
        {
            throw new InvalidOperationException(
                $"{RequireVariable} is set, so the GnuPG interoperability tests must run, but {what} is not usable here: {reason}");
        }

        return ok;
    }

    private static (bool, string) ProbeBinary()
    {
        try
        {
            using var probe = new GnuPgRunner();

            Result version = probe.Run("--version");
            if (!version.Ok)
                return (false, $"gpg --version exited {version.ExitCode}: {version.All.Trim()}");

            // Then check it can actually read a file at a path we produced, which is what every
            // test here does and is a separate question from whether the binary runs.
            //
            // The gpg bundled with Git for Windows answers --version happily and then fails every
            // file operation with "error reading ... General error", so a version-only probe
            // reported usable and the suite failed instead of skipping. Feeding it a file that is
            // deliberately not a key separates the two outcomes: "no valid OpenPGP data found"
            // means it read the file and rejected the contents, which is a pass here.
            using var work = new TempWorkspace();
            string probeFile = work.Path("probe.txt");
            File.WriteAllText(probeFile, "not a key, and not meant to be");

            Result import = probe.Run("--import", probeFile);
            if (import.All.Contains("error reading", StringComparison.OrdinalIgnoreCase))
                return (false, $"gpg cannot read files at our paths: {import.All.Trim()}");

            return (true, "");
        }
        catch (Exception ex)
        {
            // Missing binary, blocked process start, anything else.
            return (false, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static (bool, string) ProbeAgent()
    {
        try
        {
            using var probe = new GnuPgRunner();

            // Generating a throwaway key is the cheapest thing that exercises the agent end to
            // end, and it is what every secret key test here depends on.
            Result generated = probe.Run(
                "--pinentry-mode", "loopback", "--passphrase", "probe",
                "--quick-generate-key", "Probe <probe@example.com>", "ed25519", "sign", "0");

            return generated.Ok
                ? (true, "")
                : (false, $"could not generate a probe key: {generated.All.Trim()}");
        }
        catch (Exception ex)
        {
            return (false, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    public void Dispose()
    {
        // gpg-agent holds handles under the home directory and does not always exit promptly.
        // Ask it to stop so the workspace can actually be deleted.
        try { Run("--quiet", "--no-autostart", "--card-status"); } catch { }
        try
        {
            var psi = new ProcessStartInfo("gpgconf")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            psi.ArgumentList.Add("--homedir");
            psi.ArgumentList.Add(Home);
            psi.ArgumentList.Add("--kill");
            psi.ArgumentList.Add("all");
            using Process? kill = Process.Start(psi);
            kill?.WaitForExit(5000);
        }
        catch { }

        _work.Dispose();
    }
}
