using System.Diagnostics;
using PgpUtility.Models;
using PgpUtility.Services;

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
        psi.ArgumentList.Add(ToGpgPath(Home));
        foreach (string argument in arguments)
            psi.ArgumentList.Add(ToGpgPath(argument));

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
    /// Rewrites a rooted Windows path into the /c/... form when the gpg on PATH is an MSYS
    /// build, and returns everything else unchanged.
    /// </summary>
    /// <remarks>
    /// The gpg inside Git for Windows is compiled against the MSYS runtime, and a Windows-style
    /// path breaks it in version-dependent ways: the build on the CI image treats C:\... as
    /// relative and fails with "no writable keyring found", while an older local build accepted
    /// the keyring path and then could not talk to its agent. Handing it /c/... instead makes the
    /// homedir, the file arguments and gpg-agent all work, which is what lets the
    /// interoperability tests run on a machine whose only gpg is Git's. A native build (Gpg4win)
    /// takes C:\... as-is and is left alone.
    /// </remarks>
    private static string ToGpgPath(string argument)
    {
        if (!GpgIsMsys.Value)
            return argument;

        bool looksLikeRootedWindowsPath =
            argument.Length >= 3
            && char.IsAsciiLetter(argument[0])
            && argument[1] == ':'
            && (argument[2] == '\\' || argument[2] == '/');
        if (!looksLikeRootedWindowsPath)
            return argument;

        return "/" + char.ToLowerInvariant(argument[0]) + argument[2..].Replace('\\', '/');
    }

    /// <summary>
    /// True when the gpg that PATH resolves to is an MSYS build. The msys-2.0.dll sitting next
    /// to gpg.exe is the marker; Git for Windows and MSYS2 both have it, a native build does not.
    /// </summary>
    private static readonly Lazy<bool> GpgIsMsys = new(() =>
    {
        if (!OperatingSystem.IsWindows())
            return false;

        string pathVariable = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (string entry in pathVariable.Split(
            Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                if (!File.Exists(Path.Combine(entry, "gpg.exe")))
                    continue;

                return File.Exists(Path.Combine(entry, "msys-2.0.dll"));
            }
            catch (ArgumentException)
            {
                // A malformed PATH entry cannot be the directory gpg runs from. Skip it.
            }
        }

        return false;
    });

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

            // Importing a key we generated is the first thing every interoperability test does,
            // so the probe does exactly that. Two weaker probes shipped before this one and both
            // reported usable while the tests failed: --version alone said nothing about file
            // operations, and importing a file that was deliberately not a key produced "no
            // valid OpenPGP data found", which is not the error a broken homedir produces on a
            // real key.
            //
            // The check is on the message, deliberately not the exit code. A gpg whose agent
            // cannot start, which is normal on CI runners (macOS, and any temp directory deep
            // enough to push the agent socket past the 108 byte sun_path limit), still imports
            // the key, prints "imported: 1", and exits 2. The public key tests pass on exactly
            // such a machine because they never assert the import's exit code; a probe that
            // required exit 0 here skipped them on every runner they were meant for.
            GeneratedKeyPair pair = new PgpService().GenerateKeyPairAsync(new KeyGenerationOptions
            {
                Name = "Gpg Probe",
                Email = "gpg-probe@example.com",
                Passphrase = "probe".ToCharArray(),
                Algorithm = PgpKeyAlgorithm.Ed25519
            }).GetAwaiter().GetResult();

            using var work = new TempWorkspace();
            string keyFile = work.Path("probe-pub.asc");
            File.WriteAllText(keyFile, pair.PublicKey);

            Result import = probe.Run("--import", keyFile);
            if (!import.All.Contains("imported", StringComparison.OrdinalIgnoreCase))
                return (false, $"gpg could not import a key we generated: {import.All.Trim()}");

            // The tests do assert exit codes on listing and encrypting, so require a clean exit
            // from the one of those the probe can do without a recipient.
            Result listed = probe.Run("--list-keys");
            if (!listed.Ok)
                return (false, $"gpg --list-keys exited {listed.ExitCode}: {listed.All.Trim()}");

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
            psi.ArgumentList.Add(ToGpgPath(Home));
            psi.ArgumentList.Add("--kill");
            psi.ArgumentList.Add("all");
            using Process? kill = Process.Start(psi);
            kill?.WaitForExit(5000);
        }
        catch { }

        _work.Dispose();
    }
}
