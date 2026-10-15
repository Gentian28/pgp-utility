namespace PgpUtility.Models;

public sealed record BatchOutputPlan(string InputPath, string OutputPath)
{
    /// <summary>Reserves distinct output names without overwriting inputs or existing files.</summary>
    public static IReadOnlyList<BatchOutputPlan> Create(IEnumerable<string> inputs, string outputDirectory, bool encrypt, bool armor)
    {
        if (!Directory.Exists(outputDirectory)) throw new IOException("Choose an existing output folder.");
        var comparer = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        string[] sources = inputs.Select(Path.GetFullPath).ToArray();
        var reserved = new HashSet<string>(sources, comparer);
        var result = new List<BatchOutputPlan>();
        foreach (string source in sources)
        {
            string name = encrypt ? Path.GetFileName(source) + (armor ? ".asc" : ".pgp") : DecryptedName(source);
            string candidate = Path.GetFullPath(Path.Combine(outputDirectory, name));
            int suffix = 1;
            while (reserved.Contains(candidate) || File.Exists(candidate) || Directory.Exists(candidate))
            {
                suffix++;
                if (suffix > 10000) throw new IOException("Too many output name conflicts. Choose another output folder.");
                candidate = Path.GetFullPath(Path.Combine(outputDirectory,
                    Path.GetFileNameWithoutExtension(name) + $" ({suffix})" + Path.GetExtension(name)));
            }
            reserved.Add(candidate);
            result.Add(new(source, candidate));
        }
        return result;
    }

    private static string DecryptedName(string path)
    {
        string name = Path.GetFileName(path);
        foreach (string suffix in new[] { ".asc", ".pgp", ".gpg" })
            if (name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) && name.Length > suffix.Length)
                return name[..^suffix.Length];
        return name + ".decrypted";
    }
}
