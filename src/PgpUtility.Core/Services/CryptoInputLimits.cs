using System.Text;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace PgpUtility.Services;

internal static class CryptoInputLimits
{
    public const int TextBytes = 16 * 1024 * 1024;
    public static void CheckText(string text)
    {
        if (Encoding.UTF8.GetByteCount(text) > TextBytes)
            throw new PgpException("This message is too large for Text. Use the Files tab for data above 16 MiB.");
    }
    public static void CheckKey(Stream input)
    {
        if (input.CanSeek && input.Length - input.Position > TextBytes)
            throw new PgpException("This key file exceeds the supported 16 MiB limit.");
    }
}
