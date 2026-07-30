using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace PgpUtility.App.ViewModels;

/// <summary>
/// The handful of value converters the views need.
/// </summary>
/// <remarks>
/// Avalonia ships boolean negation as the <c>!</c> binding operator and null checks as
/// <c>x:Static</c> converters, so this is only for cases with no built-in equivalent.
/// </remarks>
public static class Converters
{
    /// <summary>Labels the action button for the mode it is in.</summary>
    public static readonly IValueConverter EncryptOrDecrypt =
        new FuncValueConverter<bool, string>(isEncrypt => isEncrypt ? "Encrypt" : "Decrypt");

    /// <summary>Formats an optional expiry as something a person reads, not a nullable date.</summary>
    public static readonly IValueConverter ExpiryText =
        new FuncValueConverter<DateTime?, string>(static expiry =>
            expiry is null
                ? "Never expires"
                : expiry.Value < DateTime.UtcNow
                    ? $"Expired {Format(expiry.Value)}"
                    : $"Expires {Format(expiry.Value)}");

    /// <summary>True when a key has expired, so the view can colour it.</summary>
    public static readonly IValueConverter HasExpired =
        new FuncValueConverter<DateTime?, bool>(static expiry => expiry is not null && expiry.Value < DateTime.UtcNow);

    /// <summary>
    /// Groups a fingerprint into blocks of four.
    /// </summary>
    /// <remarks>
    /// Forty unbroken hex characters cannot be compared by eye, and comparing fingerprints by eye
    /// is the entire point of showing one.
    /// </remarks>
    public static readonly IValueConverter SpacedFingerprint =
        new FuncValueConverter<string?, string>(static fingerprint =>
        {
            if (string.IsNullOrEmpty(fingerprint)) return string.Empty;

            var builder = new System.Text.StringBuilder(fingerprint.Length + fingerprint.Length / 4);
            for (int i = 0; i < fingerprint.Length; i++)
            {
                if (i > 0 && i % 4 == 0) builder.Append(' ');
                builder.Append(fingerprint[i]);
            }
            return builder.ToString();
        });

    /// <summary>Formats a date without dragging culture-specific noise into the XAML.</summary>
    public static readonly IValueConverter ShortDate =
        new FuncValueConverter<DateTime, string>(static value => Format(value));

    /// <summary>
    /// One date format for the whole app.
    /// </summary>
    /// <remarks>
    /// Shared so a single screen cannot show "30 Jul 2026" next to "7/30/2028", which is what
    /// happened when the expiry text formatted its own. Day-month-year spelled out rather than
    /// numeric, because 7/30 and 30/7 are the same date to different readers.
    /// </remarks>
    private static string Format(DateTime value) =>
        value.ToLocalTime().ToString("d MMM yyyy", CultureInfo.CurrentCulture);

    /// <summary>
    /// Turns BouncyCastle's algorithm tag into the name people actually use.
    /// </summary>
    /// <remarks>
    /// The raw tag is stored, not this, because the stored value should stay stable and
    /// machine-readable. But "EdDsa" is an internal spelling and means nothing to someone
    /// deciding whether a key is modern, while "Ed25519" is the name on every guide.
    /// </remarks>
    public static readonly IValueConverter AlgorithmName =
        new FuncValueConverter<string?, string>(static tag => tag switch
        {
            "EdDsa" or "EdDsa_Legacy" => "Ed25519",
            "ECDH" => "Curve25519",
            "RsaGeneral" or "RsaSign" or "RsaEncrypt" => "RSA",
            "ECDsa" => "ECDSA",
            "Dsa" => "DSA",
            "ElGamalEncrypt" or "ElGamalGeneral" => "ElGamal",
            null or "" => "Unknown",
            _ => tag
        });

    /// <summary>
    /// A key size only worth showing for the algorithms where it varies.
    /// </summary>
    /// <remarks>
    /// Ed25519 reports 255 bits, which reads as weaker than RSA-2048 to anyone comparing the two
    /// numbers, when it is considerably stronger. Better to say nothing than to invite that.
    /// </remarks>
    public static readonly IValueConverter KeySizeIfMeaningful =
        new FuncValueConverter<string?, bool>(static tag =>
            tag is "RsaGeneral" or "RsaSign" or "RsaEncrypt" or "Dsa" or "ElGamalEncrypt" or "ElGamalGeneral");

    public static readonly IValueConverter SignOrVerify =
        new FuncValueConverter<bool, string>(isSign => isSign ? "Sign" : "Verify");

    public static readonly IValueConverter SignOrVerifyKeyLabel =
        new FuncValueConverter<bool, string>(isSign => isSign ? "Sign with" : "Expected signer");

    /// <summary>
    /// The one line someone actually reads after verifying, so it says the answer rather than
    /// restating the question.
    /// </summary>
    public static readonly IValueConverter SignatureHeadline =
        new FuncValueConverter<bool, string>(valid => valid ? "Signature is good" : "Signature is NOT valid");

    public static readonly IValueConverter SignatureBrush =
        new FuncValueConverter<bool, IBrush>(static valid => valid
            ? new SolidColorBrush(Color.FromRgb(0x4A, 0xDE, 0x80))
            : new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71)));
}
