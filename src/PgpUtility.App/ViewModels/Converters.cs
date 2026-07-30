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
                    ? $"Expired {expiry.Value.ToLocalTime():d}"
                    : $"Expires {expiry.Value.ToLocalTime():d}");

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
        new FuncValueConverter<DateTime, string>(static value =>
            value.ToLocalTime().ToString("d MMM yyyy", CultureInfo.CurrentCulture));

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
