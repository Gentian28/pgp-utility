using System.Runtime.InteropServices;
using System.Security;
using System.Windows.Controls;

namespace PgpUtility.Views;

internal static class PasswordBoxExtensions
{
    /// <summary>
    /// Copies what the user typed into a char array without ever reading
    /// <see cref="PasswordBox.Password"/>.
    /// </summary>
    /// <remarks>
    /// Reading <c>.Password</c> hands back an immutable string, and since PasswordChanged fires on
    /// every keystroke that is one string per prefix of the passphrase, all of them left on the
    /// heap for a collector that is free to copy them around and under no obligation to zero
    /// anything. <see cref="PasswordBox.SecurePassword"/> copies out of the same internal buffer
    /// without minting any of them.
    ///
    /// Defence in depth: fewer copies, and a window measured in the lifetime of one operation
    /// rather than the session. It is not protection against an attacker who can already read this
    /// process's memory, and it cannot stop the page being written to swap.
    /// </remarks>
    internal static char[] ReadPassphrase(this PasswordBox box)
    {
        using SecureString secure = box.SecurePassword;
        if (secure.Length == 0)
            return Array.Empty<char>();

        IntPtr unmanaged = IntPtr.Zero;
        try
        {
            unmanaged = Marshal.SecureStringToGlobalAllocUnicode(secure);
            var chars = new char[secure.Length];
            Marshal.Copy(unmanaged, chars, 0, chars.Length);
            return chars;
        }
        finally
        {
            if (unmanaged != IntPtr.Zero)
                Marshal.ZeroFreeGlobalAllocUnicode(unmanaged);
        }
    }
}
