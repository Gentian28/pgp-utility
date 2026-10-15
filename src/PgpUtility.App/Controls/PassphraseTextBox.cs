using System;
using Avalonia.Automation;
using Avalonia.Automation.Peers;
using Avalonia.Automation.Provider;
using Avalonia.Controls;

namespace PgpUtility.App.Controls;

/// <summary>Preserves editable accessibility without exposing the passphrase as an automation value.</summary>
public sealed class PassphraseTextBox : TextBox
{
    protected override Type StyleKeyOverride => typeof(TextBox);

    protected override AutomationPeer OnCreateAutomationPeer() => new PassphraseAutomationPeer(this);

    // TextBoxAutomationPeer returns Owner.Text and includes old/new plaintext in value-change
    // events, even when PasswordChar is set. Use a peer that never reads or publishes that text.
    private sealed class PassphraseAutomationPeer(PassphraseTextBox owner) : ControlAutomationPeer(owner), IValueProvider
    {
        public bool IsReadOnly => owner.IsReadOnly;
        public string Value => string.Empty;
        public void SetValue(string? value) => owner.Text = value;
        protected override AutomationControlType GetAutomationControlTypeCore() => AutomationControlType.Edit;
        protected override string GetClassNameCore() => nameof(PassphraseTextBox);
    }
}
