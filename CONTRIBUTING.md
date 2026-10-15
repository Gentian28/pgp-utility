# Contributing

Install the SDK selected by global.json. Versions and target frameworks live in the central props
files. Core owns cryptographic and toolkit-neutral operation state; the desktop App owns controls,
native pickers and clipboard integration. Tests reference Core only.

Before proposing a change, reproduce the issue with synthetic data. Never attach a real private
key, passphrase, plaintext message or key-store backup to an issue. Report security problems through
[the private process](SECURITY.md).

Run:

```sh
dotnet build PgpUtility.slnx -c Release -warnaserror
dotnet test PgpUtility.slnx -c Release --no-build
```

For crypto changes, put GnuPG on PATH and set `PGPUTILITY_REQUIRE_GPG=1` before running the suite.
Document which comparisons were run. A round trip through the same implementation does not prove
interoperability. CI makes GnuPG comparisons mandatory on Linux. Run the PowerShell dependency gate
with `pwsh -File scripts/check-vulnerabilities.ps1` and report failed feeds as failed checks.

Preserve these invariants: AES-256 and integrity checks for new messages, verification before output
commit, validated certificate ownership, full-fingerprint identity, UTF-8 passphrase handling,
array cleanup and no deletion of pre-existing outputs after an error. New output files must use
FileTransaction; replacement is reserved for controlled internal store updates.

Visible changes need an approved repo-owned design first and an update if implementation diverges.
Use synthetic identities, cover all affected screens, and verify keyboard access, both themes and
narrow widths in the running app. Keep the local-only product promise. Prefer a focused change with
its behavioral evidence and disclose limits of any platform verification.
