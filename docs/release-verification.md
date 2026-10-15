# Verify a release

Download the asset for your platform and the corresponding SHA256SUMS file from the same GitHub
release. Verify the exact file before opening it. A matching checksum detects a damaged or changed
file; it cannot establish authenticity when both the file and checksum come from a compromised source.

On Windows, compare `Get-FileHash <downloaded-file> -Algorithm SHA256` with its line in the checksum
file. On Linux use `sha256sum <downloaded-file>`, or `shasum -a 256 <downloaded-file>` on macOS.

New builds configured by .github/workflows/release.yml generate GitHub build provenance. When an
attestation exists for that release, use the GitHub CLI:

```sh
gh attestation verify <downloaded-file> --repo Gentian28/pgp-utility --signer-workflow Gentian28/pgp-utility/.github/workflows/release.yml
```

Read the verified source commit and workflow identity, and compare them with the intended tag.
If no attestation exists, this command cannot supply evidence that an older release never produced.
A failed check is a reason to stop and investigate. Follow the [GitHub CLI verification reference](https://cli.github.com/manual/gh_attestation_verify)
for the options available in your installed CLI. Provenance is not an independent code audit or a
Windows/macOS signing certificate. The app itself performs no online verification or update check.

## Maintainer release procedure

The release workflow builds a draft. Before making it public, verify the exact commit's build,
mandatory GnuPG comparisons, advisory check, and four native publish/startup jobs. Inspect the
release assets, hashes and attestations. Exercise installer and portable startup on each target OS,
including existing-store migration and a backup restore. Check keyboard access, light and dark themes,
and each tab at a narrow window size against the approved design. Do not equate a ten-second startup
check with an end-to-end installer or UI test.

Review the compatibility and security policy for the version being released. Handle security reports
privately and arrange disclosure with remediation. Screenshots must use synthetic identities and a
scratch store. Keep the design a proposal while release verification is outstanding; after shipping,
promote it to the current screen record and retire the historical screenshots it replaces.

Only publish after that review. Publishing triggers the existing opt-in winget submission flow;
its token and repository variable are managed separately. Never use a public issue or release asset
to publish an unremediated security reproduction.
