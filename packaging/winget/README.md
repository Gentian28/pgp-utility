# winget manifests

One folder per released version, `Gentian28.PgpUtility` as the permanent package identity, same
conventions as resume-builder's `packaging/winget/`. Keep the two repos in step rather than
letting them drift.

## Releasing a new version

`new-version.ps1` does the mechanical part. Run it **after** the GitHub release is published,
because it reads the released `SHA256SUMS-win.txt` so the hash always matches what people
actually download:

```powershell
.\packaging\winget\new-version.ps1 -Version 1.1.0
winget install --manifest packaging\winget\1.1.0   # verify it really installs
wingetcreate submit --token <github-PAT> packaging\winget\1.1.0
```

Local manifest installs are disabled by default; enable once from an administrator PowerShell
with `winget settings --enable LocalManifestFiles`. The install itself is per-user and needs no
elevation.

`.github/workflows/winget.yml` automates all of this on every published release, but stays inert
until two things exist: a repository variable `WINGET_AUTO_SUBMIT` set to `true`, and a
`WINGET_TOKEN` secret holding a PAT with `public_repo` scope. Leave it off until the first
submission has merged.

## The first submission

The first PR to microsoft/winget-pkgs carries package-identity review (publisher, package ID,
licence, installer type) and a human moderator, so expect a wait measured in weeks. Version bumps
after that ride through on the established identity. The account-level CLA is already signed
from the resume-builder submission.

Test-install the exact released build before submitting. Resume-builder shipped two versions
with an off-screen-window bug that only a real install caught; submitting either would have put
a broken build in Microsoft's index.
