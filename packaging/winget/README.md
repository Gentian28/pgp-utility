# winget manifests

Drafts for submitting PGP Utility to the winget community repository. They cannot be submitted
until the v1.0.0 GitHub release is public, because winget validates the installer URL and its
hash against the live download.

## Before submitting

1. Publish the v1.0.0 release and confirm `PgpUtility-win-Setup.exe` downloads from the URL in
   the installer manifest.
2. Replace the two `TODO` values in `GentianShkembi.PgpUtility.installer.yaml`: the SHA256 from
   `SHA256SUMS-win.txt` on the release page, and the release date.
3. Install the release build on a clean machine or VM and check Apps & Features. The
   `AppsAndFeaturesEntries` block must match the entry it writes exactly, DisplayName and
   DisplayVersion included, or winget will not recognise the app as installed.
4. Validate locally:

   ```
   winget validate --manifest packaging/winget
   winget install --manifest packaging/winget
   ```

5. Submit a pull request to https://github.com/microsoft/winget-pkgs placing these three files
   under `manifests/g/GentianShkembi/PgpUtility/1.0.0/`, or run `wingetcreate` and paste the
   values in. New packages get a human review, which can take a week or two.

## Things decided here that are hard to change later

- **PackageIdentifier `GentianShkembi.PgpUtility`** is permanent once the first version is
  merged. Renaming means deprecating the package and starting over.
- The installer is Velopack's Setup.exe: per-user scope, silent via `--silent`. Velopack apps
  self-update, so expect installed versions to drift ahead of the manifest; `UpgradeBehavior:
  install` keeps `winget upgrade` harmless in that case.

Each new release repeats steps 2 to 5 with a bumped `PackageVersion` in all three files.
