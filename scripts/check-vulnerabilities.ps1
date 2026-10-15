$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    # Failed feeds and audit warnings are failures too, not a clean vulnerability report.
    & dotnet restore PgpUtility.slnx --force-evaluate -warnaserror -p:NuGetAudit=true -p:NuGetAuditMode=all
    if ($LASTEXITCODE -ne 0) { throw 'Restore or NuGet audit failed.' }

    $raw = & dotnet list PgpUtility.slnx package --vulnerable --include-transitive --format json --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'The dependency advisory query failed.' }
    $report = ($raw -join "`n") | ConvertFrom-Json -ErrorAction Stop
    if ($report.version -ne 1 -or @($report.projects).Count -ne 3) {
        throw 'The dependency advisory report has an unexpected schema or project count.'
    }
    if ($report.PSObject.Properties['problems'] -and @($report.problems).Count -gt 0) {
        throw 'The dependency advisory report contains problems.'
    }
    $vulnerable = @()
    foreach ($project in $report.projects) {
        if (-not $project.PSObject.Properties['frameworks']) { continue }
        foreach ($framework in $project.frameworks) {
            foreach ($kind in @('topLevelPackages', 'transitivePackages')) {
                if (-not $framework.PSObject.Properties[$kind]) { continue }
                foreach ($package in $framework.$kind) {
                    if ($package.PSObject.Properties['vulnerabilities'] -and @($package.vulnerabilities).Count -gt 0) {
                        $vulnerable += $package.id
                    }
                }
            }
        }
    }
    if ($vulnerable.Count -gt 0) { throw ('Vulnerable dependencies: ' + (($vulnerable | Sort-Object -Unique) -join ', ')) }
    Write-Output 'No known vulnerable dependencies reported for all three projects.'
}
finally { Pop-Location }
