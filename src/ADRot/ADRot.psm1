#Requires -Version 7.0
<#
.SYNOPSIS
    ADRot module loader.
.DESCRIPTION
    Dot-sources every Private and Public script into the module scope, then exports
    only the public surface declared in ADRot.psd1.

    Load order matters: Util and Engine define helpers that Rules and Render depend on
    at *call* time, not at parse time, so alphabetical dot-sourcing within each group
    is sufficient. Public scripts load last.
#>

Set-StrictMode -Version Latest

$script:ModuleRoot = $PSScriptRoot

# Ordered so that lower-level helpers exist before anything that might invoke them
# during load. (No script currently executes at load time; this keeps it that way.)
$loadGroups = @(
    'Private/Util',
    'Private/Engine',
    'Private/Sources',
    'Private/Rules',
    'Private/Render',
    'Public'
)

foreach ($group in $loadGroups) {
    $groupPath = Join-Path $script:ModuleRoot $group
    if (-not (Test-Path -LiteralPath $groupPath)) { continue }

    $scripts = Get-ChildItem -LiteralPath $groupPath -Filter '*.ps1' -File | Sort-Object Name
    foreach ($file in $scripts) {
        try {
            . $file.FullName
        }
        catch {
            throw "ADRot failed to load '$($file.FullName)': $($_.Exception.Message)"
        }
    }
}

Export-ModuleMember -Function @(
    'Invoke-ADRotScan',
    'Export-ADRotSnapshot',
    'Get-ADRotRule'
)
