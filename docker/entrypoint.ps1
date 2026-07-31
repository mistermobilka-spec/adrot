#Requires -Version 7.0
<#
.SYNOPSIS
    Container entrypoint for ADRot.
.DESCRIPTION
    Mirrors the parameter surface of Invoke-ADRotScan and forwards it as a hashtable
    splat, so the image is used exactly like the cmdlet:

        docker run --rm -v "$PWD:/data" adrot -SnapshotPath /data/snapshot.json
        docker run --rm -v "$PWD:/data" adrot -SnapshotPath /data/snap.json -HtmlPath /data/report.html

    The parameters are declared explicitly rather than collected with
    ValueFromRemainingArguments: splatting a plain array binds every element
    positionally, so "-SnapshotPath" would arrive as a value rather than a
    parameter name.

    Exit codes:
      0  scan completed, no -FailOn threshold breached
      1  scan could not run (bad arguments, unreadable snapshot, LDAP failure)
      2  scan completed but findings breached the -FailOn threshold
.PARAMETER SnapshotPath
    Analyse this JSON snapshot instead of querying LDAP.
.PARAMETER Server
    Domain controller hostname or domain DNS name for a live scan.
.PARAMETER SearchBase
    LDAP search base.
.PARAMETER ConfigPath
    Path to a JSON configuration file.
.PARAMETER HtmlPath
    Write a self-contained HTML report here.
.PARAMETER JsonPath
    Write the machine-readable result here.
.PARAMETER FailOn
    Exit 2 if any finding is at or above this severity.
.PARAMETER Quiet
    Suppress the terminal summary.
.PARAMETER Help
    Print usage and exit.
#>
[CmdletBinding()]
param(
    [string] $SnapshotPath,
    [string] $Server,
    [string] $SearchBase,
    [string] $ConfigPath,
    [string] $HtmlPath,
    [string] $JsonPath,

    [ValidateSet('Critical', 'High', 'Medium', 'Low', 'None')]
    [string] $FailOn,

    [switch] $Quiet,
    [switch] $Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module /opt/adrot/src/ADRot/ADRot.psd1 -Force

if ($Help -or ($PSBoundParameters.Count -eq 0)) {
    Write-Host @'
ADRot - read-only Active Directory hygiene scanner

  Analyse a snapshot captured earlier on a domain-joined host:
    docker run --rm -v "$PWD:/data" adrot -SnapshotPath /data/snapshot.json

  Write a shareable HTML report:
    docker run --rm -v "$PWD:/data" adrot -SnapshotPath /data/snapshot.json -HtmlPath /data/report.html

  Fail a CI job when anything High or worse is present:
    docker run --rm -v "$PWD:/data" adrot -SnapshotPath /data/snapshot.json -FailOn High

  List the rule catalogue:
    docker run --rm --entrypoint pwsh adrot -NoProfile -Command \
      "Import-Module /opt/adrot/src/ADRot/ADRot.psd1; Get-ADRotRule | Format-Table Id,Severity,Title"

A live LDAP scan needs a Kerberos/NTLM identity this container does not have.
Run ADRot directly on a domain-joined machine for live scans.
'@
    exit 0
}

# Forward exactly what the caller supplied. -Help is ours, not the cmdlet's.
$scanArgs = @{}
foreach ($key in $PSBoundParameters.Keys) {
    if ($key -eq 'Help') { continue }
    $scanArgs[$key] = $PSBoundParameters[$key]
}

try {
    Invoke-ADRotScan @scanArgs | Out-Null
    exit 0
}
catch {
    # Invoke-ADRotScan sets LASTEXITCODE 2 before throwing on a -FailOn breach; any
    # other failure is an operational error and must be distinguishable in CI.
    # Test-Path is required because Set-StrictMode makes reading an unset
    # $LASTEXITCODE a terminating error, which would mask the real failure.
    $lastExit = if (Test-Path variable:global:LASTEXITCODE) { $global:LASTEXITCODE } else { 0 }

    if ($lastExit -eq 2) {
        Write-Host $_.Exception.Message
        exit 2
    }

    Write-Error "ADRot failed: $($_.Exception.Message)"
    exit 1
}
