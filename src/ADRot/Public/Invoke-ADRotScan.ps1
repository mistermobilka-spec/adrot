Set-StrictMode -Version Latest

function Invoke-ADRotScan {
    <#
    .SYNOPSIS
        Runs a read-only Active Directory hygiene scan and returns the findings.
    .DESCRIPTION
        ADRot reads Active Directory over LDAP, evaluates a catalogue of hygiene and
        security rules against what it finds, and reports a 0-100 score with prioritised,
        remediable findings.

        It never writes to the directory. Every LDAP operation is a search; there is no
        code path in ADRot that issues an add, modify, or delete.

        Two data sources:
          -SnapshotPath   analyse a JSON snapshot captured earlier by Export-ADRotSnapshot
                          (works anywhere, needs no domain connectivity)
          default         query LDAP live, as the current Windows identity

    .PARAMETER SnapshotPath
        Analyse this JSON snapshot instead of querying LDAP.
    .PARAMETER Server
        Domain controller hostname or domain DNS name. Overrides config and environment.
    .PARAMETER SearchBase
        LDAP search base. Defaults to the server's default naming context.
    .PARAMETER ConfigPath
        Path to a JSON configuration file. See adrot.config.example.json.
    .PARAMETER HtmlPath
        Write a self-contained HTML report to this path.
    .PARAMETER JsonPath
        Write the machine-readable result to this path.
    .PARAMETER FailOn
        Exit with a non-zero code if any finding is at or above this severity. Intended
        for CI. Overrides the config file value.
    .PARAMETER Quiet
        Suppress the terminal summary. The result object is still returned.
    .OUTPUTS
        System.Management.Automation.PSCustomObject — the full scan result.
    .EXAMPLE
        Invoke-ADRotScan
        Scan the current domain and print a summary.
    .EXAMPLE
        Invoke-ADRotScan -HtmlPath ./report.html
        Scan and write a shareable HTML report.
    .EXAMPLE
        Invoke-ADRotScan -SnapshotPath ./snapshot.json -JsonPath ./findings.json -Quiet
        Analyse a snapshot offline and emit machine-readable findings only.
    .EXAMPLE
        Invoke-ADRotScan -FailOn High
        Scan in CI; the process exits non-zero if anything High or Critical is present.
    .LINK
        https://github.com/MisterMobilka/adrot
    #>
    [CmdletBinding(DefaultParameterSetName = 'Live')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(ParameterSetName = 'Snapshot', Mandatory)]
        [string] $SnapshotPath,

        [Parameter(ParameterSetName = 'Live')]
        [string] $Server,

        [Parameter(ParameterSetName = 'Live')]
        [string] $SearchBase,

        [string] $ConfigPath,
        [string] $HtmlPath,
        [string] $JsonPath,

        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'None')]
        [string] $FailOn,

        [switch] $Quiet
    )

    $started = [DateTimeOffset]::UtcNow

    $config = Resolve-ADRotConfig -ConfigPath $ConfigPath
    if ($Server) { $config.server = $Server }
    if ($SearchBase) { $config.searchBase = $SearchBase }
    if ($FailOn) { $config.failOn = $FailOn }

    if ($PSCmdlet.ParameterSetName -eq 'Snapshot') {
        Write-ADRotLog -Level Info -Message 'scan.source.snapshot' -Data @{ path = $SnapshotPath }
        $snapshot = Import-ADRotSnapshot -Path $SnapshotPath
    }
    else {
        Write-ADRotLog -Level Info -Message 'scan.source.ldap' -Data @{
            server = ($config.server ?? '<auto-discover>')
        }
        $snapshot = Get-ADRotLdapSnapshot -Config $config
    }

    $rules = Get-ADRotRule
    $findings = @(Invoke-ADRotRuleSet -Snapshot $snapshot -Config $config -Rule $rules)
    $score = Get-ADRotScore -Finding $findings

    $result = [pscustomobject]@{
        PSTypeName    = 'ADRot.ScanResult'
        Tool          = 'ADRot'
        ToolVersion   = (Get-Module ADRot).Version.ToString()
        CapturedAt    = (Get-ADRotReferenceTime -Snapshot $snapshot).ToString('o')
        ScannedAt     = $started.ToString('o')
        DurationMs    = [int] ([DateTimeOffset]::UtcNow - $started).TotalMilliseconds
        Domain        = $snapshot.domain
        DomainPolicy  = $snapshot.domainPolicy
        Score         = $score
        Findings      = $findings
        Stats         = [pscustomobject]@{
            Users          = $snapshot.users.Count
            Computers      = $snapshot.computers.Count
            Groups         = $snapshot.groups.Count
            RulesEvaluated = $rules.Count - @($config.disabledRules).Count
            RulesTotal     = $rules.Count
        }
    }

    if ($JsonPath) {
        $json = $result | ConvertTo-Json -Depth 12
        Set-Content -LiteralPath $JsonPath -Value $json -Encoding utf8 -NoNewline:$false
        Write-ADRotLog -Level Info -Message 'report.json.written' -Data @{ path = $JsonPath }
    }

    if ($HtmlPath) {
        $html = ConvertTo-ADRotHtml -Result $result
        Set-Content -LiteralPath $HtmlPath -Value $html -Encoding utf8
        Write-ADRotLog -Level Info -Message 'report.html.written' -Data @{ path = $HtmlPath }
    }

    if (-not $Quiet) { Write-ADRotConsole -Result $result }

    if (Test-ADRotFailThreshold -Finding $findings -FailOn $config.failOn) {
        Write-ADRotLog -Level Warn -Message 'scan.threshold.breached' -Data @{ failOn = $config.failOn }
        # Surface the result before signalling failure so a caller capturing output
        # still gets the data it came for.
        Write-Output $result
        $global:LASTEXITCODE = 2
        throw "ADRot: findings at or above severity '$($config.failOn)' were present."
    }

    return $result
}
