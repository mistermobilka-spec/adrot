Set-StrictMode -Version Latest

# Ordering weight for severities, used for sorting and for -FailOn comparisons.
$script:ADRotSeverityRank = @{
    Critical = 4
    High     = 3
    Medium   = 2
    Low      = 1
    None     = 0
}

function New-ADRotRule {
    <#
    .SYNOPSIS
        Constructs a rule definition object.
    .DESCRIPTION
        Rules are data, not code paths: each carries its own metadata and a Test
        scriptblock that is a pure function of (Snapshot, Config). Keeping rules pure
        is what lets the entire catalogue be unit-tested without an Active Directory.
    .PARAMETER Id
        Stable identifier, e.g. 'AD-001'. Never reuse an ID for a different check.
    .PARAMETER Title
        Short human-readable finding title.
    .PARAMETER Severity
        Critical, High, Medium or Low.
    .PARAMETER Category
        Grouping for the report: Accounts, Privileged, Computers or Domain.
    .PARAMETER Weight
        Points deducted from the 100-point score when this rule fires.
    .PARAMETER Rationale
        Why this matters — shown in the report.
    .PARAMETER Remediation
        Concrete fix instructions — shown in the report.
    .PARAMETER Reference
        Authoritative URL for further reading.
    .PARAMETER Test
        Scriptblock accepting ($Snapshot, $Config) and returning zero or more affected
        objects. Each returned object should have .Name and .Detail properties.
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Constructs an in-memory object. Changes no system state, so ShouldProcess would be noise.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string] $Id,
        [Parameter(Mandatory)][string] $Title,
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low')][string] $Severity,
        [Parameter(Mandatory)][ValidateSet('Accounts', 'Privileged', 'Computers', 'Domain')][string] $Category,
        [Parameter(Mandatory)][int] $Weight,
        [Parameter(Mandatory)][string] $Rationale,
        [Parameter(Mandatory)][string] $Remediation,
        [Parameter(Mandatory)][string] $Reference,
        [Parameter(Mandatory)][scriptblock] $Test
    )

    return [pscustomobject]@{
        PSTypeName  = 'ADRot.Rule'
        Id          = $Id
        Title       = $Title
        Severity    = $Severity
        Category    = $Category
        Weight      = $Weight
        Rationale   = $Rationale
        Remediation = $Remediation
        Reference   = $Reference
        Test        = $Test
    }
}

function New-ADRotAffectedObject {
    <#
    .SYNOPSIS
        Constructs one affected-object entry for a finding.
    .PARAMETER Name
        Identifier of the offending object (samAccountName, group name, or 'domain').
    .PARAMETER Detail
        Short explanation of why this specific object matched.
    .PARAMETER DistinguishedName
        Optional LDAP DN, shown in the report for precise targeting.
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Constructs an in-memory object. Changes no system state.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][string] $Detail,
        [string] $DistinguishedName = ''
    )

    return [pscustomobject]@{
        PSTypeName        = 'ADRot.AffectedObject'
        Name              = $Name
        Detail            = $Detail
        DistinguishedName = $DistinguishedName
    }
}

function Invoke-ADRotRuleSet {
    <#
    .SYNOPSIS
        Evaluates every enabled rule against a snapshot and returns the findings.
    .DESCRIPTION
        A rule that returns no affected objects produces no finding. A rule whose Test
        throws is reported as an 'error' finding rather than aborting the scan — one
        malformed object in a 40,000-user domain must not cost the operator the whole
        report.
    .PARAMETER Snapshot
        Normalised snapshot from Import-ADRotSnapshot or Get-ADRotLdapSnapshot.
    .PARAMETER Config
        Effective configuration from Resolve-ADRotConfig.
    .PARAMETER Rule
        Explicit rule set. Defaults to the full built-in catalogue.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[] — findings, most severe first.
    .EXAMPLE
        $findings = Invoke-ADRotRuleSet -Snapshot $snap -Config $cfg
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)][hashtable] $Snapshot,
        [Parameter(Mandatory)][hashtable] $Config,
        [pscustomobject[]] $Rule
    )

    if (-not $Rule) { $Rule = Get-ADRotRule }

    $disabled = @($Config.disabledRules)
    $findings = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($r in $Rule) {
        if ($r.Id -in $disabled) {
            Write-ADRotLog -Level Debug -Message 'rule.skipped' -Data @{ rule = $r.Id }
            continue
        }

        try {
            $affected = @(& $r.Test $Snapshot $Config)
        }
        catch {
            Write-ADRotLog -Level Warn -Message 'rule.failed' -Data @{
                rule  = $r.Id
                error = $_.Exception.Message
            }
            $findings.Add([pscustomobject]@{
                    PSTypeName    = 'ADRot.Finding'
                    RuleId        = $r.Id
                    Title         = "$($r.Title) (rule failed to evaluate)"
                    Severity      = 'Low'
                    Category      = $r.Category
                    Weight        = 0
                    Rationale     = "This rule could not be evaluated: $($_.Exception.Message)"
                    Remediation   = 'Report this as a bug at https://github.com/mistermobilka-spec/adrot/issues with the snapshot that triggered it.'
                    Reference     = $r.Reference
                    AffectedCount = 0
                    Affected      = @()
                    Errored       = $true
                })
            continue
        }

        if ($affected.Count -eq 0) {
            Write-ADRotLog -Level Debug -Message 'rule.passed' -Data @{ rule = $r.Id }
            continue
        }

        $findings.Add([pscustomobject]@{
                PSTypeName    = 'ADRot.Finding'
                RuleId        = $r.Id
                Title         = $r.Title
                Severity      = $r.Severity
                Category      = $r.Category
                Weight        = $r.Weight
                Rationale     = $r.Rationale
                Remediation   = $r.Remediation
                Reference     = $r.Reference
                AffectedCount = $affected.Count
                Affected      = $affected
                Errored       = $false
            })

        Write-ADRotLog -Level Info -Message 'rule.finding' -Data @{
            rule     = $r.Id
            severity = $r.Severity
            affected = $affected.Count
        }
    }

    # Returned as a plain array: PowerShell unrolls it on the pipeline, so callers that
    # need .Count on a possibly-empty result wrap with @(), as Invoke-ADRotScan does.
    # Do NOT add a leading comma here — it would emit the array as a single object and
    # any caller writing @(...) would silently get a nested array.
    return @($findings | Sort-Object `
        @{ Expression = { $script:ADRotSeverityRank[$_.Severity] }; Descending = $true }, `
        @{ Expression = { $_.AffectedCount }; Descending = $true }, `
        @{ Expression = { $_.RuleId }; Descending = $false })
}
