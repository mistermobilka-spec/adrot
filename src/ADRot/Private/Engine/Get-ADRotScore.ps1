Set-StrictMode -Version Latest

function Get-ADRotScore {
    <#
    .SYNOPSIS
        Reduces a set of findings to a 0-100 hygiene score and a letter grade.
    .DESCRIPTION
        The model is deliberately simple and explainable: every domain starts at 100 and
        each triggered rule deducts its own Weight, once, regardless of how many objects
        it matched. A domain with one Kerberoastable account and a domain with two
        hundred both have the same *class* of problem; the affected count is shown in the
        report but does not compound the score. This keeps a single sprawling misconfiguration
        from swamping the grade and makes the number stable enough to trend over time.

        Rules that failed to evaluate carry Weight 0 and never affect the score.
    .PARAMETER Finding
        Findings from Invoke-ADRotRuleSet. An empty set scores 100 / grade A.
    .OUTPUTS
        System.Management.Automation.PSCustomObject with Score, Grade, and per-severity counts.
    .EXAMPLE
        Get-ADRotScore -Finding $findings
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [pscustomobject[]] $Finding
    )

    $deduction = 0
    foreach ($f in $Finding) { $deduction += [int] $f.Weight }

    $score = 100 - $deduction
    if ($score -lt 0) { $score = 0 }

    $grade = switch ($score) {
        { $_ -ge 90 } { 'A'; break }
        { $_ -ge 75 } { 'B'; break }
        { $_ -ge 60 } { 'C'; break }
        { $_ -ge 40 } { 'D'; break }
        default { 'F' }
    }

    $bySeverity = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0 }
    foreach ($f in $Finding) {
        if ($bySeverity.Contains($f.Severity)) { $bySeverity[$f.Severity]++ }
    }

    return [pscustomobject]@{
        PSTypeName    = 'ADRot.Score'
        Score         = $score
        Grade         = $grade
        TotalFindings = $Finding.Count
        Critical      = $bySeverity.Critical
        High          = $bySeverity.High
        Medium        = $bySeverity.Medium
        Low           = $bySeverity.Low
    }
}

function Test-ADRotFailThreshold {
    <#
    .SYNOPSIS
        Determines whether findings breach the configured -FailOn severity.
    .PARAMETER Finding
        The findings to test.
    .PARAMETER FailOn
        Severity threshold. 'None' never fails.
    .OUTPUTS
        System.Boolean — $true when at least one finding is at or above the threshold.
    .EXAMPLE
        Test-ADRotFailThreshold -Finding $findings -FailOn High
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [pscustomobject[]] $Finding,

        [Parameter(Mandatory)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'None')]
        [string] $FailOn
    )

    if ($FailOn -eq 'None') { return $false }

    $threshold = $script:ADRotSeverityRank[$FailOn]
    foreach ($f in $Finding) {
        if ($script:ADRotSeverityRank[$f.Severity] -ge $threshold) { return $true }
    }
    return $false
}
