Set-StrictMode -Version Latest

$script:ADRotSeverityColour = @{
    Critical = "`e[1;97;41m"   # bold white on red
    High     = "`e[1;31m"      # bold red
    Medium   = "`e[1;33m"      # bold yellow
    Low      = "`e[36m"        # cyan
}
$script:ADRotReset = "`e[0m"
$script:ADRotDim = "`e[2m"
$script:ADRotBold = "`e[1m"

function Write-ADRotConsole {
    <#
    .SYNOPSIS
        Renders a scan result as a human-readable terminal summary.
    .DESCRIPTION
        Writes to the host, not the pipeline: the structured result object is what
        Invoke-ADRotScan returns, so piping the cmdlet into ConvertTo-Json still works
        while the operator watching the terminal gets something readable.

        Honours the NO_COLOR convention (https://no-color.org/).
    .PARAMETER Result
        The scan result from Invoke-ADRotScan.
    .PARAMETER MaxAffected
        How many affected objects to list per finding before summarising the remainder.
    .EXAMPLE
        Write-ADRotConsole -Result $result
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Result,
        [int] $MaxAffected = 5
    )

    $useColour = -not [Environment]::GetEnvironmentVariable('NO_COLOR')
    function Format-Colour {
        param([string] $Text, [string] $Code)
        if ($useColour -and $Code) { return "$Code$Text$script:ADRotReset" }
        return $Text
    }

    $score = $Result.Score
    $gradeColour = switch ($score.Grade) {
        'A' { "`e[1;32m" }
        'B' { "`e[1;32m" }
        'C' { "`e[1;33m" }
        'D' { "`e[1;31m" }
        default { "`e[1;97;41m" }
    }

    Write-Host ''
    Write-Host (Format-Colour '  ADRot — Active Directory hygiene report' $script:ADRotBold)
    Write-Host (Format-Colour "  $($Result.Domain.dnsRoot)  ·  captured $($Result.CapturedAt)" $script:ADRotDim)
    Write-Host ''
    Write-Host ('  Score  ' + (Format-Colour " $($score.Score)/100  grade $($score.Grade) " $gradeColour))
    Write-Host ("  {0} findings — {1} critical, {2} high, {3} medium, {4} low" -f `
            $score.TotalFindings, $score.Critical, $score.High, $score.Medium, $score.Low)
    Write-Host (Format-Colour ("  Scanned {0} users, {1} computers, {2} groups against {3} rules" -f `
                $Result.Stats.Users, $Result.Stats.Computers, $Result.Stats.Groups, $Result.Stats.RulesEvaluated) $script:ADRotDim)
    Write-Host ''

    if ($Result.Findings.Count -eq 0) {
        Write-Host (Format-Colour '  No findings. Every rule in the catalogue passed.' "`e[1;32m")
        Write-Host ''
        return
    }

    Write-Host ('  ' + ('─' * 76))
    foreach ($f in $Result.Findings) {
        $badge = Format-Colour (" {0,-8} " -f $f.Severity.ToUpperInvariant()) $script:ADRotSeverityColour[$f.Severity]
        Write-Host ''
        Write-Host ("  {0} {1}  {2}" -f $badge, (Format-Colour $f.RuleId $script:ADRotDim), (Format-Colour $f.Title $script:ADRotBold))
        Write-Host ("           {0} affected" -f $f.AffectedCount)

        $shown = 0
        foreach ($a in $f.Affected) {
            if ($shown -ge $MaxAffected) { break }
            Write-Host (Format-Colour ("             · {0} — {1}" -f $a.Name, $a.Detail) $script:ADRotDim)
            $shown++
        }
        if ($f.AffectedCount -gt $MaxAffected) {
            Write-Host (Format-Colour ("             … and {0} more" -f ($f.AffectedCount - $MaxAffected)) $script:ADRotDim)
        }
    }

    Write-Host ''
    Write-Host ('  ' + ('─' * 76))
    Write-Host (Format-Colour '  Run with -HtmlPath to produce the full report with remediation guidance.' $script:ADRotDim)
    Write-Host ''
}
