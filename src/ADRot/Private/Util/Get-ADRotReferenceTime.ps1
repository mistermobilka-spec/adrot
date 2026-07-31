Set-StrictMode -Version Latest

function Get-ADRotReferenceTime {
    <#
    .SYNOPSIS
        Returns the "now" that age-based rules measure against.
    .DESCRIPTION
        Age rules (stale accounts, krbtgt rotation, password age) must be deterministic
        so that the same snapshot always yields the same findings — otherwise unit tests
        rot as the calendar advances and an archived snapshot re-analysed next year
        silently changes its verdict.

        The reference time is therefore the snapshot's own capturedAt, not the wall
        clock. Only when a snapshot carries no capturedAt does this fall back to now.
    .PARAMETER Snapshot
        The normalised snapshot.
    .OUTPUTS
        System.DateTimeOffset
    .EXAMPLE
        $now = Get-ADRotReferenceTime -Snapshot $snapshot
    #>
    [CmdletBinding()]
    [OutputType([DateTimeOffset])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Snapshot
    )

    if ($Snapshot.ContainsKey('capturedAt') -and $Snapshot.capturedAt) {
        $value = $Snapshot.capturedAt
        if ($value -is [DateTimeOffset]) { return $value }
        if ($value -is [datetime]) { return [DateTimeOffset] $value }

        [DateTimeOffset] $parsed = [DateTimeOffset]::MinValue
        if ([DateTimeOffset]::TryParse("$value", [ref] $parsed)) { return $parsed }

        Write-ADRotLog -Level Warn -Message 'snapshot.capturedAt.unparseable' -Data @{ value = $value }
    }

    return [DateTimeOffset]::UtcNow
}

function Get-ADRotAgeInDays {
    <#
    .SYNOPSIS
        Whole days between a timestamp and the snapshot reference time.
    .PARAMETER Timestamp
        The timestamp to age. $null returns $null (meaning "never happened").
    .PARAMETER ReferenceTime
        The "now" to measure against.
    .OUTPUTS
        System.Nullable[System.Int32]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()] $Timestamp,
        [Parameter(Mandatory)][DateTimeOffset] $ReferenceTime
    )

    if ($null -eq $Timestamp) { return $null }
    if ($Timestamp -isnot [DateTimeOffset]) {
        [DateTimeOffset] $parsed = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse("$Timestamp", [ref] $parsed)) { return $null }
        $Timestamp = $parsed
    }

    return [int] [Math]::Floor(($ReferenceTime - $Timestamp).TotalDays)
}
