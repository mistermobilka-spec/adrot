Set-StrictMode -Version Latest

$script:ADRotLogLevels = @{
    Debug = 0
    Info  = 1
    Warn  = 2
    Error = 3
}

function Write-ADRotLog {
    <#
    .SYNOPSIS
        Emits a structured log line to the PowerShell information/warning/error streams.
    .DESCRIPTION
        ADRot logs as single-line key=value records so output stays greppable when the
        scanner is run from cron, a scheduled task, or a CI job. Nothing is written to
        stdout: stdout is reserved for the scan result object, so `Invoke-ADRotScan |
        ConvertTo-Json` stays clean.
    .PARAMETER Message
        Human-readable message.
    .PARAMETER Level
        Severity. Records below $MinimumLevel are suppressed.
    .PARAMETER Data
        Optional hashtable of extra fields appended as key=value pairs.
    .PARAMETER MinimumLevel
        Threshold below which records are dropped. Defaults to the ADROT_LOG_LEVEL
        environment variable, else 'Info'.
    .EXAMPLE
        Write-ADRotLog -Level Info -Message 'ldap.search.complete' -Data @{ objects = 412 }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Message,

        [ValidateSet('Debug', 'Info', 'Warn', 'Error')]
        [string] $Level = 'Info',

        [hashtable] $Data,

        [ValidateSet('Debug', 'Info', 'Warn', 'Error')]
        [string] $MinimumLevel
    )

    if (-not $PSBoundParameters.ContainsKey('MinimumLevel')) {
        $envLevel = [Environment]::GetEnvironmentVariable('ADROT_LOG_LEVEL')
        $MinimumLevel = if ($envLevel -and $script:ADRotLogLevels.ContainsKey($envLevel)) { $envLevel } else { 'Info' }
    }

    if ($script:ADRotLogLevels[$Level] -lt $script:ADRotLogLevels[$MinimumLevel]) { return }

    $timestamp = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $line = "$timestamp level=$($Level.ToLowerInvariant()) msg=$Message"

    if ($Data) {
        foreach ($key in ($Data.Keys | Sort-Object)) {
            $value = $Data[$key]
            # Quote values containing whitespace so the line stays parseable.
            if ($null -ne $value -and "$value" -match '\s') { $value = '"' + "$value" + '"' }
            $line += " $key=$value"
        }
    }

    switch ($Level) {
        'Error' { Write-Error   -Message $line -ErrorAction Continue }
        'Warn'  { Write-Warning -Message $line }
        default { Write-Information -MessageData $line -InformationAction Continue }
    }
}
