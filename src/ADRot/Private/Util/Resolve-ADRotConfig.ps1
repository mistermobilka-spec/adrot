Set-StrictMode -Version Latest

function Get-ADRotDefaultConfig {
    <#
    .SYNOPSIS
        Returns ADRot's built-in default configuration.
    .OUTPUTS
        System.Collections.Hashtable
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{
        server                  = $null
        port                    = 389
        useSsl                  = $false
        searchBase              = $null
        thresholds              = @{
            staleDays            = 90
            krbtgtMaxAgeDays     = 180
            maxPrivilegedMembers = 5
            minPasswordLength    = 14
            maxPasswordAgeDays   = 365
        }
        legacyOperatingSystems  = @(
            'Windows 2000', 'Windows XP', 'Windows Vista', 'Windows 7', 'Windows 8',
            'Windows Server 2003', 'Windows Server 2008', 'Windows Server 2012'
        )
        disabledRules           = @()
        failOn                  = 'None'
        logLevel                = 'Info'
    }
}

function Resolve-ADRotConfig {
    <#
    .SYNOPSIS
        Merges default, file, and environment configuration into one effective config.
    .DESCRIPTION
        Precedence, lowest to highest:
          1. Built-in defaults (Get-ADRotDefaultConfig)
          2. JSON file at -ConfigPath
          3. ADROT_* environment variables
        Unknown keys in the JSON file are preserved but ignored; keys beginning with
        '$' (JSON pseudo-comments) are dropped.
    .PARAMETER ConfigPath
        Optional path to a JSON config file. Missing file is an error only if the
        caller explicitly supplied the path.
    .OUTPUTS
        System.Collections.Hashtable — the effective configuration.
    .EXAMPLE
        $cfg = Resolve-ADRotConfig -ConfigPath ./adrot.config.json
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string] $ConfigPath
    )

    $config = Get-ADRotDefaultConfig

    if ($ConfigPath) {
        if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
            throw "ADRot config file not found: $ConfigPath"
        }

        $raw = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
        try {
            $fromFile = $raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        }
        catch {
            throw "ADRot config file '$ConfigPath' is not valid JSON: $($_.Exception.Message)"
        }

        foreach ($key in $fromFile.Keys) {
            if ($key.StartsWith('$')) { continue }   # JSON pseudo-comment
            if ($key -eq 'thresholds' -and $fromFile[$key] -is [hashtable]) {
                foreach ($t in $fromFile[$key].Keys) { $config.thresholds[$t] = $fromFile[$key][$t] }
            }
            else {
                $config[$key] = $fromFile[$key]
            }
        }
        Write-ADRotLog -Level Debug -Message 'config.file.loaded' -Data @{ path = $ConfigPath }
    }

    # Environment overrides. Mapping: env var -> config path.
    $envMap = @{
        ADROT_SERVER                  = 'server'
        ADROT_SEARCH_BASE             = 'searchBase'
        ADROT_FAIL_ON                 = 'failOn'
        ADROT_LOG_LEVEL               = 'logLevel'
    }
    foreach ($name in $envMap.Keys) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($value)) { $config[$envMap[$name]] = $value }
    }

    $intMap = @{
        ADROT_PORT                    = @{ Section = $null;         Key = 'port' }
        ADROT_STALE_DAYS              = @{ Section = 'thresholds';  Key = 'staleDays' }
        ADROT_KRBTGT_MAX_AGE_DAYS     = @{ Section = 'thresholds';  Key = 'krbtgtMaxAgeDays' }
        ADROT_MAX_PRIVILEGED_MEMBERS  = @{ Section = 'thresholds';  Key = 'maxPrivilegedMembers' }
        ADROT_MIN_PASSWORD_LENGTH     = @{ Section = 'thresholds';  Key = 'minPasswordLength' }
    }
    foreach ($name in $intMap.Keys) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ([string]::IsNullOrWhiteSpace($value)) { continue }

        [int] $parsed = 0
        if (-not [int]::TryParse($value, [ref] $parsed)) {
            throw "Environment variable $name must be an integer, got '$value'."
        }
        $target = $intMap[$name]
        if ($target.Section) { $config[$target.Section][$target.Key] = $parsed }
        else { $config[$target.Key] = $parsed }
    }

    $sslValue = [Environment]::GetEnvironmentVariable('ADROT_USE_SSL')
    if (-not [string]::IsNullOrWhiteSpace($sslValue)) {
        $config.useSsl = $sslValue -in @('1', 'true', 'True', 'yes', 'on')
    }

    # LDAPS implies 636 unless the caller pinned a port explicitly.
    if ($config.useSsl -and -not [Environment]::GetEnvironmentVariable('ADROT_PORT') -and $config.port -eq 389) {
        $config.port = 636
    }

    if ($config.failOn -notin @('Critical', 'High', 'Medium', 'Low', 'None')) {
        throw "failOn must be one of Critical, High, Medium, Low, None — got '$($config.failOn)'."
    }

    return $config
}
