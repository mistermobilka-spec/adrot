Set-StrictMode -Version Latest

function ConvertFrom-ADRotLdapSid {
    <#
    .SYNOPSIS
        Converts a binary objectSid attribute to its S-1-... string form.
    .DESCRIPTION
        LDAP returns objectSid as raw bytes. ADRot matches privileged groups on
        well-known RID suffix, so the string form is what the rules need.

        Kept as a standalone pure function so it can be unit-tested without a
        directory: SID decoding is fiddly (big-endian authority, little-endian
        sub-authorities) and is exactly the kind of code that silently breaks.
    .PARAMETER Bytes
        The raw objectSid bytes.
    .OUTPUTS
        System.String — the SID, or an empty string if the input is not a valid SID.
    .EXAMPLE
        ConvertFrom-ADRotLdapSid -Bytes $entry.Attributes['objectSid'][0]
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [byte[]] $Bytes
    )

    if ($null -eq $Bytes -or $Bytes.Length -lt 8) { return '' }

    try {
        return [System.Security.Principal.SecurityIdentifier]::new($Bytes, 0).Value
    }
    catch {
        Write-ADRotLog -Level Warn -Message 'sid.parse.failed' -Data @{ length = $Bytes.Length }
        return ''
    }
}

function ConvertFrom-ADRotGeneralizedTime {
    <#
    .SYNOPSIS
        Parses an LDAP GeneralizedTime string into a DateTimeOffset.
    .DESCRIPTION
        Attributes such as whenCreated are returned in the form yyyyMMddHHmmss.0Z
        rather than as a FILETIME integer.
    .PARAMETER Value
        The GeneralizedTime string.
    .OUTPUTS
        System.Nullable[System.DateTimeOffset]
    .EXAMPLE
        ConvertFrom-ADRotGeneralizedTime -Value '20240115100000.0Z'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    # Must be string[], not object[]: PowerShell binds the wrong TryParseExact overload
    # for an untyped array and the parse silently fails for every input.
    [string[]] $formats = @('yyyyMMddHHmmss.fZ', 'yyyyMMddHHmmss.ffZ', 'yyyyMMddHHmmss.fffZ', 'yyyyMMddHHmmssZ')
    [datetime] $parsed = [datetime]::MinValue
    if ([datetime]::TryParseExact($Value, $formats, [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
            [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref] $parsed)) {
        return [DateTimeOffset]::new($parsed, [TimeSpan]::Zero)
    }

    Write-ADRotLog -Level Warn -Message 'generalizedtime.parse.failed' -Data @{ value = $Value }
    return $null
}

function ConvertFrom-ADRotPwdAgeInterval {
    <#
    .SYNOPSIS
        Converts an AD password-age interval to whole days.
    .DESCRIPTION
        maxPwdAge and lockoutDuration are stored as negative 100-nanosecond intervals.
        The sentinel -9223372036854775808 means "never expires" and returns 0.
    .PARAMETER Value
        The raw interval value.
    .OUTPUTS
        System.Nullable[System.Int32]
    .EXAMPLE
        ConvertFrom-ADRotPwdAgeInterval -Value -36288000000000   # 42
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value -or "$Value" -eq '') { return $null }

    [int64] $ticks = 0
    if (-not [int64]::TryParse("$Value", [ref] $ticks)) { return $null }
    if ($ticks -eq 0 -or $ticks -eq [int64]::MinValue) { return 0 }   # never expires

    return [int] [Math]::Round([Math]::Abs($ticks) / 864000000000.0)
}
