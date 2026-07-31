Set-StrictMode -Version Latest

function ConvertFrom-ADRotLdapSid {
    <#
    .SYNOPSIS
        Converts a binary objectSid attribute to its S-1-... string form.
    .DESCRIPTION
        LDAP returns objectSid as raw bytes. ADRot matches privileged groups on
        well-known RID suffix, so the string form is what the rules need.

        Decoded by hand rather than with System.Security.Principal.SecurityIdentifier,
        which is Windows-only and throws PlatformNotSupportedException on Linux and
        macOS. That would silently blank every SID on a Linux CI runner or inside the
        container image, and privileged-group matching would fall back to English
        display names without anyone noticing.

        Binary layout (MS-DTYP 2.4.2.2):
          byte  0      revision
          byte  1      sub-authority count
          bytes 2-7    identifier authority, 48-bit BIG-endian
          bytes 8+     sub-authorities, 32-bit LITTLE-endian each
        The mixed endianness is the part that makes hand-rolling this worth testing.
    .PARAMETER Bytes
        The raw objectSid bytes.
    .OUTPUTS
        System.String — the SID, or an empty string if the input is not a valid SID.
    .EXAMPLE
        ConvertFrom-ADRotLdapSid -Bytes (Get-ADRotLdapBinaryAttribute -Entry $e -Name 'objectSid')
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
        $revision = [int] $Bytes[0]
        $subAuthorityCount = [int] $Bytes[1]

        # A SID carries at most 15 sub-authorities; anything else is corrupt input.
        if ($subAuthorityCount -lt 0 -or $subAuthorityCount -gt 15) {
            Write-ADRotLog -Level Warn -Message 'sid.parse.failed' -Data @{
                reason = 'subauthority-count'; count = $subAuthorityCount
            }
            return ''
        }
        if ($Bytes.Length -lt (8 + 4 * $subAuthorityCount)) {
            Write-ADRotLog -Level Warn -Message 'sid.parse.failed' -Data @{
                reason = 'truncated'; length = $Bytes.Length; expected = (8 + 4 * $subAuthorityCount)
            }
            return ''
        }

        [uint64] $authority = 0
        for ($i = 2; $i -le 7; $i++) {
            $authority = ($authority -shl 8) -bor [uint64] $Bytes[$i]
        }

        $sid = [System.Text.StringBuilder]::new("S-$revision-$authority")
        for ($i = 0; $i -lt $subAuthorityCount; $i++) {
            $offset = 8 + ($i * 4)
            # Assembled by hand rather than with BitConverter so the result does not
            # depend on the endianness of the machine running the scan.
            [uint32] $sub = [uint32] $Bytes[$offset] `
                -bor ([uint32] $Bytes[$offset + 1] -shl 8) `
                -bor ([uint32] $Bytes[$offset + 2] -shl 16) `
                -bor ([uint32] $Bytes[$offset + 3] -shl 24)
            [void] $sid.Append("-$sub")
        }
        return $sid.ToString()
    }
    catch {
        Write-ADRotLog -Level Warn -Message 'sid.parse.failed' -Data @{
            length = $Bytes.Length; error = $_.Exception.Message
        }
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
