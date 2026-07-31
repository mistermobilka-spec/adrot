Set-StrictMode -Version Latest

# userAccountControl bit flags.
# Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
$script:ADRotUacFlags = [ordered]@{
    SCRIPT                         = 0x00000001
    ACCOUNTDISABLE                 = 0x00000002
    HOMEDIR_REQUIRED               = 0x00000008
    LOCKOUT                        = 0x00000010
    PASSWD_NOTREQD                 = 0x00000020
    PASSWD_CANT_CHANGE             = 0x00000040
    ENCRYPTED_TEXT_PWD_ALLOWED     = 0x00000080
    TEMP_DUPLICATE_ACCOUNT         = 0x00000100
    NORMAL_ACCOUNT                 = 0x00000200
    INTERDOMAIN_TRUST_ACCOUNT      = 0x00000800
    WORKSTATION_TRUST_ACCOUNT      = 0x00001000
    SERVER_TRUST_ACCOUNT           = 0x00002000
    DONT_EXPIRE_PASSWORD           = 0x00010000
    MNS_LOGON_ACCOUNT              = 0x00020000
    SMARTCARD_REQUIRED             = 0x00040000
    TRUSTED_FOR_DELEGATION         = 0x00080000
    NOT_DELEGATED                  = 0x00100000
    USE_DES_KEY_ONLY               = 0x00200000
    DONT_REQ_PREAUTH               = 0x00400000
    PASSWORD_EXPIRED               = 0x00800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000
    PARTIAL_SECRETS_ACCOUNT        = 0x04000000
}

function ConvertFrom-ADRotUac {
    <#
    .SYNOPSIS
        Decodes a userAccountControl integer into its named flags.
    .PARAMETER Value
        The raw userAccountControl value.
    .OUTPUTS
        System.String[] — the names of every set flag, in bit order.
    .EXAMPLE
        ConvertFrom-ADRotUac -Value 66048
        # NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [System.Nullable[int]] $Value
    )

    if ($null -eq $Value) { return @() }

    $set = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $script:ADRotUacFlags.Keys) {
        if (($Value -band $script:ADRotUacFlags[$name]) -ne 0) { $set.Add($name) }
    }
    return $set.ToArray()
}

function Test-ADRotUacFlag {
    <#
    .SYNOPSIS
        Tests whether a single userAccountControl flag is set.
    .PARAMETER Value
        The raw userAccountControl value. $null returns $false.
    .PARAMETER Flag
        Flag name, e.g. 'PASSWD_NOTREQD'.
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        Test-ADRotUacFlag -Value 66048 -Flag DONT_EXPIRE_PASSWORD   # True
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [System.Nullable[int]] $Value,

        [Parameter(Mandatory)]
        [string] $Flag
    )

    if ($null -eq $Value) { return $false }
    if (-not $script:ADRotUacFlags.Contains($Flag)) {
        throw "Unknown userAccountControl flag '$Flag'. Known flags: $($script:ADRotUacFlags.Keys -join ', ')"
    }
    return ($Value -band $script:ADRotUacFlags[$Flag]) -ne 0
}

function ConvertFrom-ADRotFileTime {
    <#
    .SYNOPSIS
        Converts an Active Directory FILETIME integer to a DateTimeOffset.
    .DESCRIPTION
        AD stores lastLogonTimestamp, pwdLastSet and friends as 100-nanosecond
        intervals since 1601-01-01 UTC. The sentinel values 0 and 0x7FFFFFFFFFFFFFFF
        mean "never" / "no expiry" and are returned as $null so rules can distinguish
        "never happened" from "happened long ago".
    .PARAMETER Value
        The raw FILETIME value, as Int64 or a numeric string.
    .OUTPUTS
        System.Nullable[System.DateTimeOffset]
    .EXAMPLE
        ConvertFrom-ADRotFileTime -Value 133000000000000000
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

    # 0 = never set; Int64.MaxValue = "never expires" sentinel.
    if ($ticks -le 0 -or $ticks -eq [int64]::MaxValue) { return $null }

    try {
        return [DateTimeOffset]::FromFileTime($ticks)
    }
    catch {
        # Out-of-range FILETIME values exist in the wild on corrupted objects.
        Write-ADRotLog -Level Warn -Message 'filetime.parse.failed' -Data @{ value = $ticks }
        return $null
    }
}
