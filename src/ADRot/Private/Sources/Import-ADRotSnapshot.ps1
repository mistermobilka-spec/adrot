Set-StrictMode -Version Latest

# Bump when the on-disk snapshot shape changes incompatibly.
$script:ADRotSnapshotSchemaVersion = 1

function Import-ADRotSnapshot {
    <#
    .SYNOPSIS
        Loads an ADRot snapshot from a JSON file and normalises it for the rule engine.
    .DESCRIPTION
        This is the offline data source. It exists so that an operator can capture a
        snapshot on a domain controller with Export-ADRotSnapshot, carry the JSON out
        of a restricted network, and analyse it anywhere — and so that every rule can
        be unit-tested without an Active Directory.

        Normalisation guarantees the rule engine can rely on:
          * users/computers/groups are always arrays (never $null, never a bare object)
          * every account has .uacFlags decoded and .enabled resolved
          * FILETIME fields are DateTimeOffset or $null
    .PARAMETER Path
        Path to the snapshot JSON file.
    .OUTPUTS
        System.Collections.Hashtable — the normalised snapshot.
    .EXAMPLE
        $snapshot = Import-ADRotSnapshot -Path ./tests/fixtures/dirty-domain.json
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "ADRot snapshot not found: $Path"
    }

    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    try {
        $snapshot = $raw | ConvertFrom-Json -AsHashtable -Depth 32 -ErrorAction Stop
    }
    catch {
        throw "ADRot snapshot '$Path' is not valid JSON: $($_.Exception.Message)"
    }

    return ConvertTo-ADRotNormalisedSnapshot -Snapshot $snapshot -Origin $Path
}

function ConvertTo-ADRotNormalisedSnapshot {
    <#
    .SYNOPSIS
        Normalises a raw snapshot hashtable into the shape the rule engine expects.
    .PARAMETER Snapshot
        Raw snapshot, as produced by Export-ADRotSnapshot or read from JSON.
    .PARAMETER Origin
        Free-text description of where the snapshot came from, for error messages.
    .OUTPUTS
        System.Collections.Hashtable
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Snapshot,

        [string] $Origin = '<in-memory>'
    )

    if (-not $Snapshot.ContainsKey('schemaVersion')) {
        throw "ADRot snapshot from '$Origin' has no schemaVersion field."
    }
    if ([int] $Snapshot.schemaVersion -ne $script:ADRotSnapshotSchemaVersion) {
        throw ("ADRot snapshot from '$Origin' has schemaVersion {0}, this build understands {1}." -f `
                $Snapshot.schemaVersion, $script:ADRotSnapshotSchemaVersion)
    }

    # Force collections to arrays. ConvertFrom-Json yields a bare object for
    # single-element arrays, and $null for [] — both break `.Count` and foreach.
    foreach ($collection in @('users', 'computers', 'groups')) {
        if (-not $Snapshot.ContainsKey($collection) -or $null -eq $Snapshot[$collection]) {
            $Snapshot[$collection] = @()
        }
        else {
            $Snapshot[$collection] = @($Snapshot[$collection])
        }
    }

    foreach ($section in @('domain', 'domainPolicy')) {
        if (-not $Snapshot.ContainsKey($section) -or $null -eq $Snapshot[$section]) {
            $Snapshot[$section] = @{}
        }
    }

    foreach ($account in @($Snapshot.users) + @($Snapshot.computers)) {
        Initialize-ADRotAccount -Account $account
    }

    foreach ($group in $Snapshot.groups) {
        if (-not $group.ContainsKey('members') -or $null -eq $group.members) { $group.members = @() }
        else { $group.members = @($group.members) }
    }

    Write-ADRotLog -Level Debug -Message 'snapshot.normalised' -Data @{
        origin    = $Origin
        users     = $Snapshot.users.Count
        computers = $Snapshot.computers.Count
        groups    = $Snapshot.groups.Count
    }

    return $Snapshot
}

function Initialize-ADRotAccount {
    <#
    .SYNOPSIS
        Adds derived fields to a user or computer account in place.
    .DESCRIPTION
        Populates .uacFlags, .enabled, and converts FILETIME fields to DateTimeOffset.
        Idempotent: safe to call twice on the same account.
    .PARAMETER Account
        The account hashtable to enrich. Mutated in place.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Account
    )

    $uac = if ($Account.ContainsKey('userAccountControl')) { $Account.userAccountControl } else { $null }
    $uacInt = $null
    if ($null -ne $uac) {
        [int] $parsed = 0
        if ([int]::TryParse("$uac", [ref] $parsed)) { $uacInt = $parsed }
    }

    $Account.userAccountControl = $uacInt
    $Account.uacFlags = @(ConvertFrom-ADRotUac -Value $uacInt)
    $Account.enabled = ($null -ne $uacInt) -and -not (Test-ADRotUacFlag -Value $uacInt -Flag 'ACCOUNTDISABLE')

    foreach ($field in @('lastLogonTimestamp', 'pwdLastSet', 'whenCreated', 'accountExpires')) {
        if (-not $Account.ContainsKey($field)) { $Account[$field] = $null; continue }

        $value = $Account[$field]
        if ($value -is [datetime]) { $Account[$field] = [DateTimeOffset] $value; continue }
        if ($value -is [DateTimeOffset]) { continue }

        # ISO-8601 strings pass through; numeric strings are FILETIME.
        if ($value -is [string] -and $value -match '^\d{4}-\d{2}-\d{2}') {
            [DateTimeOffset] $dto = [DateTimeOffset]::MinValue
            $Account[$field] = if ([DateTimeOffset]::TryParse($value, [ref] $dto)) { $dto } else { $null }
        }
        else {
            $Account[$field] = ConvertFrom-ADRotFileTime -Value $value
        }
    }

    foreach ($field in @('servicePrincipalName', 'memberOf')) {
        if (-not $Account.ContainsKey($field) -or $null -eq $Account[$field]) { $Account[$field] = @() }
        else { $Account[$field] = @($Account[$field]) }
    }

    if (-not $Account.ContainsKey('adminCount')) { $Account.adminCount = 0 }
}
