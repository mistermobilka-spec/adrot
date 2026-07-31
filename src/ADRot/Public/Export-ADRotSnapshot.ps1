Set-StrictMode -Version Latest

function Export-ADRotSnapshot {
    <#
    .SYNOPSIS
        Captures a read-only snapshot of Active Directory to a JSON file.
    .DESCRIPTION
        Separates data capture from analysis. Run this on a domain-joined host — a
        jump box, a management server — then copy the JSON out and analyse it anywhere
        with Invoke-ADRotScan -SnapshotPath, including on a machine that has no line of
        sight to the domain at all.

        Useful for air-gapped estates, for consultants who are allowed to read a client
        domain but not to install tooling on it, and for keeping a dated series of
        snapshots so posture can be trended over time.

        PRIVACY: the snapshot contains directory metadata — account names,
        distinguished names, group membership, operating system versions and timestamps.
        It contains no passwords and no password hashes: ADRot never requests those
        attributes. Treat the file as you would any AD inventory export.
    .PARAMETER Path
        Destination JSON file path.
    .PARAMETER Server
        Domain controller hostname or domain DNS name. Defaults to auto-discovery.
    .PARAMETER SearchBase
        LDAP search base. Defaults to the server's default naming context.
    .PARAMETER ConfigPath
        Path to a JSON configuration file.
    .PARAMETER Force
        Overwrite Path if it already exists.
    .OUTPUTS
        System.IO.FileInfo — the written snapshot file.
    .EXAMPLE
        Export-ADRotSnapshot -Path ./corp-2026-07-31.json
    .EXAMPLE
        Export-ADRotSnapshot -Path ./client.json -Server dc01.client.local
        Invoke-ADRotScan -SnapshotPath ./client.json -HtmlPath ./client-report.html
    .LINK
        https://github.com/mistermobilka-spec/adrot
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [string] $Server,
        [string] $SearchBase,
        [string] $ConfigPath,
        [switch] $Force
    )

    if ((Test-Path -LiteralPath $Path) -and -not $Force) {
        throw "ADRot snapshot '$Path' already exists. Pass -Force to overwrite."
    }

    $config = Resolve-ADRotConfig -ConfigPath $ConfigPath
    if ($Server) { $config.server = $Server }
    if ($SearchBase) { $config.searchBase = $SearchBase }

    if (-not $PSCmdlet.ShouldProcess($Path, 'Capture Active Directory snapshot')) { return }

    $snapshot = Get-ADRotLdapSnapshot -Config $config

    # Strip the derived fields that normalisation adds. They are recomputed on import,
    # and DateTimeOffset objects would otherwise serialise into a verbose nested shape.
    $export = @{
        schemaVersion = $snapshot.schemaVersion
        capturedAt    = $snapshot.capturedAt
        domain        = $snapshot.domain
        domainPolicy  = $snapshot.domainPolicy
        users         = @($snapshot.users     | ForEach-Object { ConvertTo-ADRotExportableAccount -Account $_ })
        computers     = @($snapshot.computers | ForEach-Object { ConvertTo-ADRotExportableAccount -Account $_ })
        groups        = @($snapshot.groups)
    }

    $json = $export | ConvertTo-Json -Depth 12
    Set-Content -LiteralPath $Path -Value $json -Encoding utf8

    Write-ADRotLog -Level Info -Message 'snapshot.exported' -Data @{
        path = $Path; users = $export.users.Count; computers = $export.computers.Count
    }

    return Get-Item -LiteralPath $Path
}

function ConvertTo-ADRotExportableAccount {
    <#
    .SYNOPSIS
        Reduces a normalised account back to its serialisable fields.
    .DESCRIPTION
        Drops the derived uacFlags/enabled fields and renders timestamps as ISO-8601
        strings so the snapshot round-trips through JSON without losing fidelity.
    .PARAMETER Account
        The normalised account.
    .OUTPUTS
        System.Collections.Hashtable
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][hashtable] $Account
    )

    $out = @{}
    $derived = @('uacFlags', 'enabled')
    $timestamps = @('lastLogonTimestamp', 'pwdLastSet', 'whenCreated', 'accountExpires')

    foreach ($key in $Account.Keys) {
        if ($key -in $derived) { continue }

        $value = $Account[$key]
        if ($key -in $timestamps) {
            $out[$key] = if ($value -is [DateTimeOffset]) { $value.ToString('o') } else { $null }
        }
        else {
            $out[$key] = $value
        }
    }
    return $out
}
