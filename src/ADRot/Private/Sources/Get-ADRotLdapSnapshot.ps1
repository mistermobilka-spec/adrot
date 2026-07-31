Set-StrictMode -Version Latest

function New-ADRotLdapConnection {
    <#
    .SYNOPSIS
        Opens an authenticated, integrity-protected LDAP connection.
    .DESCRIPTION
        Authentication is Negotiate (Kerberos, falling back to NTLM) as the identity of
        the calling process. ADRot never accepts, stores or transmits a password.

        On plain LDAP (389) signing and sealing are switched on. That is not optional
        hardening: an unsigned LDAP bind is relayable, and a tool whose whole purpose is
        auditing domain security must not itself be the weak link. On LDAPS the TLS
        channel provides the same protection.
    .PARAMETER Config
        Effective configuration from Resolve-ADRotConfig.
    .OUTPUTS
        System.DirectoryServices.Protocols.LdapConnection
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Opens a read-only client connection. Nothing on the directory or the local system is modified.')]
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.Protocols.LdapConnection])]
    param(
        [Parameter(Mandatory)][hashtable] $Config
    )

    $server = $Config.server
    if ([string]::IsNullOrWhiteSpace($server) -and $Config.authType -eq 'Anonymous') {
        throw 'ADRot requires an explicit -Server when authType is Anonymous; there is no domain to auto-discover.'
    }
    if ([string]::IsNullOrWhiteSpace($server)) {
        # Auto-discover: the machine's own AD domain. Fails clearly off-domain.
        try {
            $server = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        }
        catch {
            throw ('ADRot could not determine a domain to query. This machine does not ' +
                   'appear to be domain-joined. Pass -Server <dc-hostname>, or analyse a ' +
                   "snapshot with -SnapshotPath. Underlying error: $($_.Exception.Message)")
        }
    }

    $identifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new(
        $server, [int] $Config.port, $false, $false)

    $connection = [System.DirectoryServices.Protocols.LdapConnection]::new($identifier)
    $connection.SessionOptions.ProtocolVersion = 3
    $connection.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None

    $authType = if ($Config.ContainsKey('authType') -and $Config.authType) { $Config.authType } else { 'Negotiate' }
    $connection.AuthType = [System.DirectoryServices.Protocols.AuthType] $authType

    if ($Config.useSsl) {
        $connection.SessionOptions.SecureSocketLayer = $true
    }
    elseif ($authType -eq 'Negotiate') {
        # Signing and sealing require a Negotiate security context, so they can only be
        # demanded on an authenticated bind. Against Active Directory this is the
        # normal path and is not optional hardening.
        $connection.SessionOptions.Signing = $true
        $connection.SessionOptions.Sealing = $true
    }

    Write-ADRotLog -Level Info -Message 'ldap.connect' -Data @{
        server = $server; port = $Config.port; ssl = $Config.useSsl; auth = $authType
    }

    try {
        $connection.Bind()
    }
    catch {
        throw "ADRot could not bind to LDAP server '$server':$($Config.port) — $($_.Exception.Message)"
    }

    return $connection
}

function Get-ADRotRootDseValue {
    <#
    .SYNOPSIS
        Reads a single attribute from RootDSE.
    .PARAMETER Connection
        An open LdapConnection.
    .PARAMETER Attribute
        Attribute name, e.g. 'defaultNamingContext'.
    .OUTPUTS
        System.String — empty when the attribute is absent.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][System.DirectoryServices.Protocols.LdapConnection] $Connection,
        [Parameter(Mandatory)][string] $Attribute
    )

    $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
        '', '(objectClass=*)', [System.DirectoryServices.Protocols.SearchScope]::Base, @($Attribute))
    $response = [System.DirectoryServices.Protocols.SearchResponse] $Connection.SendRequest($request)

    if ($response.Entries.Count -eq 0) { return '' }
    $entry = $response.Entries[0]
    if (-not $entry.Attributes.Contains($Attribute)) { return '' }
    return [string] $entry.Attributes[$Attribute][0]
}

function Invoke-ADRotLdapSearch {
    <#
    .SYNOPSIS
        Runs a paged LDAP search and returns every entry.
    .DESCRIPTION
        Active Directory caps a single search at MaxPageSize (1000 by default), so any
        query against a real domain must page or it silently truncates. Silent
        truncation in an audit tool is worse than an error: it reports "no findings"
        for the 39,000 objects it never looked at.
    .PARAMETER Connection
        An open LdapConnection.
    .PARAMETER SearchBase
        Distinguished name to search under.
    .PARAMETER Filter
        LDAP filter.
    .PARAMETER Attribute
        Attributes to retrieve.
    .PARAMETER PageSize
        Entries per page.
    .OUTPUTS
        System.DirectoryServices.Protocols.SearchResultEntry[]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.DirectoryServices.Protocols.LdapConnection] $Connection,
        [Parameter(Mandatory)][string] $SearchBase,
        [Parameter(Mandatory)][string] $Filter,
        [Parameter(Mandatory)][string[]] $Attribute,
        [int] $PageSize = 500
    )

    $entries = [System.Collections.Generic.List[object]]::new()
    $pageControl = [System.DirectoryServices.Protocols.PageResultRequestControl]::new($PageSize)
    $pageControl.IsCritical = $true
    $pages = 0

    while ($true) {
        $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
            $SearchBase, $Filter, [System.DirectoryServices.Protocols.SearchScope]::Subtree, $Attribute)
        [void] $request.Controls.Add($pageControl)

        try {
            $response = [System.DirectoryServices.Protocols.SearchResponse] $Connection.SendRequest($request)
        }
        catch [System.DirectoryServices.Protocols.LdapException] {
            # ErrorCode 4 is sizeLimitExceeded. Active Directory caps a single *page*
            # and lets paging retrieve everything, but some directories (OpenLDAP by
            # default) cap the *total* entries a search may return, so paging cannot
            # get past it. Fail loudly with an explanation: returning the partial set
            # would mean reporting "no findings" for objects never examined.
            if ($_.Exception.ErrorCode -eq 4) {
                throw ("ADRot stopped after $($entries.Count) entries: the directory " +
                       "enforces a server-side size limit on this search. Raise the " +
                       "server's size limit for the querying account, or narrow the scan " +
                       "with -SearchBase / a custom filter. Refusing to report on a " +
                       "partial view of the directory. Filter was: $Filter")
            }
            throw ("ADRot LDAP search failed (code $($_.Exception.ErrorCode)): " +
                   "$($_.Exception.Message). Filter was: $Filter")
        }

        $pages++
        foreach ($e in $response.Entries) { $entries.Add($e) }

        $cookie = $null
        foreach ($control in $response.Controls) {
            if ($control -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                $cookie = $control.Cookie
                break
            }
        }

        if ($null -eq $cookie -or $cookie.Length -eq 0) { break }
        $pageControl.Cookie = $cookie
    }

    Write-ADRotLog -Level Debug -Message 'ldap.search.complete' -Data @{
        filter = $Filter; entries = $entries.Count; pages = $pages
    }
    return $entries.ToArray()
}

function Get-ADRotLdapAttribute {
    <#
    .SYNOPSIS
        Safely reads one attribute from a SearchResultEntry.
    .PARAMETER Entry
        The LDAP entry.
    .PARAMETER Name
        Attribute name.
    .PARAMETER AsArray
        Return every value instead of only the first.
    .OUTPUTS
        The attribute value, an array of values, or $null when absent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Entry,
        [Parameter(Mandatory)][string] $Name,
        [switch] $AsArray
    )

    if (-not $Entry.Attributes.Contains($Name)) {
        if ($AsArray) { return @() }
        return $null
    }

    $attr = $Entry.Attributes[$Name]
    if ($AsArray) {
        $values = @()
        for ($i = 0; $i -lt $attr.Count; $i++) { $values += [string] $attr[$i] }
        return $values
    }
    if ($attr.Count -eq 0) { return $null }
    return [string] $attr[0]
}

function Get-ADRotLdapBinaryAttribute {
    <#
    .SYNOPSIS
        Reads a binary attribute from a SearchResultEntry as raw bytes.
    .DESCRIPTION
        The DirectoryAttribute indexer coerces values to String, which mangles binary
        data such as objectSid into unusable text. GetValues([byte[]]) is the only way
        to retrieve the bytes intact.
    .PARAMETER Entry
        The LDAP entry.
    .PARAMETER Name
        Attribute name, e.g. 'objectSid'.
    .OUTPUTS
        System.Byte[] — or $null when the attribute is absent or unreadable.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)] $Entry,
        [Parameter(Mandatory)][string] $Name
    )

    if (-not $Entry.Attributes.Contains($Name)) { return $null }

    try {
        $values = $Entry.Attributes[$Name].GetValues([byte[]])
        if ($null -eq $values -or $values.Count -eq 0) { return $null }
        return [byte[]] $values[0]
    }
    catch {
        Write-ADRotLog -Level Warn -Message 'ldap.binary.read.failed' -Data @{
            attribute = $Name; error = $_.Exception.Message
        }
        return $null
    }
}

function Get-ADRotLdapSnapshot {
    <#
    .SYNOPSIS
        Captures a normalised snapshot of a domain over read-only LDAP.
    .DESCRIPTION
        Performs four paged searches — users, computers, groups, and the domain object —
        and shapes the results into the same structure that Import-ADRotSnapshot produces
        from a JSON file. Every operation is a search; nothing is written.

        Attributes are requested explicitly rather than with a wildcard so the tool reads
        only what its rules actually need.
    .PARAMETER Config
        Effective configuration from Resolve-ADRotConfig.
    .OUTPUTS
        System.Collections.Hashtable — the normalised snapshot.
    .EXAMPLE
        $snapshot = Get-ADRotLdapSnapshot -Config (Resolve-ADRotConfig)
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][hashtable] $Config
    )

    $connection = $null
    try {
        $connection = New-ADRotLdapConnection -Config $Config

        $searchBase = $Config.searchBase
        if ([string]::IsNullOrWhiteSpace($searchBase)) {
            $searchBase = Get-ADRotRootDseValue -Connection $connection -Attribute 'defaultNamingContext'
            if ([string]::IsNullOrWhiteSpace($searchBase)) {
                throw 'ADRot could not read defaultNamingContext from RootDSE. Pass -SearchBase explicitly.'
            }
        }
        Write-ADRotLog -Level Info -Message 'ldap.searchbase' -Data @{ base = $searchBase }

        # --- Users -----------------------------------------------------------------
        $userAttrs = @('sAMAccountName', 'distinguishedName', 'userAccountControl',
            'lastLogonTimestamp', 'pwdLastSet', 'whenCreated', 'servicePrincipalName',
            'memberOf', 'adminCount', 'objectSid')
        $users = foreach ($e in (Invoke-ADRotLdapSearch -Connection $connection -SearchBase $searchBase `
                    -Filter $Config.filters.user -Attribute $userAttrs)) {
            $sidBytes = Get-ADRotLdapBinaryAttribute -Entry $e -Name 'objectSid'

            @{
                samAccountName       = Get-ADRotLdapAttribute -Entry $e -Name 'sAMAccountName'
                distinguishedName    = Get-ADRotLdapAttribute -Entry $e -Name 'distinguishedName'
                sid                  = ConvertFrom-ADRotLdapSid -Bytes $sidBytes
                userAccountControl   = Get-ADRotLdapAttribute -Entry $e -Name 'userAccountControl'
                lastLogonTimestamp   = Get-ADRotLdapAttribute -Entry $e -Name 'lastLogonTimestamp'
                pwdLastSet           = Get-ADRotLdapAttribute -Entry $e -Name 'pwdLastSet'
                whenCreated          = ConvertFrom-ADRotGeneralizedTime -Value (Get-ADRotLdapAttribute -Entry $e -Name 'whenCreated')
                servicePrincipalName = Get-ADRotLdapAttribute -Entry $e -Name 'servicePrincipalName' -AsArray
                memberOf             = Get-ADRotLdapAttribute -Entry $e -Name 'memberOf' -AsArray
                adminCount           = [int] ((Get-ADRotLdapAttribute -Entry $e -Name 'adminCount') ?? 0)
            }
        }

        # --- Computers -------------------------------------------------------------
        $computerAttrs = @('sAMAccountName', 'distinguishedName', 'userAccountControl',
            'operatingSystem', 'operatingSystemVersion', 'lastLogonTimestamp', 'whenCreated')
        $computers = foreach ($e in (Invoke-ADRotLdapSearch -Connection $connection -SearchBase $searchBase `
                    -Filter $Config.filters.computer -Attribute $computerAttrs)) {
            @{
                samAccountName         = Get-ADRotLdapAttribute -Entry $e -Name 'sAMAccountName'
                distinguishedName      = Get-ADRotLdapAttribute -Entry $e -Name 'distinguishedName'
                userAccountControl     = Get-ADRotLdapAttribute -Entry $e -Name 'userAccountControl'
                operatingSystem        = Get-ADRotLdapAttribute -Entry $e -Name 'operatingSystem'
                operatingSystemVersion = Get-ADRotLdapAttribute -Entry $e -Name 'operatingSystemVersion'
                lastLogonTimestamp     = Get-ADRotLdapAttribute -Entry $e -Name 'lastLogonTimestamp'
                whenCreated            = ConvertFrom-ADRotGeneralizedTime -Value (Get-ADRotLdapAttribute -Entry $e -Name 'whenCreated')
            }
        }

        # --- Groups ----------------------------------------------------------------
        $groups = foreach ($e in (Invoke-ADRotLdapSearch -Connection $connection -SearchBase $searchBase `
                    -Filter $Config.filters.group -Attribute @('sAMAccountName', 'distinguishedName', 'member', 'objectSid'))) {
            $sidBytes = Get-ADRotLdapBinaryAttribute -Entry $e -Name 'objectSid'

            @{
                samAccountName    = Get-ADRotLdapAttribute -Entry $e -Name 'sAMAccountName'
                distinguishedName = Get-ADRotLdapAttribute -Entry $e -Name 'distinguishedName'
                sid               = ConvertFrom-ADRotLdapSid -Bytes $sidBytes
                members           = Get-ADRotLdapAttribute -Entry $e -Name 'member' -AsArray
            }
        }

        # --- Domain object and policy ----------------------------------------------
        $domainAttrs = @('minPwdLength', 'lockoutThreshold', 'maxPwdAge', 'ms-DS-MachineAccountQuota', 'objectSid')
        $domainRequest = [System.DirectoryServices.Protocols.SearchRequest]::new(
            $searchBase, '(objectClass=*)', [System.DirectoryServices.Protocols.SearchScope]::Base, $domainAttrs)
        $domainResponse = [System.DirectoryServices.Protocols.SearchResponse] $connection.SendRequest($domainRequest)

        $domainPolicy = @{}
        $domainSid = ''
        if ($domainResponse.Entries.Count -gt 0) {
            $d = $domainResponse.Entries[0]
            $domainPolicy.minPwdLength = [int] ((Get-ADRotLdapAttribute -Entry $d -Name 'minPwdLength') ?? 0)
            $domainPolicy.lockoutThreshold = [int] ((Get-ADRotLdapAttribute -Entry $d -Name 'lockoutThreshold') ?? 0)
            $domainPolicy.maxPwdAgeDays = ConvertFrom-ADRotPwdAgeInterval -Value (Get-ADRotLdapAttribute -Entry $d -Name 'maxPwdAge')
            $maq = Get-ADRotLdapAttribute -Entry $d -Name 'ms-DS-MachineAccountQuota'
            $domainPolicy.machineAccountQuota = if ($null -ne $maq) { [int] $maq } else { $null }
            $domainSidBytes = Get-ADRotLdapBinaryAttribute -Entry $d -Name 'objectSid'
            if ($domainSidBytes) { $domainSid = ConvertFrom-ADRotLdapSid -Bytes $domainSidBytes }
        }

        $snapshot = @{
            schemaVersion = $script:ADRotSnapshotSchemaVersion
            capturedAt    = [DateTimeOffset]::UtcNow.ToString('o')
            domain        = @{
                dnsRoot           = (Get-ADRotRootDseValue -Connection $connection -Attribute 'ldapServiceName')
                distinguishedName = $searchBase
                domainSid         = $domainSid
            }
            domainPolicy  = $domainPolicy
            users         = @($users)
            computers     = @($computers)
            groups        = @($groups)
        }

        # Derive a readable DNS root from the search base when ldapServiceName is unhelpful.
        if ($snapshot.domain.dnsRoot -match '^([^:]+):') { $snapshot.domain.dnsRoot = $Matches[1] }
        if ([string]::IsNullOrWhiteSpace($snapshot.domain.dnsRoot)) {
            $snapshot.domain.dnsRoot = (($searchBase -split ',' | Where-Object { $_ -match '^DC=' } |
                    ForEach-Object { $_ -replace '^DC=', '' }) -join '.')
        }

        Write-ADRotLog -Level Info -Message 'ldap.snapshot.complete' -Data @{
            users = $snapshot.users.Count; computers = $snapshot.computers.Count; groups = $snapshot.groups.Count
        }

        return ConvertTo-ADRotNormalisedSnapshot -Snapshot $snapshot -Origin "ldap://$($Config.server)"
    }
    finally {
        if ($connection) { $connection.Dispose() }
    }
}
