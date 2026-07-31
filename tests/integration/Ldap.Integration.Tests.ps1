#Requires -Modules Pester
<#
    Integration tests against a real LDAP server.

    WHAT THESE PROVE
      * LdapConnection binds and the paged-search implementation works against a live
        server speaking the real LDAP wire protocol
      * paging actually pages — the fixture holds more entries than the server will
        return in one response, so a broken implementation silently truncates and the
        assertion fails
      * binary attributes (objectSid) round-trip off the wire and decode correctly
      * the full Get-ADRotLdapSnapshot -> rule engine -> findings pipeline runs on
        live-fetched data rather than a JSON file

    WHAT THEY DO NOT PROVE
      The fixture is OpenLDAP carrying a hand-written AD-shaped schema, not Active
      Directory. It cannot validate AD-specific server behaviour: the real
      objectCategory filters, RootDSE defaultNamingContext, Negotiate/Kerberos
      binding, or the true attribute syntaxes. Those need a real domain.

    Start the fixture first:  make ldap-up      (or)
    docker compose -f docker/docker-compose.yml up -d --build --wait
#>

# Runs during Pester DISCOVERY, not during the run phase. This matters: -Skip: on a
# Describe block is evaluated at discovery, so a probe placed inside BeforeAll would
# still be $null when Pester decides what to skip, and every test would be skipped
# even with the fixture up.
$LdapHost = $env:ADROT_TEST_LDAP_HOST ?? '127.0.0.1'
$LdapPort = [int] ($env:ADROT_TEST_LDAP_PORT ?? '3890')
$LdapReachable = try {
    $probe = [System.Net.Sockets.TcpClient]::new()
    $probe.Connect($LdapHost, $LdapPort)
    $probe.Close()
    $true
}
catch { $false }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'ADRot' 'ADRot.psd1') -Force

    $script:LdapHost = $env:ADROT_TEST_LDAP_HOST ?? '127.0.0.1'
    $script:LdapPort = [int] ($env:ADROT_TEST_LDAP_PORT ?? '3890')
    $script:BaseDn = 'dc=adrot,dc=test'

    # Re-probed at run time: discovery-time variables drive -Skip: but are not visible
    # inside It blocks.
    $script:LdapReachable = try {
        $c = [System.Net.Sockets.TcpClient]::new(); $c.Connect($script:LdapHost, $script:LdapPort); $c.Close(); $true
    }
    catch { $false }

    # The fixture uses an AD-shaped schema on OpenLDAP, which has no objectCategory
    # semantics, so the filters are overridden to select by the seeded marker attribute.
    $script:TestConfig = InModuleScope ADRot -Parameters @{
        h = $script:LdapHost; p = $script:LdapPort; b = $script:BaseDn
    } {
        param($h, $p, $b)
        $config = Get-ADRotDefaultConfig
        $config.server = $h
        $config.port = $p
        $config.searchBase = $b
        $config.authType = 'Anonymous'
        $config.filters.user = '(&(objectClass=inetOrgPerson)(objectCategory=person))'
        $config.filters.computer = '(&(objectClass=device)(objectCategory=computer))'
        $config.filters.group = '(&(objectClass=groupOfNames)(objectCategory=group))'
        return $config
    }
}

AfterAll {
    Remove-Module ADRot -Force -ErrorAction SilentlyContinue
}

Describe 'LDAP fixture availability' {
    It 'has a reachable test LDAP server' {
        $script:LdapReachable | Should -BeTrue -Because `
            "the fixture must be running: docker compose -f docker/docker-compose.yml up -d --build --wait (tried $($script:LdapHost):$($script:LdapPort))"
    }
}

Describe 'Live LDAP capture' -Skip:(-not $LdapReachable) {
    BeforeAll {
        $script:Snapshot = InModuleScope ADRot -Parameters @{ c = $script:TestConfig } {
            param($c)
            Get-ADRotLdapSnapshot -Config $c
        } 6>$null
    }

    It 'binds anonymously and returns a normalised snapshot' {
        $script:Snapshot | Should -Not -BeNullOrEmpty
        $script:Snapshot.schemaVersion | Should -Be 1
    }

    It 'pages past the server size limit' {
        # The fixture seeds 600 bulk users plus 4 named ones. The server caps a single
        # unpaged response at 500, so anything at or below 500 means paging is broken
        # and a real domain would be silently under-reported.
        $script:Snapshot.users.Count | Should -BeGreaterThan 500 -Because 'paged search must defeat the server size limit'
        $script:Snapshot.users.Count | Should -Be 604
    }

    It 'retrieves computers and groups' {
        $script:Snapshot.computers.Count | Should -Be 2
        $script:Snapshot.groups.Count | Should -Be 1
    }

    It 'decodes the binary objectSid off the wire' {
        $group = $script:Snapshot.groups | Where-Object { $_.samAccountName -eq 'Domain Admins' }
        $group | Should -Not -BeNullOrEmpty
        $group.sid | Should -BeLike 'S-1-5-21-*'
        $group.sid | Should -BeLike '*-512' -Because 'the seeded SID is a Domain Admins RID'
    }

    It 'decodes userAccountControl fetched from the directory' {
        $svc = $script:Snapshot.users | Where-Object { $_.samAccountName -eq 'svc-sql' }
        $svc.userAccountControl | Should -Be 66048
        $svc.uacFlags | Should -Contain 'DONT_EXPIRE_PASSWORD'
        $svc.enabled | Should -BeTrue
    }

    It 'converts FILETIME attributes fetched from the directory' {
        $svc = $script:Snapshot.users | Where-Object { $_.samAccountName -eq 'svc-sql' }
        $svc.pwdLastSet | Should -BeOfType [DateTimeOffset]
        $svc.pwdLastSet.UtcDateTime.Year | Should -BeGreaterThan 2000
    }

    It 'collects multi-valued attributes such as servicePrincipalName' {
        $svc = $script:Snapshot.users | Where-Object { $_.samAccountName -eq 'svc-sql' }
        @($svc.servicePrincipalName).Count | Should -Be 1
        $svc.servicePrincipalName[0] | Should -BeLike 'MSSQLSvc/*'
    }

    It 'reads group membership' {
        $group = $script:Snapshot.groups | Where-Object { $_.samAccountName -eq 'Domain Admins' }
        @($group.members).Count | Should -Be 1
        $group.members[0] | Should -BeLike '*admin-jdoe*'
    }
}

Describe 'Rule engine over live-fetched data' -Skip:(-not $LdapReachable) {
    BeforeAll {
        $script:Findings = InModuleScope ADRot -Parameters @{ c = $script:TestConfig } {
            param($c)
            $snapshot = Get-ADRotLdapSnapshot -Config $c
            @(Invoke-ADRotRuleSet -Snapshot $snapshot -Config $c)
        } 6>$null
    }

    It 'produces findings from data captured over the wire' {
        $script:Findings.Count | Should -BeGreaterThan 0
    }

    It 'detects the Kerberoastable service account seeded in the directory' {
        $f = $script:Findings | Where-Object RuleId -eq 'AD-004'
        $f | Should -Not -BeNullOrEmpty
        $f.Affected.Name | Should -Contain 'svc-sql'
    }

    It 'detects the AS-REP roastable account seeded in the directory' {
        ($script:Findings | Where-Object RuleId -eq 'AD-003').Affected.Name |
            Should -Contain 'asrep-victim'
    }

    It 'detects PASSWD_NOTREQD on the seeded kiosk account' {
        ($script:Findings | Where-Object RuleId -eq 'AD-002').Affected.Name |
            Should -Contain 'kiosk'
    }

    It 'detects unconstrained delegation on the seeded print server' {
        ($script:Findings | Where-Object RuleId -eq 'AD-012').Affected.Name |
            Should -Contain 'PRINT01$'
    }

    It 'detects the out-of-support operating system' {
        ($script:Findings | Where-Object RuleId -eq 'AD-013').Affected.Name |
            Should -Contain 'OLDAPP01$'
    }

    It 'scores the captured directory' {
        InModuleScope ADRot -Parameters @{ f = $script:Findings } {
            param($f)
            $score = Get-ADRotScore -Finding $f
            $score.Score | Should -BeLessThan 100
            $score.Grade | Should -BeIn @('A', 'B', 'C', 'D', 'F')
        }
    }
}

Describe 'Connection error handling' -Skip:(-not $LdapReachable) {
    It 'reports a clear error when the server refuses the connection' {
        InModuleScope ADRot {
            $config = Get-ADRotDefaultConfig
            $config.server = '127.0.0.1'
            $config.port = 3891      # nothing listening
            $config.authType = 'Anonymous'
            $config.searchBase = 'dc=adrot,dc=test'
            { Get-ADRotLdapSnapshot -Config $config } | Should -Throw '*could not bind*'
        } 6>$null
    }

    It 'refuses anonymous auth without an explicit server rather than guessing' {
        InModuleScope ADRot {
            $config = Get-ADRotDefaultConfig
            $config.authType = 'Anonymous'
            $config.server = $null
            { Get-ADRotLdapSnapshot -Config $config } | Should -Throw '*requires an explicit -Server*'
        } 6>$null
    }
}

