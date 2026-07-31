#Requires -Modules Pester

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..' '..' 'src' 'ADRot' 'ADRot.psd1'
    Import-Module $script:ModulePath -Force

    $script:FixtureDir = Join-Path $PSScriptRoot '..' 'fixtures'
    $script:CleanPath = Join-Path $script:FixtureDir 'clean-domain.json'
    $script:DirtyPath = Join-Path $script:FixtureDir 'dirty-domain.json'

    # Both fixtures pin capturedAt, so every age-based rule is deterministic.
    $script:Clean = Invoke-ADRotScan -SnapshotPath $script:CleanPath -Quiet -InformationAction SilentlyContinue
    $script:Dirty = Invoke-ADRotScan -SnapshotPath $script:DirtyPath -Quiet -InformationAction SilentlyContinue
}

AfterAll {
    Remove-Module ADRot -Force -ErrorAction SilentlyContinue
}

Describe 'Rule catalogue integrity' {
    It 'exposes 17 rules' {
        (Get-ADRotRule).Count | Should -Be 17
    }

    It 'has unique rule IDs' {
        $ids = (Get-ADRotRule).Id
        ($ids | Select-Object -Unique).Count | Should -Be $ids.Count
    }

    It 'gives every rule a rationale, remediation and reference' {
        foreach ($rule in Get-ADRotRule) {
            $rule.Rationale   | Should -Not -BeNullOrEmpty -Because "$($rule.Id) needs a rationale"
            $rule.Remediation | Should -Not -BeNullOrEmpty -Because "$($rule.Id) needs remediation guidance"
            $rule.Reference   | Should -Match '^https://' -Because "$($rule.Id) needs an authoritative link"
        }
    }

    It 'gives every rule a positive weight' {
        foreach ($rule in Get-ADRotRule) {
            $rule.Weight | Should -BeGreaterThan 0 -Because "$($rule.Id) must affect the score"
        }
    }

    It 'filters by severity' {
        $critical = Get-ADRotRule -Severity Critical
        $critical.Count | Should -BeGreaterThan 0
        $critical.Severity | ForEach-Object { $_ | Should -Be 'Critical' }
    }

    It 'filters by category' {
        (Get-ADRotRule -Category Domain).Category | ForEach-Object { $_ | Should -Be 'Domain' }
    }

    It 'filters by ID' {
        (Get-ADRotRule -Id 'AD-001').Id | Should -Be 'AD-001'
    }
}

Describe 'Clean domain fixture' {
    It 'produces no findings at all' {
        $names = ($script:Clean.Findings | ForEach-Object { "$($_.RuleId) ($($_.Affected.Name -join ','))" }) -join '; '
        $script:Clean.Findings.Count | Should -Be 0 -Because "a healthy domain must be silent, but got: $names"
    }

    It 'scores 100 and grades A' {
        $script:Clean.Score.Score | Should -Be 100
        $script:Clean.Score.Grade | Should -Be 'A'
    }
}

Describe 'Rotten domain fixture' {
    It 'fires every rule in the catalogue' {
        $fired = $script:Dirty.Findings.RuleId
        foreach ($rule in Get-ADRotRule) {
            $fired | Should -Contain $rule.Id -Because "$($rule.Id) must be reachable by the fixture"
        }
    }

    It 'floors the score at 0 and grades F' {
        $script:Dirty.Score.Score | Should -Be 0
        $script:Dirty.Score.Grade | Should -Be 'F'
    }

    It 'orders findings most severe first' {
        $rank = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }
        $ranks = $script:Dirty.Findings | ForEach-Object { $rank[$_.Severity] }
        $sorted = $ranks | Sort-Object -Descending
        "$ranks" | Should -Be "$sorted"
    }
}

Describe 'Individual rule behaviour' {
    BeforeAll {
        function Get-Finding {
            param([string] $Id)
            return $script:Dirty.Findings | Where-Object RuleId -eq $Id
        }
    }

    It 'AD-001 catches reversible encryption on legacy.radius' {
        (Get-Finding 'AD-001').Affected.Name | Should -Be 'legacy.radius'
    }

    It 'AD-002 catches PASSWD_NOTREQD on kiosk' {
        (Get-Finding 'AD-002').Affected.Name | Should -Be 'kiosk'
    }

    It 'AD-003 catches the AS-REP roastable account' {
        (Get-Finding 'AD-003').Affected.Name | Should -Be 'asrep.victim'
    }

    It 'AD-004 catches the Kerberoastable service account and reports its SPN' {
        $f = Get-Finding 'AD-004'
        $f.Affected.Name | Should -Be 'svc-sql'
        $f.Affected.Detail | Should -BeLike '*MSSQLSvc/sql01*'
    }

    It 'AD-006 reports the dormant account with its age' {
        $f = Get-Finding 'AD-006'
        $f.Affected.Name | Should -Be 'dormant.user'
        $f.Affected.Detail | Should -BeLike '*300 days ago*'
    }

    It 'AD-007 catches the never-logged-on account' {
        (Get-Finding 'AD-007').Affected.Name | Should -Be 'provisioned.never'
    }

    It 'AD-009 flags Domain Admins as oversized but not Enterprise Admins' {
        $f = Get-Finding 'AD-009'
        $f.Affected.Name | Should -Contain 'Domain Admins'
        $f.Affected.Name | Should -Not -Contain 'Enterprise Admins'
    }

    It 'AD-012 flags the delegating server but never a domain controller' {
        $f = Get-Finding 'AD-012'
        $f.Affected.Name | Should -Contain 'PRINT01$'
        $f.Affected.Name | Should -Not -Contain 'DC01$' -Because 'domain controllers delegate by design'
    }

    It 'AD-013 catches the out-of-support operating system' {
        $f = Get-Finding 'AD-013'
        $f.Affected.Name | Should -Be 'OLDAPP01$'
        $f.Affected.Detail | Should -BeLike '*2008 R2*'
    }

    It 'AD-015 reports the stale krbtgt password' {
        (Get-Finding 'AD-015').Affected.Detail | Should -BeLike '*900 days ago*'
    }

    It 'AD-016 catches a non-zero machine account quota' {
        (Get-Finding 'AD-016').Affected.Detail | Should -BeLike '*Set to 10*'
    }

    It 'AD-017 reports both the short minimum length and the disabled lockout' {
        $f = Get-Finding 'AD-017'
        $f.AffectedCount | Should -Be 2
        $f.Affected.Name | Should -Contain 'Minimum password length'
        $f.Affected.Name | Should -Contain 'Account lockout threshold'
    }
}

Describe 'AD-011 orphaned adminCount (regression)' {
    It 'flags the genuinely orphaned account' {
        ($script:Dirty.Findings | Where-Object RuleId -eq 'AD-011').Affected.Name |
            Should -Contain 'expired.admin'
    }

    It 'never flags krbtgt, which carries adminCount=1 permanently by design' {
        # Regression guard: the first implementation flagged krbtgt on every clean
        # domain, which would have made the tool untrustworthy on first run.
        $all = @($script:Clean.Findings) + @($script:Dirty.Findings)
        foreach ($f in ($all | Where-Object RuleId -eq 'AD-011')) {
            $f.Affected.Name | Should -Not -Contain 'krbtgt'
        }
    }

    It 'does not flag an account that is in a protected group other than tier-0' {
        InModuleScope ADRot {
            $snapshot = ConvertTo-ADRotNormalisedSnapshot -Snapshot @{
                schemaVersion = 1
                capturedAt    = '2026-07-01T00:00:00Z'
                domain        = @{}; domainPolicy = @{}
                users         = @(
                    @{ samAccountName = 'backup.op'; distinguishedName = 'CN=backup.op,DC=x'
                       userAccountControl = 512; adminCount = 1 }
                )
                computers     = @()
                groups        = @(
                    @{ samAccountName = 'Backup Operators'; distinguishedName = 'CN=BO,DC=x'
                       sid = 'S-1-5-32-551'; members = @('CN=backup.op,DC=x') }
                )
            }
            $rule = Get-ADRotRule -Id 'AD-011'
            $findings = @(Invoke-ADRotRuleSet -Snapshot $snapshot -Config (Get-ADRotDefaultConfig) -Rule $rule)
            $findings.Count | Should -Be 0 -Because 'Backup Operators is AdminSDHolder-protected'
        }
    }

    It 'flags an account whose only group is not protected' {
        InModuleScope ADRot {
            $snapshot = ConvertTo-ADRotNormalisedSnapshot -Snapshot @{
                schemaVersion = 1
                capturedAt    = '2026-07-01T00:00:00Z'
                domain        = @{}; domainPolicy = @{}
                users         = @(
                    @{ samAccountName = 'ex.admin'; distinguishedName = 'CN=ex.admin,DC=x'
                       userAccountControl = 512; adminCount = 1 }
                )
                computers     = @()
                groups        = @(
                    @{ samAccountName = 'Helpdesk'; distinguishedName = 'CN=HD,DC=x'
                       sid = 'S-1-5-21-1-2-3-1234'; members = @('CN=ex.admin,DC=x') }
                )
            }
            $rule = Get-ADRotRule -Id 'AD-011'
            $findings = Invoke-ADRotRuleSet -Snapshot $snapshot -Config (Get-ADRotDefaultConfig) -Rule $rule
            $findings.Count | Should -Be 1
        }
    }
}

Describe 'Rules ignore disabled accounts' {
    It 'does not report a disabled account with every dangerous flag set' {
        InModuleScope ADRot {
            # 514 = NORMAL_ACCOUNT + ACCOUNTDISABLE, plus reversible/notreqd/preauth bits.
            $uac = 514 -bor 0x80 -bor 0x20 -bor 0x400000 -bor 0x10000
            $snapshot = ConvertTo-ADRotNormalisedSnapshot -Snapshot @{
                schemaVersion = 1
                capturedAt    = '2026-07-01T00:00:00Z'
                domain        = @{}; domainPolicy = @{}
                users         = @(
                    @{ samAccountName = 'retired'; distinguishedName = 'CN=retired,DC=x'
                       userAccountControl = $uac; adminCount = 0
                       servicePrincipalName = @('HTTP/old.x') }
                )
                computers     = @(); groups = @()
            }
            $rules = Get-ADRotRule -Id @('AD-001', 'AD-002', 'AD-003', 'AD-004', 'AD-005')
            $findings = @(Invoke-ADRotRuleSet -Snapshot $snapshot -Config (Get-ADRotDefaultConfig) -Rule $rules)
            $findings.Count | Should -Be 0 -Because 'a disabled account is not an active risk'
        }
    }
}

Describe 'AD-007 grace window for new joiners' {
    It 'does not flag an account created inside the stale window' {
        InModuleScope ADRot {
            $snapshot = ConvertTo-ADRotNormalisedSnapshot -Snapshot @{
                schemaVersion = 1
                capturedAt    = '2026-07-01T00:00:00Z'
                domain        = @{}; domainPolicy = @{}
                users         = @(
                    @{ samAccountName = 'new.joiner'; distinguishedName = 'CN=nj,DC=x'
                       userAccountControl = 512; adminCount = 0
                       lastLogonTimestamp = $null; whenCreated = '2026-06-20T00:00:00Z' }
                )
                computers     = @(); groups = @()
            }
            $rule = Get-ADRotRule -Id 'AD-007'
            $findings = @(Invoke-ADRotRuleSet -Snapshot $snapshot -Config (Get-ADRotDefaultConfig) -Rule $rule)
            $findings.Count | Should -Be 0 -Because 'an 11-day-old account has not had time to log on'
        }
    }
}
