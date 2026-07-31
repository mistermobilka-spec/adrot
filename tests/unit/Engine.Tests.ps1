#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'ADRot' 'ADRot.psd1') -Force
}

AfterAll {
    Remove-Module ADRot -Force -ErrorAction SilentlyContinue
}

Describe 'Get-ADRotScore' {
    It 'scores an empty finding set as 100 / A' {
        InModuleScope ADRot {
            $score = Get-ADRotScore -Finding @()
            $score.Score | Should -Be 100
            $score.Grade | Should -Be 'A'
            $score.TotalFindings | Should -Be 0
        }
    }

    It 'deducts each finding weight exactly once' {
        InModuleScope ADRot {
            $findings = @(
                [pscustomobject]@{ Severity = 'Critical'; Weight = 20; AffectedCount = 900 }
                [pscustomobject]@{ Severity = 'Medium';   Weight = 6;  AffectedCount = 1 }
            )
            # 100 - 26 = 74, and the 900 affected objects must not compound the deduction.
            (Get-ADRotScore -Finding $findings).Score | Should -Be 74
        }
    }

    It 'clamps at zero rather than going negative' {
        InModuleScope ADRot {
            $findings = 1..20 | ForEach-Object {
                [pscustomobject]@{ Severity = 'Critical'; Weight = 20; AffectedCount = 1 }
            }
            (Get-ADRotScore -Finding $findings).Score | Should -Be 0
        }
    }

    It 'grades <Score> as <Grade>' -ForEach @(
        @{ Weight = 0;  Score = 100; Grade = 'A' }
        @{ Weight = 10; Score = 90;  Grade = 'A' }
        @{ Weight = 11; Score = 89;  Grade = 'B' }
        @{ Weight = 25; Score = 75;  Grade = 'B' }
        @{ Weight = 26; Score = 74;  Grade = 'C' }
        @{ Weight = 41; Score = 59;  Grade = 'D' }
        @{ Weight = 61; Score = 39;  Grade = 'F' }
    ) {
        InModuleScope ADRot -Parameters @{ w = $Weight; s = $Score; g = $Grade } {
            $result = Get-ADRotScore -Finding @([pscustomobject]@{ Severity = 'Low'; Weight = $w })
            $result.Score | Should -Be $s
            $result.Grade | Should -Be $g
        }
    }

    It 'counts findings per severity' {
        InModuleScope ADRot {
            $findings = @(
                [pscustomobject]@{ Severity = 'Critical'; Weight = 1 }
                [pscustomobject]@{ Severity = 'High';     Weight = 1 }
                [pscustomobject]@{ Severity = 'High';     Weight = 1 }
                [pscustomobject]@{ Severity = 'Low';      Weight = 1 }
            )
            $score = Get-ADRotScore -Finding $findings
            $score.Critical | Should -Be 1
            $score.High     | Should -Be 2
            $score.Medium   | Should -Be 0
            $score.Low      | Should -Be 1
        }
    }
}

Describe 'Test-ADRotFailThreshold' {
    BeforeAll {
        $script:Sample = @(
            [pscustomobject]@{ Severity = 'Medium' }
            [pscustomobject]@{ Severity = 'Low' }
        )
    }

    It 'never fails when the threshold is None' {
        InModuleScope ADRot -Parameters @{ f = $script:Sample } {
            Test-ADRotFailThreshold -Finding $f -FailOn 'None' | Should -BeFalse
        }
    }

    It 'does not fail when all findings are below the threshold' {
        InModuleScope ADRot -Parameters @{ f = $script:Sample } {
            Test-ADRotFailThreshold -Finding $f -FailOn 'High' | Should -BeFalse
        }
    }

    It 'fails when a finding is exactly at the threshold' {
        InModuleScope ADRot -Parameters @{ f = $script:Sample } {
            Test-ADRotFailThreshold -Finding $f -FailOn 'Medium' | Should -BeTrue
        }
    }

    It 'fails when a finding is above the threshold' {
        InModuleScope ADRot -Parameters @{ f = $script:Sample } {
            Test-ADRotFailThreshold -Finding $f -FailOn 'Low' | Should -BeTrue
        }
    }

    It 'does not fail on an empty finding set' {
        InModuleScope ADRot {
            Test-ADRotFailThreshold -Finding @() -FailOn 'Critical' | Should -BeFalse
        }
    }
}

Describe 'Invoke-ADRotRuleSet resilience' {
    It 'reports a throwing rule as an error finding instead of aborting the scan' {
        InModuleScope ADRot {
            $exploding = New-ADRotRule -Id 'AD-999' -Title 'Always explodes' -Severity 'High' `
                -Category 'Domain' -Weight 10 -Rationale 'n/a' -Remediation 'n/a' `
                -Reference 'https://example.invalid/' `
                -Test { throw 'boom' }

            $snapshot = ConvertTo-ADRotNormalisedSnapshot -Snapshot @{
                schemaVersion = 1; capturedAt = '2026-07-01T00:00:00Z'
                domain = @{}; domainPolicy = @{}; users = @(); computers = @(); groups = @()
            }

            $findings = Invoke-ADRotRuleSet -Snapshot $snapshot -Config (Get-ADRotDefaultConfig) `
                -Rule @($exploding) -WarningAction SilentlyContinue

            $findings.Count | Should -Be 1
            $findings[0].Errored | Should -BeTrue
            $findings[0].Weight  | Should -Be 0 -Because 'a broken rule must not move the score'
            $findings[0].Rationale | Should -BeLike '*boom*'
        }
    }

    It 'a failed rule does not prevent other rules from running' {
        InModuleScope ADRot {
            $exploding = New-ADRotRule -Id 'AD-998' -Title 'Explodes' -Severity 'High' `
                -Category 'Domain' -Weight 10 -Rationale 'n/a' -Remediation 'n/a' `
                -Reference 'https://example.invalid/' -Test { throw 'boom' }
            $working = New-ADRotRule -Id 'AD-997' -Title 'Works' -Severity 'Low' `
                -Category 'Domain' -Weight 2 -Rationale 'n/a' -Remediation 'n/a' `
                -Reference 'https://example.invalid/' `
                -Test { New-ADRotAffectedObject -Name 'thing' -Detail 'found' }

            $snapshot = ConvertTo-ADRotNormalisedSnapshot -Snapshot @{
                schemaVersion = 1; capturedAt = '2026-07-01T00:00:00Z'
                domain = @{}; domainPolicy = @{}; users = @(); computers = @(); groups = @()
            }
            $findings = Invoke-ADRotRuleSet -Snapshot $snapshot -Config (Get-ADRotDefaultConfig) `
                -Rule @($exploding, $working) -WarningAction SilentlyContinue

            $findings.RuleId | Should -Contain 'AD-997'
        }
    }

    It 'honours disabledRules' {
        InModuleScope ADRot {
            $snapshot = Import-ADRotSnapshot -Path (Join-Path $PSScriptRoot '..' 'fixtures' 'dirty-domain.json')
            $config = Get-ADRotDefaultConfig
            $config.disabledRules = @('AD-001', 'AD-012')

            $findings = Invoke-ADRotRuleSet -Snapshot $snapshot -Config $config
            $findings.RuleId | Should -Not -Contain 'AD-001'
            $findings.RuleId | Should -Not -Contain 'AD-012'
            $findings.RuleId | Should -Contain 'AD-002'
        }
    }
}

Describe 'Invoke-ADRotScan contract' {
    It 'returns a result carrying score, findings and stats' {
        $result = Invoke-ADRotScan -SnapshotPath (Join-Path $PSScriptRoot '..' 'fixtures' 'dirty-domain.json') `
            -Quiet -InformationAction SilentlyContinue
        $result.Tool | Should -Be 'ADRot'
        $result.Score.Score | Should -BeOfType [int]
        $result.Stats.Users | Should -Be 10
        $result.Stats.Computers | Should -Be 4
        $result.Stats.RulesTotal | Should -Be 17
    }

    It 'writes machine-readable JSON that round-trips' {
        $out = Join-Path ([System.IO.Path]::GetTempPath()) "adrot-test-$([guid]::NewGuid()).json"
        try {
            Invoke-ADRotScan -SnapshotPath (Join-Path $PSScriptRoot '..' 'fixtures' 'dirty-domain.json') `
                -JsonPath $out -Quiet -InformationAction SilentlyContinue | Out-Null
            Test-Path $out | Should -BeTrue
            $parsed = Get-Content $out -Raw | ConvertFrom-Json
            $parsed.Score.Grade | Should -Be 'F'
            $parsed.Findings.Count | Should -Be 17
        }
        finally { Remove-Item $out -ErrorAction SilentlyContinue }
    }

    It 'throws when -FailOn is breached, after emitting the result' {
        $path = Join-Path $PSScriptRoot '..' 'fixtures' 'dirty-domain.json'
        { Invoke-ADRotScan -SnapshotPath $path -FailOn Critical -Quiet `
            -InformationAction SilentlyContinue -WarningAction SilentlyContinue } |
            Should -Throw '*at or above severity*'
    }

    It 'does not throw when -FailOn is not breached' {
        $path = Join-Path $PSScriptRoot '..' 'fixtures' 'clean-domain.json'
        { Invoke-ADRotScan -SnapshotPath $path -FailOn Critical -Quiet `
            -InformationAction SilentlyContinue } | Should -Not -Throw
    }

    It 'rejects a missing snapshot with a clear message' {
        { Invoke-ADRotScan -SnapshotPath './does-not-exist.json' -Quiet } |
            Should -Throw '*snapshot not found*'
    }
}
