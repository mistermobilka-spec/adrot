#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'ADRot' 'ADRot.psd1') -Force
    $script:FixtureDir = Join-Path $PSScriptRoot '..' 'fixtures'
}

AfterAll {
    Remove-Module ADRot -Force -ErrorAction SilentlyContinue
}

Describe 'ConvertTo-ADRotHtml' {
    BeforeAll {
        $script:DirtyResult = Invoke-ADRotScan -SnapshotPath (Join-Path $script:FixtureDir 'dirty-domain.json') `
            -Quiet -InformationAction SilentlyContinue
        $script:CleanResult = Invoke-ADRotScan -SnapshotPath (Join-Path $script:FixtureDir 'clean-domain.json') `
            -Quiet -InformationAction SilentlyContinue
        $script:Html = InModuleScope ADRot -Parameters @{ r = $script:DirtyResult } {
            ConvertTo-ADRotHtml -Result $r
        }
    }

    It 'produces a complete HTML document' {
        $script:Html | Should -BeLike '*<!DOCTYPE html>*'
        $script:Html | Should -BeLike '*</html>*'
    }

    It 'includes the score and grade' {
        $script:Html | Should -BeLike '*grade F*'
    }

    It 'includes every finding' {
        foreach ($f in $script:DirtyResult.Findings) {
            $script:Html | Should -BeLike "*$($f.RuleId)*" -Because "$($f.RuleId) must appear in the report"
        }
    }

    It 'includes remediation guidance for each finding' {
        $script:Html | Should -BeLike '*Remediation*'
        $script:Html | Should -BeLike '*Group Managed Service Account*'
    }

    It 'has no external references — no CDN, font, script src or remote image' {
        # A report describing domain security posture must not phone home.
        $script:Html | Should -Not -Match '<script[^>]+src='
        $script:Html | Should -Not -Match '<link[^>]+href="https?://'
        $script:Html | Should -Not -Match '@import\s+url'
        $script:Html | Should -Not -Match '<img[^>]+src="https?://'
        $script:Html | Should -Not -Match 'fonts\.googleapis'
        $script:Html | Should -Not -Match 'cdn\.'
    }

    It 'renders an explicit empty state for a clean domain' {
        $html = InModuleScope ADRot -Parameters @{ r = $script:CleanResult } {
            ConvertTo-ADRotHtml -Result $r
        }
        $html | Should -BeLike '*No findings*'
    }

    It 'supports both colour schemes' {
        $script:Html | Should -BeLike '*prefers-color-scheme: dark*'
    }
}

Describe 'HTML injection defence' {
    It 'encodes markup that arrives in directory attributes' {
        # samAccountName and DN are attacker-influenceable in a domain an attacker has
        # any write access to. Encoding them is a security control, not cosmetics.
        InModuleScope ADRot {
            $snapshot = ConvertTo-ADRotNormalisedSnapshot -Snapshot @{
                schemaVersion = 1
                capturedAt    = '2026-07-01T00:00:00Z'
                domain        = @{ dnsRoot = 'evil<script>alert(1)</script>.local' }
                domainPolicy  = @{}
                users         = @(
                    @{ samAccountName    = '<img src=x onerror=alert(1)>'
                       distinguishedName = 'CN="><script>alert(2)</script>,DC=x'
                       userAccountControl = 544 }
                )
                computers = @(); groups = @()
            }
            $findings = Invoke-ADRotRuleSet -Snapshot $snapshot -Config (Get-ADRotDefaultConfig) `
                -Rule (Get-ADRotRule -Id 'AD-002')
            $findings.Count | Should -Be 1

            $result = [pscustomobject]@{
                Tool = 'ADRot'; ToolVersion = '0.0.0-test'
                CapturedAt = '2026-07-01T00:00:00Z'; DurationMs = 1
                Domain = $snapshot.domain; DomainPolicy = @{}
                Score = (Get-ADRotScore -Finding $findings)
                Findings = $findings
                Stats = [pscustomobject]@{ Users = 1; Computers = 0; Groups = 0; RulesEvaluated = 1; RulesTotal = 17 }
            }
            $html = ConvertTo-ADRotHtml -Result $result

            $html | Should -Not -Match '<script>alert\(1\)</script>'
            $html | Should -Not -Match '<script>alert\(2\)</script>'
            $html | Should -Not -Match '<img src=x onerror'
            $html | Should -BeLike '*&lt;img src=x onerror*'
            $html | Should -BeLike '*&lt;script&gt;*'
        }
    }
}

Describe 'Write-ADRotConsole' {
    It 'renders without throwing for a domain with findings' {
        InModuleScope ADRot -Parameters @{ dir = $script:FixtureDir } {
            $result = Invoke-ADRotScan -SnapshotPath (Join-Path $dir 'dirty-domain.json') `
                -Quiet -InformationAction SilentlyContinue
            { Write-ADRotConsole -Result $result 6>$null } | Should -Not -Throw
        }
    }

    It 'renders without throwing for a clean domain' {
        InModuleScope ADRot -Parameters @{ dir = $script:FixtureDir } {
            $result = Invoke-ADRotScan -SnapshotPath (Join-Path $dir 'clean-domain.json') `
                -Quiet -InformationAction SilentlyContinue
            { Write-ADRotConsole -Result $result 6>$null } | Should -Not -Throw
        }
    }
}

Describe 'End-to-end HTML output' {
    It 'writes a readable HTML file to disk' {
        $out = Join-Path ([System.IO.Path]::GetTempPath()) "adrot-report-$([guid]::NewGuid()).html"
        try {
            Invoke-ADRotScan -SnapshotPath (Join-Path $script:FixtureDir 'dirty-domain.json') `
                -HtmlPath $out -Quiet -InformationAction SilentlyContinue | Out-Null
            Test-Path $out | Should -BeTrue
            (Get-Item $out).Length | Should -BeGreaterThan 5000
            (Get-Content $out -Raw) | Should -BeLike '*Active Directory hygiene report*'
        }
        finally { Remove-Item $out -ErrorAction SilentlyContinue }
    }
}
