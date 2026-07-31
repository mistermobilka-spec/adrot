#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'src' 'ADRot' 'ADRot.psd1') -Force
    $script:FixtureDir = Join-Path $PSScriptRoot '..' 'fixtures'
}

AfterAll {
    Remove-Module ADRot -Force -ErrorAction SilentlyContinue
}

Describe 'Import-ADRotSnapshot' {
    It 'loads a fixture and reports the expected object counts' {
        InModuleScope ADRot -Parameters @{ dir = $script:FixtureDir } {
            $snapshot = Import-ADRotSnapshot -Path (Join-Path $dir 'clean-domain.json')
            $snapshot.users.Count     | Should -Be 4
            $snapshot.computers.Count | Should -Be 2
            $snapshot.groups.Count    | Should -Be 2
        }
    }

    It 'rejects a missing file with a clear message' {
        InModuleScope ADRot {
            { Import-ADRotSnapshot -Path './nope.json' } | Should -Throw '*snapshot not found*'
        }
    }

    It 'rejects malformed JSON' {
        InModuleScope ADRot {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "adrot-bad-$([guid]::NewGuid()).json"
            Set-Content -LiteralPath $tmp -Value '{ not json'
            try { { Import-ADRotSnapshot -Path $tmp } | Should -Throw '*not valid JSON*' }
            finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
        }
    }

    It 'rejects an unknown schema version rather than misreading it' {
        InModuleScope ADRot {
            { ConvertTo-ADRotNormalisedSnapshot -Snapshot @{ schemaVersion = 99 } } |
                Should -Throw '*schemaVersion 99*'
        }
    }

    It 'rejects a snapshot with no schemaVersion' {
        InModuleScope ADRot {
            { ConvertTo-ADRotNormalisedSnapshot -Snapshot @{} } | Should -Throw '*no schemaVersion*'
        }
    }
}

Describe 'Snapshot normalisation' {
    It 'turns absent collections into empty arrays' {
        InModuleScope ADRot {
            $snapshot = ConvertTo-ADRotNormalisedSnapshot -Snapshot @{ schemaVersion = 1 }
            $snapshot.users.Count     | Should -Be 0
            $snapshot.computers.Count | Should -Be 0
            $snapshot.groups.Count    | Should -Be 0
            $snapshot.domain          | Should -BeOfType [hashtable]
            $snapshot.domainPolicy    | Should -BeOfType [hashtable]
        }
    }

    It 'wraps a single object into an array so .Count is safe' {
        InModuleScope ADRot {
            $snapshot = ConvertTo-ADRotNormalisedSnapshot -Snapshot @{
                schemaVersion = 1
                users = @{ samAccountName = 'solo'; userAccountControl = 512 }
            }
            $snapshot.users.Count | Should -Be 1
            $snapshot.users[0].samAccountName | Should -Be 'solo'
        }
    }

    It 'derives uacFlags and enabled from userAccountControl' {
        InModuleScope ADRot {
            $snapshot = ConvertTo-ADRotNormalisedSnapshot -Snapshot @{
                schemaVersion = 1
                users = @(
                    @{ samAccountName = 'on';  userAccountControl = 512 }
                    @{ samAccountName = 'off'; userAccountControl = 514 }
                )
            }
            $snapshot.users[0].enabled  | Should -BeTrue
            $snapshot.users[0].uacFlags | Should -Contain 'NORMAL_ACCOUNT'
            $snapshot.users[1].enabled  | Should -BeFalse
            $snapshot.users[1].uacFlags | Should -Contain 'ACCOUNTDISABLE'
        }
    }

    It 'treats an account with no userAccountControl as disabled rather than guessing' {
        InModuleScope ADRot {
            $snapshot = ConvertTo-ADRotNormalisedSnapshot -Snapshot @{
                schemaVersion = 1
                users = @(@{ samAccountName = 'unknown' })
            }
            $snapshot.users[0].enabled | Should -BeFalse
        }
    }

    It 'accepts both ISO-8601 strings and raw FILETIME integers for timestamps' {
        InModuleScope ADRot {
            $snapshot = ConvertTo-ADRotNormalisedSnapshot -Snapshot @{
                schemaVersion = 1
                users = @(
                    @{ samAccountName = 'iso';  userAccountControl = 512; pwdLastSet = '2024-01-15T10:00:00Z' }
                    @{ samAccountName = 'ft';   userAccountControl = 512; pwdLastSet = 133000000000000000 }
                    @{ samAccountName = 'zero'; userAccountControl = 512; pwdLastSet = 0 }
                )
            }
            $snapshot.users[0].pwdLastSet | Should -BeOfType [DateTimeOffset]
            $snapshot.users[1].pwdLastSet | Should -BeOfType [DateTimeOffset]
            $snapshot.users[2].pwdLastSet | Should -BeNullOrEmpty
        }
    }

    It 'is idempotent — normalising twice does not change the result' {
        InModuleScope ADRot {
            $raw = @{
                schemaVersion = 1
                users = @(@{ samAccountName = 'a'; userAccountControl = 512; pwdLastSet = '2024-01-15T10:00:00Z' })
            }
            $once  = ConvertTo-ADRotNormalisedSnapshot -Snapshot $raw
            $twice = ConvertTo-ADRotNormalisedSnapshot -Snapshot $once
            $twice.users[0].pwdLastSet | Should -Be $once.users[0].pwdLastSet
            $twice.users[0].enabled    | Should -Be $once.users[0].enabled
        }
    }
}

Describe 'Resolve-ADRotConfig' {
    AfterEach {
        # Environment overrides leak between tests otherwise.
        foreach ($n in @('ADROT_SERVER', 'ADROT_PORT', 'ADROT_STALE_DAYS', 'ADROT_USE_SSL', 'ADROT_FAIL_ON')) {
            [Environment]::SetEnvironmentVariable($n, $null)
        }
    }

    It 'returns sane defaults with no file and no environment' {
        InModuleScope ADRot {
            $config = Resolve-ADRotConfig
            $config.port | Should -Be 389
            $config.thresholds.staleDays | Should -Be 90
            $config.failOn | Should -Be 'None'
        }
    }

    It 'lets environment variables override defaults' {
        InModuleScope ADRot {
            [Environment]::SetEnvironmentVariable('ADROT_SERVER', 'dc99.test.local')
            [Environment]::SetEnvironmentVariable('ADROT_STALE_DAYS', '30')
            $config = Resolve-ADRotConfig
            $config.server | Should -Be 'dc99.test.local'
            $config.thresholds.staleDays | Should -Be 30
        }
    }

    It 'rejects a non-integer where an integer is required' {
        InModuleScope ADRot {
            [Environment]::SetEnvironmentVariable('ADROT_PORT', 'not-a-number')
            { Resolve-ADRotConfig } | Should -Throw '*must be an integer*'
        }
    }

    It 'rejects an invalid failOn value' {
        InModuleScope ADRot {
            [Environment]::SetEnvironmentVariable('ADROT_FAIL_ON', 'Catastrophic')
            { Resolve-ADRotConfig } | Should -Throw '*failOn must be one of*'
        }
    }

    It 'switches to port 636 when SSL is enabled and no port was pinned' {
        InModuleScope ADRot {
            [Environment]::SetEnvironmentVariable('ADROT_USE_SSL', 'true')
            (Resolve-ADRotConfig).port | Should -Be 636
        }
    }

    It 'keeps an explicitly pinned port even with SSL enabled' {
        InModuleScope ADRot {
            [Environment]::SetEnvironmentVariable('ADROT_USE_SSL', 'true')
            [Environment]::SetEnvironmentVariable('ADROT_PORT', '3269')
            (Resolve-ADRotConfig).port | Should -Be 3269
        }
    }

    It 'loads a config file and ignores JSON pseudo-comments' {
        InModuleScope ADRot {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "adrot-cfg-$([guid]::NewGuid()).json"
            Set-Content -LiteralPath $tmp -Value '{ "$comment": "ignore me", "port": 3268, "thresholds": { "staleDays": 45 } }'
            try {
                $config = Resolve-ADRotConfig -ConfigPath $tmp
                $config.port | Should -Be 3268
                $config.thresholds.staleDays | Should -Be 45
                $config.thresholds.minPasswordLength | Should -Be 14 -Because 'unspecified thresholds keep their default'
                $config.Keys | Should -Not -Contain '$comment'
            }
            finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
        }
    }

    It 'lets the environment win over the config file' {
        InModuleScope ADRot {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "adrot-cfg-$([guid]::NewGuid()).json"
            Set-Content -LiteralPath $tmp -Value '{ "server": "from-file" }'
            [Environment]::SetEnvironmentVariable('ADROT_SERVER', 'from-env')
            try { (Resolve-ADRotConfig -ConfigPath $tmp).server | Should -Be 'from-env' }
            finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
        }
    }

    It 'rejects a config path that does not exist' {
        InModuleScope ADRot {
            { Resolve-ADRotConfig -ConfigPath './missing.json' } | Should -Throw '*config file not found*'
        }
    }
}
