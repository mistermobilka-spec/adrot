#Requires -Modules Pester

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..' '..' 'src' 'ADRot' 'ADRot.psd1'
    Import-Module $script:ModulePath -Force
}

AfterAll {
    Remove-Module ADRot -Force -ErrorAction SilentlyContinue
}

Describe 'ConvertFrom-ADRotUac' {
    It 'decodes a plain enabled account' {
        InModuleScope ADRot {
            ConvertFrom-ADRotUac -Value 512 | Should -Be @('NORMAL_ACCOUNT')
        }
    }

    It 'decodes combined flags' {
        InModuleScope ADRot {
            $flags = ConvertFrom-ADRotUac -Value 66048
            $flags | Should -Contain 'NORMAL_ACCOUNT'
            $flags | Should -Contain 'DONT_EXPIRE_PASSWORD'
            $flags.Count | Should -Be 2
        }
    }

    It 'returns nothing for null' {
        # PowerShell unwraps an empty array on return, so callers wrap in @() — as
        # Initialize-ADRotAccount does. The contract is "no flags", not "an array".
        InModuleScope ADRot {
            @(ConvertFrom-ADRotUac -Value $null).Count | Should -Be 0
        }
    }

    It 'decodes a domain controller account (server trust + delegation)' {
        InModuleScope ADRot {
            $flags = ConvertFrom-ADRotUac -Value 532480
            $flags | Should -Contain 'SERVER_TRUST_ACCOUNT'
            $flags | Should -Contain 'TRUSTED_FOR_DELEGATION'
        }
    }
}

Describe 'Test-ADRotUacFlag' {
    It 'detects <Flag> in <Value>' -ForEach @(
        @{ Value = 544;     Flag = 'PASSWD_NOTREQD';             Expected = $true }
        @{ Value = 512;     Flag = 'PASSWD_NOTREQD';             Expected = $false }
        @{ Value = 4194816; Flag = 'DONT_REQ_PREAUTH';           Expected = $true }
        @{ Value = 640;     Flag = 'ENCRYPTED_TEXT_PWD_ALLOWED'; Expected = $true }
        @{ Value = 514;     Flag = 'ACCOUNTDISABLE';             Expected = $true }
        @{ Value = 528384;  Flag = 'TRUSTED_FOR_DELEGATION';     Expected = $true }
    ) {
        InModuleScope ADRot -Parameters @{ v = $Value; f = $Flag; e = $Expected } {
            Test-ADRotUacFlag -Value $v -Flag $f | Should -Be $e
        }
    }

    It 'returns false for a null value rather than throwing' {
        InModuleScope ADRot {
            Test-ADRotUacFlag -Value $null -Flag 'PASSWD_NOTREQD' | Should -BeFalse
        }
    }

    It 'throws on an unknown flag name so typos are caught at development time' {
        InModuleScope ADRot {
            { Test-ADRotUacFlag -Value 512 -Flag 'NOT_A_REAL_FLAG' } | Should -Throw '*Unknown userAccountControl flag*'
        }
    }
}

Describe 'ConvertFrom-ADRotFileTime' {
    It 'converts a real FILETIME' {
        InModuleScope ADRot {
            $result = ConvertFrom-ADRotFileTime -Value 133000000000000000
            $result | Should -Not -BeNullOrEmpty
            $result.UtcDateTime.Year | Should -Be 2022
        }
    }

    It 'treats <Name> as never and returns null' -ForEach @(
        @{ Name = 'zero';           Value = 0 }
        @{ Name = 'negative';       Value = -1 }
        @{ Name = 'Int64.MaxValue'; Value = [int64]::MaxValue }
        @{ Name = 'null';           Value = $null }
        @{ Name = 'empty string';   Value = '' }
    ) {
        InModuleScope ADRot -Parameters @{ v = $Value } {
            ConvertFrom-ADRotFileTime -Value $v | Should -BeNullOrEmpty
        }
    }

    It 'accepts a numeric string as LDAP returns it' {
        InModuleScope ADRot {
            ConvertFrom-ADRotFileTime -Value '133000000000000000' | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'ConvertFrom-ADRotGeneralizedTime' {
    It 'parses <Value>' -ForEach @(
        @{ Value = '20240115100000.0Z' }
        @{ Value = '20240115100000.000Z' }
        @{ Value = '20240115100000Z' }
    ) {
        InModuleScope ADRot -Parameters @{ v = $Value } {
            $result = ConvertFrom-ADRotGeneralizedTime -Value $v
            $result | Should -Not -BeNullOrEmpty
            $result.UtcDateTime.Year  | Should -Be 2024
            $result.UtcDateTime.Month | Should -Be 1
            $result.UtcDateTime.Day   | Should -Be 15
            $result.UtcDateTime.Hour  | Should -Be 10
        }
    }

    It 'returns null for unparseable input' {
        InModuleScope ADRot {
            ConvertFrom-ADRotGeneralizedTime -Value 'garbage' -WarningAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }

    It 'returns null for empty input' {
        InModuleScope ADRot {
            ConvertFrom-ADRotGeneralizedTime -Value '' | Should -BeNullOrEmpty
        }
    }
}

Describe 'ConvertFrom-ADRotLdapSid' {
    It 'decodes a binary SID to string form' {
        InModuleScope ADRot {
            $bytes = [byte[]] @(1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0, 1, 2, 3, 0, 2, 3, 4, 0, 3, 4, 5, 0, 2, 0, 0)
            $sid = ConvertFrom-ADRotLdapSid -Bytes $bytes
            $sid | Should -BeLike 'S-1-5-21-*'
            $sid | Should -BeLike '*-512'
        }
    }

    It 'returns empty string for malformed input rather than throwing' {
        InModuleScope ADRot {
            ConvertFrom-ADRotLdapSid -Bytes ([byte[]] @(1, 2, 3)) | Should -Be ''
            ConvertFrom-ADRotLdapSid -Bytes $null | Should -Be ''
        }
    }
}

Describe 'ConvertFrom-ADRotPwdAgeInterval' {
    It 'converts a 42-day interval' {
        InModuleScope ADRot {
            ConvertFrom-ADRotPwdAgeInterval -Value -36288000000000 | Should -Be 42
        }
    }

    It 'treats the never-expires sentinel as 0' {
        InModuleScope ADRot {
            ConvertFrom-ADRotPwdAgeInterval -Value ([int64]::MinValue) | Should -Be 0
            ConvertFrom-ADRotPwdAgeInterval -Value 0 | Should -Be 0
        }
    }

    It 'returns null for unparseable input' {
        InModuleScope ADRot {
            ConvertFrom-ADRotPwdAgeInterval -Value 'nope' | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-ADRotReferenceTime' {
    It 'uses the snapshot capturedAt so results are reproducible' {
        InModuleScope ADRot {
            $snapshot = @{ capturedAt = '2026-07-01T00:00:00Z' }
            (Get-ADRotReferenceTime -Snapshot $snapshot).UtcDateTime |
                Should -Be ([datetime]::new(2026, 7, 1, 0, 0, 0, [DateTimeKind]::Utc))
        }
    }

    It 'falls back to now when capturedAt is absent' {
        InModuleScope ADRot {
            $before = [DateTimeOffset]::UtcNow.AddSeconds(-5)
            Get-ADRotReferenceTime -Snapshot @{} | Should -BeGreaterThan $before
        }
    }
}

Describe 'Get-ADRotAgeInDays' {
    It 'computes whole days between two points' {
        InModuleScope ADRot {
            $ref = [DateTimeOffset]::Parse('2026-07-01T00:00:00Z')
            Get-ADRotAgeInDays -Timestamp ([DateTimeOffset]::Parse('2026-06-01T00:00:00Z')) -ReferenceTime $ref |
                Should -Be 30
        }
    }

    It 'returns null for a null timestamp, meaning never happened' {
        InModuleScope ADRot {
            Get-ADRotAgeInDays -Timestamp $null -ReferenceTime ([DateTimeOffset]::UtcNow) | Should -BeNullOrEmpty
        }
    }
}
