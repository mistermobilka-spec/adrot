Set-StrictMode -Version Latest

function Get-ADRotAccountRule {
    <#
    .SYNOPSIS
        Rules covering user account hygiene and Kerberos exposure.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    @(
        New-ADRotRule -Id 'AD-001' -Severity 'Critical' -Category 'Accounts' -Weight 20 `
            -Title 'Accounts store passwords with reversible encryption' `
            -Rationale ('ENCRYPTED_TEXT_PWD_ALLOWED makes Active Directory keep a recoverable ' +
                        'copy of the plaintext password. Anyone who can read the NTDS.dit or ' +
                        'perform a DCSync recovers the actual password, not a hash — so the ' +
                        'credential is immediately reusable against every other system where ' +
                        'the user reused it.') `
            -Remediation ('Clear the "Store password using reversible encryption" checkbox on the ' +
                          'account and on any GPO that sets it, then force a password reset — the ' +
                          'reversible copy persists until the password next changes.') `
            -Reference 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption' `
            -Test {
                param($Snapshot, $Config)
                foreach ($u in $Snapshot.users) {
                    if (-not $u.enabled) { continue }
                    if (Test-ADRotUacFlag -Value $u.userAccountControl -Flag 'ENCRYPTED_TEXT_PWD_ALLOWED') {
                        New-ADRotAffectedObject -Name $u.samAccountName `
                            -Detail 'Reversible encryption enabled' `
                            -DistinguishedName ([string] $u.distinguishedName)
                    }
                }
            }

        New-ADRotRule -Id 'AD-002' -Severity 'High' -Category 'Accounts' -Weight 12 `
            -Title 'Accounts are exempt from the password requirement' `
            -Rationale ('PASSWD_NOTREQD lets the account keep an empty password regardless of the ' +
                        'domain password policy. Password-spray tooling tries the empty password ' +
                        'first, and these accounts answer.') `
            -Remediation 'Clear the PASSWD_NOTREQD flag and set a compliant password on each account.' `
            -Reference 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties' `
            -Test {
                param($Snapshot, $Config)
                foreach ($u in $Snapshot.users) {
                    if (-not $u.enabled) { continue }
                    if (Test-ADRotUacFlag -Value $u.userAccountControl -Flag 'PASSWD_NOTREQD') {
                        New-ADRotAffectedObject -Name $u.samAccountName `
                            -Detail 'PASSWD_NOTREQD set' `
                            -DistinguishedName ([string] $u.distinguishedName)
                    }
                }
            }

        New-ADRotRule -Id 'AD-003' -Severity 'High' -Category 'Accounts' -Weight 12 `
            -Title 'Accounts do not require Kerberos pre-authentication (AS-REP roastable)' `
            -Rationale ('With DONT_REQ_PREAUTH set, any unauthenticated host on the network can ' +
                        'request an AS-REP for the account and crack it offline at full speed. ' +
                        'No prior foothold and no credentials are needed to start.') `
            -Remediation ('Clear "Do not require Kerberos preauthentication" on each account. If a ' +
                          'legacy application genuinely needs it, give that account a long random ' +
                          'password and monitor it.') `
            -Reference 'https://attack.mitre.org/techniques/T1558/004/' `
            -Test {
                param($Snapshot, $Config)
                foreach ($u in $Snapshot.users) {
                    if (-not $u.enabled) { continue }
                    if (Test-ADRotUacFlag -Value $u.userAccountControl -Flag 'DONT_REQ_PREAUTH') {
                        New-ADRotAffectedObject -Name $u.samAccountName `
                            -Detail 'DONT_REQ_PREAUTH set' `
                            -DistinguishedName ([string] $u.distinguishedName)
                    }
                }
            }

        New-ADRotRule -Id 'AD-004' -Severity 'High' -Category 'Accounts' -Weight 10 `
            -Title 'User accounts carry a servicePrincipalName (Kerberoastable)' `
            -Rationale ('Any authenticated domain user can request a service ticket for an account ' +
                        'with an SPN and crack it offline. Unlike computer accounts, user accounts ' +
                        'rarely have a 120-character random password, so these crack in practice.') `
            -Remediation ('Migrate the service to a Group Managed Service Account (gMSA), which ' +
                          'rotates a 240-byte random password automatically. Where that is not ' +
                          'possible, set a 25+ character random password.') `
            -Reference 'https://attack.mitre.org/techniques/T1558/003/' `
            -Test {
                param($Snapshot, $Config)
                foreach ($u in $Snapshot.users) {
                    if (-not $u.enabled) { continue }
                    if (@($u.servicePrincipalName).Count -gt 0) {
                        New-ADRotAffectedObject -Name $u.samAccountName `
                            -Detail ("SPN: {0}" -f (@($u.servicePrincipalName) -join ', ')) `
                            -DistinguishedName ([string] $u.distinguishedName)
                    }
                }
            }

        New-ADRotRule -Id 'AD-005' -Severity 'Medium' -Category 'Accounts' -Weight 6 `
            -Title 'Accounts have non-expiring passwords' `
            -Rationale ('DONT_EXPIRE_PASSWORD exempts the account from rotation forever. Combined ' +
                        'with an SPN or privileged group membership it turns one leaked credential ' +
                        'into indefinite access.') `
            -Remediation ('Clear "Password never expires". For service accounts that cannot rotate ' +
                          'on a schedule, move them to gMSAs instead of exempting them.') `
            -Reference 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties' `
            -Test {
                param($Snapshot, $Config)
                foreach ($u in $Snapshot.users) {
                    if (-not $u.enabled) { continue }
                    if (Test-ADRotUacFlag -Value $u.userAccountControl -Flag 'DONT_EXPIRE_PASSWORD') {
                        New-ADRotAffectedObject -Name $u.samAccountName `
                            -Detail 'DONT_EXPIRE_PASSWORD set' `
                            -DistinguishedName ([string] $u.distinguishedName)
                    }
                }
            }

        New-ADRotRule -Id 'AD-006' -Severity 'Medium' -Category 'Accounts' -Weight 6 `
            -Title 'Enabled user accounts are dormant' `
            -Rationale ('An enabled account nobody uses is an account nobody watches. Dormant ' +
                        'accounts are the preferred landing spot for persistence because their ' +
                        'logons generate no complaints from a real user.') `
            -Remediation ('Disable, then delete after a retention window. Automate it: dormant ' +
                          'accounts reappear continuously unless offboarding is wired to HR.') `
            -Reference 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory' `
            -Test {
                param($Snapshot, $Config)
                $now = Get-ADRotReferenceTime -Snapshot $Snapshot
                $limit = [int] $Config.thresholds.staleDays
                foreach ($u in $Snapshot.users) {
                    if (-not $u.enabled) { continue }
                    if ($null -eq $u.lastLogonTimestamp) { continue }   # never logged on -> AD-007
                    $age = Get-ADRotAgeInDays -Timestamp $u.lastLogonTimestamp -ReferenceTime $now
                    if ($null -ne $age -and $age -gt $limit) {
                        New-ADRotAffectedObject -Name $u.samAccountName `
                            -Detail ("Last logon {0} days ago (threshold {1})" -f $age, $limit) `
                            -DistinguishedName ([string] $u.distinguishedName)
                    }
                }
            }

        New-ADRotRule -Id 'AD-007' -Severity 'Medium' -Category 'Accounts' -Weight 5 `
            -Title 'Enabled user accounts have never logged on' `
            -Rationale ('Accounts created and never used are usually leftovers from provisioning ' +
                        'or testing. They frequently keep the default password chosen at creation.') `
            -Remediation 'Confirm each is genuinely needed; disable and delete the rest.' `
            -Reference 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory' `
            -Test {
                param($Snapshot, $Config)
                $now = Get-ADRotReferenceTime -Snapshot $Snapshot
                $grace = [int] $Config.thresholds.staleDays
                foreach ($u in $Snapshot.users) {
                    if (-not $u.enabled) { continue }
                    if ($null -ne $u.lastLogonTimestamp) { continue }

                    # Ignore freshly created accounts: a new joiner who has not logged on
                    # yet is normal, not rot.
                    $createdAge = Get-ADRotAgeInDays -Timestamp $u.whenCreated -ReferenceTime $now
                    if ($null -ne $createdAge -and $createdAge -le $grace) { continue }

                    $detail = if ($null -eq $createdAge) { 'Never logged on' }
                              else { "Never logged on; created $createdAge days ago" }
                    New-ADRotAffectedObject -Name $u.samAccountName -Detail $detail `
                        -DistinguishedName ([string] $u.distinguishedName)
                }
            }

        New-ADRotRule -Id 'AD-008' -Severity 'Low' -Category 'Accounts' -Weight 3 `
            -Title 'Passwords have not been changed for an extended period' `
            -Rationale ('A password older than the rotation window has had maximum exposure to ' +
                        'every breach, reuse and shoulder-surf since it was set.') `
            -Remediation 'Force a reset on these accounts and verify the domain maximum password age is enforced.' `
            -Reference 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age' `
            -Test {
                param($Snapshot, $Config)
                $now = Get-ADRotReferenceTime -Snapshot $Snapshot
                $limit = [int] $Config.thresholds.maxPasswordAgeDays
                foreach ($u in $Snapshot.users) {
                    if (-not $u.enabled) { continue }
                    $age = Get-ADRotAgeInDays -Timestamp $u.pwdLastSet -ReferenceTime $now
                    if ($null -ne $age -and $age -gt $limit) {
                        New-ADRotAffectedObject -Name $u.samAccountName `
                            -Detail ("Password set {0} days ago (threshold {1})" -f $age, $limit) `
                            -DistinguishedName ([string] $u.distinguishedName)
                    }
                }
            }
    )
}
