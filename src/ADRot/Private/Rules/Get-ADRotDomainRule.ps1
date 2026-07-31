Set-StrictMode -Version Latest

function Get-ADRotDomainRule {
    <#
    .SYNOPSIS
        Rules covering domain-wide policy and the krbtgt account.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    @(
        New-ADRotRule -Id 'AD-015' -Severity 'High' -Category 'Domain' -Weight 12 `
            -Title 'The krbtgt password has not been rotated recently' `
            -Rationale ('Every Kerberos ticket in the domain is signed with the krbtgt key. An ' +
                        'attacker who extracts it can forge Golden Tickets for any user, including ' +
                        'accounts that do not exist, and those tickets remain valid until krbtgt ' +
                        'is rotated twice. An old krbtgt password means any historical compromise ' +
                        'is still live today.') `
            -Remediation ('Rotate krbtgt twice, waiting at least one full ticket lifetime (10 hours ' +
                          'by default, and longer than your longest replication delay) between the ' +
                          'two resets. Rotating twice in quick succession invalidates every ticket ' +
                          'in the domain at once — including legitimate ones.') `
            -Reference 'https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-reversible-passwords' `
            -Test {
                param($Snapshot, $Config)
                $now = Get-ADRotReferenceTime -Snapshot $Snapshot
                $limit = [int] $Config.thresholds.krbtgtMaxAgeDays

                $krbtgt = @($Snapshot.users | Where-Object {
                        $_.ContainsKey('samAccountName') -and
                        [string] $_.samAccountName -ieq 'krbtgt'
                    })
                if ($krbtgt.Count -eq 0) { return }

                foreach ($k in $krbtgt) {
                    $age = Get-ADRotAgeInDays -Timestamp $k.pwdLastSet -ReferenceTime $now
                    if ($null -eq $age) {
                        New-ADRotAffectedObject -Name 'krbtgt' `
                            -Detail 'Password last-set date unknown — treat as never rotated' `
                            -DistinguishedName ([string] $k.distinguishedName)
                    }
                    elseif ($age -gt $limit) {
                        New-ADRotAffectedObject -Name 'krbtgt' `
                            -Detail ("Password set {0} days ago (threshold {1})" -f $age, $limit) `
                            -DistinguishedName ([string] $k.distinguishedName)
                    }
                }
            }

        New-ADRotRule -Id 'AD-016' -Severity 'Medium' -Category 'Domain' -Weight 6 `
            -Title 'Any authenticated user can join computers to the domain' `
            -Rationale ('ms-DS-MachineAccountQuota defaults to 10, letting every domain user create ' +
                        'computer accounts. That single default is the enabling condition for ' +
                        'several well-known privilege-escalation chains, because the attacker ' +
                        'controls a machine account password they created themselves.') `
            -Remediation ('Set ms-DS-MachineAccountQuota to 0 and delegate the "Create Computer ' +
                          'Objects" right on the relevant OUs to the specific group that performs ' +
                          'domain joins.') `
            -Reference 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/default-workstation-numbers-join-domain' `
            -Test {
                param($Snapshot, $Config)
                if (-not $Snapshot.domainPolicy.ContainsKey('machineAccountQuota')) { return }
                $quota = $Snapshot.domainPolicy.machineAccountQuota
                if ($null -eq $quota) { return }

                if ([int] $quota -gt 0) {
                    New-ADRotAffectedObject -Name 'ms-DS-MachineAccountQuota' `
                        -Detail ("Set to {0}; every authenticated user may create that many computer accounts" -f $quota) `
                        -DistinguishedName ([string] $Snapshot.domain.distinguishedName)
                }
            }

        New-ADRotRule -Id 'AD-017' -Severity 'Medium' -Category 'Domain' -Weight 6 `
            -Title 'The domain password policy is weaker than recommended' `
            -Rationale ('The default domain policy governs every account that no fine-grained ' +
                        'policy covers. A short minimum length makes offline cracking of any ' +
                        'captured hash trivial, and a disabled lockout threshold makes online ' +
                        'password spraying unlimited.') `
            -Remediation ('Raise the minimum password length to at least 14 characters and set a ' +
                          'lockout threshold with a sensible observation window. Prefer long ' +
                          'passphrases plus banned-password screening over forced complexity.') `
            -Reference 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy' `
            -Test {
                param($Snapshot, $Config)
                $policy = $Snapshot.domainPolicy
                $minRequired = [int] $Config.thresholds.minPasswordLength

                if ($policy.ContainsKey('minPwdLength') -and $null -ne $policy.minPwdLength) {
                    $actual = [int] $policy.minPwdLength
                    if ($actual -lt $minRequired) {
                        New-ADRotAffectedObject -Name 'Minimum password length' `
                            -Detail ("{0} characters (recommended at least {1})" -f $actual, $minRequired) `
                            -DistinguishedName ([string] $Snapshot.domain.distinguishedName)
                    }
                }

                if ($policy.ContainsKey('lockoutThreshold') -and $null -ne $policy.lockoutThreshold) {
                    if ([int] $policy.lockoutThreshold -eq 0) {
                        New-ADRotAffectedObject -Name 'Account lockout threshold' `
                            -Detail 'Disabled (0) — online password spraying is unlimited' `
                            -DistinguishedName ([string] $Snapshot.domain.distinguishedName)
                    }
                }
            }
    )
}
