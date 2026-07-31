Set-StrictMode -Version Latest

function Get-ADRotComputerRule {
    <#
    .SYNOPSIS
        Rules covering computer accounts, delegation and operating system support state.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    @(
        New-ADRotRule -Id 'AD-012' -Severity 'Critical' -Category 'Computers' -Weight 20 `
            -Title 'Unconstrained Kerberos delegation is enabled' `
            -Rationale ('A host trusted for unconstrained delegation caches the TGT of every user ' +
                        'who authenticates to it. Compromise that one host and you can replay a ' +
                        'Domain Administrator TGT — and an attacker can coerce a domain controller ' +
                        'into authenticating to it on demand, so the wait is measured in seconds.') `
            -Remediation ('Replace with constrained delegation or resource-based constrained ' +
                          'delegation. Add genuinely sensitive accounts to Protected Users and mark ' +
                          'them "Account is sensitive and cannot be delegated".') `
            -Reference 'https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview' `
            -Test {
                param($Snapshot, $Config)
                foreach ($o in (@($Snapshot.computers) + @($Snapshot.users))) {
                    if (-not $o.enabled) { continue }
                    if (-not (Test-ADRotUacFlag -Value $o.userAccountControl -Flag 'TRUSTED_FOR_DELEGATION')) { continue }

                    # Domain controllers are trusted for delegation by design; flagging every
                    # DC would bury the finding that actually matters.
                    if (Test-ADRotUacFlag -Value $o.userAccountControl -Flag 'SERVER_TRUST_ACCOUNT') { continue }

                    New-ADRotAffectedObject -Name $o.samAccountName `
                        -Detail 'TRUSTED_FOR_DELEGATION set (unconstrained)' `
                        -DistinguishedName ([string] $o.distinguishedName)
                }
            }

        New-ADRotRule -Id 'AD-013' -Severity 'High' -Category 'Computers' -Weight 12 `
            -Title 'Computers run operating systems that are out of support' `
            -Rationale ('An out-of-support OS receives no security updates, so every vulnerability ' +
                        'found from its end-of-life date onward is permanent. These hosts are also ' +
                        'the last holdouts requiring SMBv1 and NTLM, which weakens the whole domain.') `
            -Remediation ('Upgrade, replace, or isolate on a segmented VLAN with no domain ' +
                          'connectivity. If the box must stay, remove its domain membership.') `
            -Reference 'https://learn.microsoft.com/en-us/lifecycle/products/' `
            -Test {
                param($Snapshot, $Config)
                $legacy = @($Config.legacyOperatingSystems)
                foreach ($c in $Snapshot.computers) {
                    if (-not $c.enabled) { continue }
                    $os = if ($c.ContainsKey('operatingSystem')) { [string] $c.operatingSystem } else { '' }
                    if ([string]::IsNullOrWhiteSpace($os)) { continue }

                    foreach ($pattern in $legacy) {
                        # Prefix match: "Windows Server 2012" must not match "Windows Server 2012 R2"
                        # differently from the base SKU, and both are equally unsupported.
                        if ($os.StartsWith($pattern, [StringComparison]::OrdinalIgnoreCase)) {
                            New-ADRotAffectedObject -Name $c.samAccountName -Detail $os `
                                -DistinguishedName ([string] $c.distinguishedName)
                            break
                        }
                    }
                }
            }

        New-ADRotRule -Id 'AD-014' -Severity 'Medium' -Category 'Computers' -Weight 5 `
            -Title 'Computer accounts are stale' `
            -Rationale ('A computer account whose password has not rotated in months belongs to a ' +
                        'machine that is decommissioned, offline, or off-domain. Stale accounts ' +
                        'inflate the attack surface and can be taken over to obtain a foothold ' +
                        'identity that nobody is monitoring.') `
            -Remediation 'Disable stale computer accounts, verify nothing breaks, then delete them.' `
            -Reference 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/machine-account-password-process' `
            -Test {
                param($Snapshot, $Config)
                $now = Get-ADRotReferenceTime -Snapshot $Snapshot
                $limit = [int] $Config.thresholds.staleDays
                foreach ($c in $Snapshot.computers) {
                    if (-not $c.enabled) { continue }
                    $age = Get-ADRotAgeInDays -Timestamp $c.lastLogonTimestamp -ReferenceTime $now
                    if ($null -ne $age -and $age -gt $limit) {
                        New-ADRotAffectedObject -Name $c.samAccountName `
                            -Detail ("Last logon {0} days ago (threshold {1})" -f $age, $limit) `
                            -DistinguishedName ([string] $c.distinguishedName)
                    }
                }
            }
    )
}
