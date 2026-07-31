Set-StrictMode -Version Latest

# Tier-0 groups, identified by well-known RID suffix rather than by name so that
# non-English domains ("Domänen-Admins", "Администраторы домена") are still matched.
$script:ADRotTier0GroupSids = @{
    '-512'        = 'Domain Admins'
    '-518'        = 'Schema Admins'
    '-519'        = 'Enterprise Admins'
    'S-1-5-32-544' = 'Administrators (built-in)'
}

# The full set of groups AdminSDHolder protects by default. Membership of ANY of these
# legitimately stamps adminCount=1, so AD-011 must consider all of them before calling
# an account orphaned — checking only tier-0 would flag every Backup Operator as a bug.
# Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
$script:ADRotProtectedGroupSids = @{
    '-512'         = 'Domain Admins'
    '-516'         = 'Domain Controllers'
    '-518'         = 'Schema Admins'
    '-519'         = 'Enterprise Admins'
    '-521'         = 'Read-only Domain Controllers'
    '-526'         = 'Key Admins'
    '-527'         = 'Enterprise Key Admins'
    'S-1-5-32-544' = 'Administrators'
    'S-1-5-32-548' = 'Account Operators'
    'S-1-5-32-549' = 'Server Operators'
    'S-1-5-32-550' = 'Print Operators'
    'S-1-5-32-551' = 'Backup Operators'
    'S-1-5-32-552' = 'Replicator'
}

$script:ADRotProtectedGroupNames = @(
    'Domain Admins', 'Domain Controllers', 'Schema Admins', 'Enterprise Admins',
    'Read-only Domain Controllers', 'Key Admins', 'Enterprise Key Admins',
    'Administrators', 'Account Operators', 'Server Operators', 'Print Operators',
    'Backup Operators', 'Replicator'
)

# Accounts that AdminSDHolder protects permanently and unconditionally, regardless of
# group membership. They will always carry adminCount=1 and are never orphans.
# RID 500 = built-in Administrator, RID 502 = krbtgt.
$script:ADRotAlwaysProtectedRids = @('-500', '-502')
$script:ADRotAlwaysProtectedNames = @('krbtgt', 'Administrator')

function Get-ADRotTier0Group {
    <#
    .SYNOPSIS
        Selects the tier-0 privileged groups from a snapshot.
    .DESCRIPTION
        Matches on well-known SID/RID first, falling back to English display names for
        snapshots whose groups carry no SID.
    .PARAMETER Snapshot
        The normalised snapshot.
    .OUTPUTS
        System.Collections.Hashtable[] — the matching group entries, each with a
        .tier0Label key added.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable] $Snapshot
    )

    $matched = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($g in $Snapshot.groups) {
        $sid = if ($g.ContainsKey('sid')) { [string] $g.sid } else { '' }
        $name = if ($g.ContainsKey('samAccountName')) { [string] $g.samAccountName } else { '' }
        $label = $null

        foreach ($key in $script:ADRotTier0GroupSids.Keys) {
            if ($key.StartsWith('S-1-')) {
                if ($sid -eq $key) { $label = $script:ADRotTier0GroupSids[$key]; break }
            }
            elseif ($sid -and $sid.EndsWith($key)) {
                $label = $script:ADRotTier0GroupSids[$key]; break
            }
        }

        if (-not $label -and $name -in @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')) {
            $label = $name
        }

        if ($label) {
            $g.tier0Label = $label
            $matched.Add($g)
        }
    }

    return $matched.ToArray()
}

function Get-ADRotProtectedGroupMemberDn {
    <#
    .SYNOPSIS
        Collects the DNs of every member of every AdminSDHolder-protected group.
    .DESCRIPTION
        Used by AD-011 to decide whether an adminCount=1 stamp is still justified.
        Matches groups on well-known RID first, falling back to English names.
    .PARAMETER Snapshot
        The normalised snapshot.
    .OUTPUTS
        System.Collections.Generic.HashSet[string] — case-insensitive set of member DNs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable] $Snapshot
    )

    $members = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($g in $Snapshot.groups) {
        $sid = if ($g.ContainsKey('sid')) { [string] $g.sid } else { '' }
        $name = if ($g.ContainsKey('samAccountName')) { [string] $g.samAccountName } else { '' }
        $isProtected = $false

        foreach ($key in $script:ADRotProtectedGroupSids.Keys) {
            if ($key.StartsWith('S-1-')) {
                if ($sid -eq $key) { $isProtected = $true; break }
            }
            elseif ($sid -and $sid.EndsWith($key)) {
                $isProtected = $true; break
            }
        }

        if (-not $isProtected -and -not $sid -and $name -in $script:ADRotProtectedGroupNames) {
            $isProtected = $true
        }

        if ($isProtected) {
            foreach ($m in @($g.members)) { [void] $members.Add([string] $m) }
        }
    }

    # The comma is load-bearing. PowerShell enumerates collections on return, which
    # would turn an empty HashSet into $null (and .Contains() into a null-reference
    # throw) and a populated one into a plain object[] whose .Contains() is
    # case-SENSITIVE — silently discarding the OrdinalIgnoreCase comparer above and
    # producing false AD-011 findings for any DN whose casing differs.
    return , $members
}

function Test-ADRotAlwaysProtectedAccount {
    <#
    .SYNOPSIS
        Tests whether an account is permanently protected by AdminSDHolder.
    .DESCRIPTION
        The built-in Administrator (RID 500) and krbtgt (RID 502) always carry
        adminCount=1 whether or not they belong to a protected group. Reporting them as
        orphaned stamps is a false positive on literally every domain in existence.
    .PARAMETER Account
        The account to test.
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][hashtable] $Account
    )

    $sid = if ($Account.ContainsKey('sid')) { [string] $Account.sid } else { '' }
    if ($sid) {
        foreach ($rid in $script:ADRotAlwaysProtectedRids) {
            if ($sid.EndsWith($rid)) { return $true }
        }
    }

    $name = if ($Account.ContainsKey('samAccountName')) { [string] $Account.samAccountName } else { '' }
    foreach ($known in $script:ADRotAlwaysProtectedNames) {
        if ($name -ieq $known) { return $true }
    }

    return $false
}

function Get-ADRotPrivilegedRule {
    <#
    .SYNOPSIS
        Rules covering privileged group membership and admin account hygiene.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()

    @(
        New-ADRotRule -Id 'AD-009' -Severity 'High' -Category 'Privileged' -Weight 12 `
            -Title 'Tier-0 administrative groups are oversized' `
            -Rationale ('Every member of Domain Admins, Enterprise Admins or Schema Admins can ' +
                        'compromise the entire forest. The blast radius of a single phished ' +
                        'workstation scales directly with how many people hold that power, and ' +
                        'membership only ever grows unless someone actively prunes it.') `
            -Remediation ('Reduce tier-0 membership to named break-glass accounts. Move day-to-day ' +
                          'administration to delegated roles or Privileged Access Management with ' +
                          'just-in-time elevation.') `
            -Reference 'https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model' `
            -Test {
                param($Snapshot, $Config)
                $limit = [int] $Config.thresholds.maxPrivilegedMembers
                foreach ($g in (Get-ADRotTier0Group -Snapshot $Snapshot)) {
                    $count = @($g.members).Count
                    if ($count -gt $limit) {
                        New-ADRotAffectedObject -Name $g.tier0Label `
                            -Detail ("{0} members (threshold {1})" -f $count, $limit) `
                            -DistinguishedName ([string] $g.distinguishedName)
                    }
                }
            }

        New-ADRotRule -Id 'AD-010' -Severity 'High' -Category 'Privileged' -Weight 10 `
            -Title 'Tier-0 administrators have stale passwords' `
            -Rationale ('A domain administrator password that has not changed in years is the ' +
                        'single highest-value credential in the estate and the most likely to ' +
                        'appear in an old breach dump, a script, or a departed admin memory.') `
            -Remediation 'Rotate tier-0 credentials now, then enforce a short maximum age for them specifically.' `
            -Reference 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory' `
            -Test {
                param($Snapshot, $Config)
                $now = Get-ADRotReferenceTime -Snapshot $Snapshot
                $limit = [int] $Config.thresholds.maxPasswordAgeDays

                $tier0Members = [System.Collections.Generic.HashSet[string]]::new(
                    [StringComparer]::OrdinalIgnoreCase)
                foreach ($g in (Get-ADRotTier0Group -Snapshot $Snapshot)) {
                    foreach ($m in @($g.members)) { [void] $tier0Members.Add([string] $m) }
                }

                foreach ($u in $Snapshot.users) {
                    if (-not $u.enabled) { continue }
                    if (-not $tier0Members.Contains([string] $u.distinguishedName)) { continue }

                    $age = Get-ADRotAgeInDays -Timestamp $u.pwdLastSet -ReferenceTime $now
                    if ($null -ne $age -and $age -gt $limit) {
                        New-ADRotAffectedObject -Name $u.samAccountName `
                            -Detail ("Tier-0 account, password set {0} days ago (threshold {1})" -f $age, $limit) `
                            -DistinguishedName ([string] $u.distinguishedName)
                    }
                }
            }

        New-ADRotRule -Id 'AD-011' -Severity 'Medium' -Category 'Privileged' -Weight 5 `
            -Title 'Orphaned adminCount=1 accounts retain hardened ACLs' `
            -Rationale ('AdminSDHolder stamps adminCount=1 and a restrictive ACL on privileged ' +
                        'accounts, but removing the account from the group does not undo it. The ' +
                        'account keeps inheritance disabled forever, quietly escaping the ' +
                        'delegation model everyone assumes is in force.') `
            -Remediation ('For each account no longer privileged: clear adminCount and re-enable ' +
                          'ACL inheritance on the object.') `
            -Reference 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory' `
            -Test {
                param($Snapshot, $Config)
                $protectedMembers = Get-ADRotProtectedGroupMemberDn -Snapshot $Snapshot

                foreach ($u in $Snapshot.users) {
                    if ([int] $u.adminCount -ne 1) { continue }

                    # krbtgt and the built-in Administrator are protected unconditionally.
                    if (Test-ADRotAlwaysProtectedAccount -Account $u) { continue }

                    # Membership of ANY protected group justifies the stamp, not just tier-0.
                    if ($protectedMembers.Contains([string] $u.distinguishedName)) { continue }

                    New-ADRotAffectedObject -Name $u.samAccountName `
                        -Detail 'adminCount=1 but not a member of any AdminSDHolder-protected group' `
                        -DistinguishedName ([string] $u.distinguishedName)
                }
            }
    )
}
