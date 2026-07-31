Set-StrictMode -Version Latest

function Get-ADRotRule {
    <#
    .SYNOPSIS
        Returns ADRot's rule catalogue.
    .DESCRIPTION
        Exposed publicly so that operators can review exactly what ADRot checks before
        running it against production, document the catalogue, or select a subset.

        Rules are pure functions of (snapshot, config): none of them writes to Active
        Directory, and none performs a network call of its own.
    .PARAMETER Id
        Return only the rules with these IDs, e.g. 'AD-001'.
    .PARAMETER Category
        Return only rules in these categories.
    .PARAMETER Severity
        Return only rules at these severities.
    .OUTPUTS
        System.Management.Automation.PSCustomObject[]
    .EXAMPLE
        Get-ADRotRule | Format-Table Id, Severity, Category, Title
    .EXAMPLE
        Get-ADRotRule -Severity Critical
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [string[]] $Id,

        [ValidateSet('Accounts', 'Privileged', 'Computers', 'Domain')]
        [string[]] $Category,

        [ValidateSet('Critical', 'High', 'Medium', 'Low')]
        [string[]] $Severity
    )

    $rules = @(
        Get-ADRotAccountRule
        Get-ADRotPrivilegedRule
        Get-ADRotComputerRule
        Get-ADRotDomainRule
    )

    if ($Id) { $rules = @($rules | Where-Object { $_.Id -in $Id }) }
    if ($Category) { $rules = @($rules | Where-Object { $_.Category -in $Category }) }
    if ($Severity) { $rules = @($rules | Where-Object { $_.Severity -in $Severity }) }

    return @($rules | Sort-Object Id)
}
