@{
    RootModule        = 'ADRot.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b1f3c6d2-4a77-4f0e-9c31-2d5e8a7b6c04'
    Author            = 'ADRot contributors'
    CompanyName       = 'Unaffiliated'
    Copyright         = '(c) 2026 ADRot contributors. MIT licensed.'
    Description       = 'Read-only Active Directory hygiene and security scanner. Pure PowerShell, no RSAT, no agent, no writes.'

    PowerShellVersion = '7.0'

    # No third-party dependencies. System.DirectoryServices.Protocols ships with .NET.
    RequiredModules   = @()

    FunctionsToExport = @(
        'Invoke-ADRotScan',
        'Export-ADRotSnapshot',
        'Get-ADRotRule'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData       = @{
        PSData = @{
            Tags         = @(
                'ActiveDirectory', 'Security', 'Audit', 'Hygiene', 'LDAP',
                'Windows', 'SysAdmin', 'BlueTeam', 'Compliance'
            )
            LicenseUri   = 'https://github.com/MisterMobilka/adrot/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/MisterMobilka/adrot'
            ReleaseNotes = 'Initial release: 15 hygiene rules, LDAP and offline-snapshot sources, HTML/JSON/console output.'
        }
    }
}
