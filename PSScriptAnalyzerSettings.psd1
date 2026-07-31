@{
    # PSScriptAnalyzer configuration for ADRot.
    # Run locally with:  make lint   (or)  Invoke-ScriptAnalyzer -Path ./src -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # ADRot deliberately uses Write-Host in the console renderer: the report is
        # user-facing terminal output, not pipeline data. Structured data goes to the
        # pipeline via Invoke-ADRotScan's return value and to the log via Write-ADRotLog.
        'PSAvoidUsingWriteHost',

        # The module is dot-sourced from ADRot.psm1; the analyzer cannot see that
        # Public/* functions are consumed by the manifest's FunctionsToExport.
        'PSUseDeclaredVarsMoreThanAssignments'
    )

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('7.0')
        }
        PSPlaceOpenBrace = @{
            Enable             = $true
            OnSameLine         = $true
            NewLineAfter       = $true
            IgnoreOneLineBlock = $true
        }
    }
}
