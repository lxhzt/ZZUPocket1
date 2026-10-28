#requires -Version 7.0
<# In-memory fixtures only. Never invokes ADB, Gradle, an emulator, a network client or the runner body. #>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    throw 'Read-only parser fixtures require FullLanguage PowerShell; no device commands were run.'
}
$Root = Split-Path -Parent $PSScriptRoot
$RunnerPath = Join-Path $Root 'tools/run-offline-android-security.ps1'
$Tokens = $null
$Errors = $null
$Ast = [Management.Automation.Language.Parser]::ParseFile($RunnerPath, [ref]$Tokens, [ref]$Errors)
if (@($Errors).Count -ne 0) { throw 'Offline runner has PowerShell syntax errors.' }
foreach ($Name in @('Get-RequiredLabChecks', 'Assert-LabReport')) {
    $Definitions = @($Ast.FindAll({ param($Node)
        $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -ceq $Name
    }, $true))
    if ($Definitions.Count -ne 1) { throw 'A report guard function is missing or duplicated.' }
    # Define exactly these pure validation functions, never the executable runner body.
    . ([scriptblock]::Create($Definitions[0].Extent.Text))
}
$LabPackage = 'com.zzupocket.app.secure.securitylab'
$TestPackage = 'com.zzupocket.app.secure.securitylab.test'
$Cases = [Collections.Generic.List[object]]::new()

function New-ValidReport {
    param([string]$Phase)
    return [pscustomobject]@{
        format_version = 1; phase = $Phase; target_package = $LabPackage; test_package = $TestPackage
        passed = $true; sdk_int = 31; hardware = 'ranchu'; pid = 1234
        checks = @((Get-RequiredLabChecks -Phase $Phase) | ForEach-Object {
            [pscustomobject]@{ name = $_; passed = $true; detail = 'Synthetic fixture' }
        })
    }
}

function Clone-Report {
    param([object]$Report)
    return ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Report -Depth 20 -Compress)
}

function Add-Case {
    param([string]$Name, [object]$Report, [string]$Phase, [bool]$Expected)
    $Accepted = $true
    try { Assert-LabReport -Report $Report -Phase $Phase } catch { $Accepted = $false }
    [void]$Cases.Add([ordered]@{ name = $Name; expected_acceptance = $Expected; accepted = $Accepted; passed = $Accepted -eq $Expected })
}

foreach ($Phase in @('setup', 'verify')) {
    $Valid = New-ValidReport $Phase
    Add-Case "$Phase-complete-report" $Valid $Phase $true
    foreach ($Name in @(Get-RequiredLabChecks $Phase)) {
        $Report = Clone-Report $Valid
        $Report.checks = @($Report.checks | Where-Object { $_.name -cne $Name })
        Add-Case "$Phase-missing-$Name" $Report $Phase $false
    }
    $Report = Clone-Report $Valid
    $Report.checks = @($Report.checks | Where-Object { $_.name -cin @('lab_target_package', 'target_internet_permission_denied', 'test_internet_permission_denied', 'emulator_hardware') })
    Add-Case "$Phase-safety-gates-only" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.checks[1].name = $Report.checks[0].name
    Add-Case "$Phase-duplicate-name-same-count" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.checks[0].name = 'unknown-check'
    Add-Case "$Phase-unknown-name-same-count" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.checks[0].passed = $false
    Add-Case "$Phase-failed-check" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.checks[0].passed = 'true'
    Add-Case "$Phase-string-check-result" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.passed = 'true'
    Add-Case "$Phase-string-overall-result" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.passed = $false
    Add-Case "$Phase-failed-overall-result" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.checks = @()
    Add-Case "$Phase-empty-checks" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.checks += [pscustomobject]@{name = 'unexpected-extra'; passed = $true}
    Add-Case "$Phase-unreviewed-extra-check" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.phase = if ($Phase -eq 'setup') { 'verify' } else { 'setup' }
    Add-Case "$Phase-wrong-phase" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.target_package = 'com.zzupocket.app.secure'
    Add-Case "$Phase-production-target" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.test_package = 'unrelated.test'
    Add-Case "$Phase-wrong-test-package" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.format_version = 2
    Add-Case "$Phase-unknown-format" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.sdk_int = 30
    Add-Case "$Phase-wrong-sdk" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.hardware = 'physical-device'
    Add-Case "$Phase-wrong-hardware" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.pid = 0
    Add-Case "$Phase-invalid-pid" $Report $Phase $false
    $Report = Clone-Report $Valid; $Report.pid = '1234'
    Add-Case "$Phase-string-pid" $Report $Phase $false
}
$Passed = @($Cases | Where-Object { -not $_.passed }).Count -eq 0
[ordered]@{
    format_version = 1; passed = $Passed; tests = $Cases.Count; parser_errors = @($Errors).Count
    required_setup_checks = @(Get-RequiredLabChecks 'setup').Count
    required_verify_checks = @(Get-RequiredLabChecks 'verify').Count
    network_requests = 0; device_commands = 0; cases = $Cases
} | ConvertTo-Json -Depth 10 -Compress
if (-not $Passed) { exit 1 }
