#requires -Version 7.0
<#
Run only the already-booted, dedicated offline lab AVD. This script never downloads,
builds, starts an emulator, changes permissions or contacts school services.
Both installed APKs must omit INTERNET. This does not claim that the emulator OS
or its boot process has no network access. Evidence contains synthetic lab data.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^emulator-[0-9]{4,5}$')]
    [string]$EmulatorSerial = 'emulator-5560',
    [ValidateSet('ZZUPocketOfflineLab31')]
    [string]$AvdName = 'ZZUPocketOfflineLab31',
    [ValidateRange(1024, 65535)]
    [int]$AdbServerPort = 5038,
    [ValidatePattern('^[A-Za-z0-9_-]{1,64}$')]
    [string]$RunId = ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)),
    [ValidateRange(30, 900)]
    [int]$PhaseTimeoutSeconds = 300,
    [string]$AdbPath,
    [string]$AaptPath,
    [string]$LabApk,
    [string]$TestApk
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    throw 'This native-process runner requires a FullLanguage PowerShell session; no device operations were performed.'
}
$Workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$LabPackage = 'com.zzupocket.app.secure.securitylab'
$TestPackage = 'com.zzupocket.app.secure.securitylab.test'
$Runner = 'com.zzupocket.app.securitylab.OfflineSecurityInstrumentation'
$EvidenceRoot = Join-Path $Workspace '.security-tools/android-lab-20261028'
$RunDirectory = Join-Path $EvidenceRoot ('run-' + $RunId)
$Utf8 = [Text.UTF8Encoding]::new($false)
$CommandNumber = 0
$IdentityConfirmed = $false
$LabInstalled = $false
$RunDirectoryCreated = $false
$ApkLocks = [Collections.Generic.List[IO.FileStream]]::new()
$Summary = [ordered]@{
    format_version = 1
    run_id = $RunId
    started_utc = [DateTime]::UtcNow.ToString('o')
    emulator_serial = $EmulatorSerial
    expected_avd = $AvdName
    adb_host = '127.0.0.1'
    adb_server_port = $AdbServerPort
    target_package = $LabPackage
    test_package = $TestPackage
    passed = $false
    school_requests = 0
    binary_downloads = 0
    emulator_started_or_stopped = $false
    limits = @('App and test APKs omit INTERNET; emulator-wide networking is not isolated.',
        'Synthetic emulator tests do not establish school authorization or physical-device security.')
    commands = [Collections.Generic.List[object]]::new()
    phases = [ordered]@{}
}

function Write-EvidenceText {
    param([string]$Name, [AllowEmptyString()][string]$Content)
    [IO.File]::WriteAllText((Join-Path $RunDirectory $Name), $Content, $Utf8)
}

function Write-EvidenceJson {
    param([string]$Name, [object]$Value)
    Write-EvidenceText $Name (ConvertTo-Json -InputObject $Value -Depth 100)
}

function Resolve-InputFile {
    param([string]$Provided, [string]$DefaultRelative)
    $Candidate = if ([string]::IsNullOrWhiteSpace($Provided)) { Join-Path $Workspace $DefaultRelative } else { $Provided }
    $Resolved = (Resolve-Path -LiteralPath $Candidate).ProviderPath
    if (-not [IO.File]::Exists($Resolved)) { throw 'A required local tool or APK file is missing.' }
    return $Resolved
}

function Invoke-BoundedNative {
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [ValidatePattern('^[a-z0-9-]+$')][string]$Label,
        [int]$TimeoutSeconds = 30
    )
    $script:CommandNumber++
    $Prefix = '{0:D3}-{1}' -f $script:CommandNumber, $Label
    $Info = [Diagnostics.ProcessStartInfo]::new()
    $Info.FileName = $Executable
    $Info.WorkingDirectory = $Workspace
    $Info.UseShellExecute = $false
    $Info.CreateNoWindow = $true
    $Info.RedirectStandardOutput = $true
    $Info.RedirectStandardError = $true
    $Info.StandardOutputEncoding = $Utf8
    $Info.StandardErrorEncoding = $Utf8
    foreach ($Argument in $Arguments) { [void]$Info.ArgumentList.Add($Argument) }
    $Process = [Diagnostics.Process]::new()
    $Process.StartInfo = $Info
    $Entry = [ordered]@{ label = $Label; started_utc = [DateTime]::UtcNow.ToString('o');
        timeout_seconds = $TimeoutSeconds; stdout_file = "$Prefix.stdout.txt"; stderr_file = "$Prefix.stderr.txt" }
    [void]$Summary.commands.Add($Entry)
    try {
        if (-not $Process.Start()) { throw 'Native process did not start.' }
        $StdoutTask = $Process.StandardOutput.ReadToEndAsync()
        $StderrTask = $Process.StandardError.ReadToEndAsync()
        $TimedOut = -not $Process.WaitForExit($TimeoutSeconds * 1000)
        if ($TimedOut) {
            # Kill this local command client only, never an ADB server or emulator.
            $Process.Kill()
            if (-not $Process.WaitForExit(5000)) { throw "Command client did not exit after timeout: $Label." }
        }
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($StdoutTask, $StderrTask), 5000)) {
            $Entry.timed_out = $true
            Write-EvidenceText $Entry.stderr_file 'Command output pipes did not close within the bounded drain time.'
            throw "Command output drain timed out: $Label."
        }
        $Stdout = $StdoutTask.GetAwaiter().GetResult()
        $Stderr = $StderrTask.GetAwaiter().GetResult()
        Write-EvidenceText $Entry.stdout_file $Stdout
        Write-EvidenceText $Entry.stderr_file $Stderr
        $Entry.timed_out = $TimedOut
        $Entry.exit_code = $Process.ExitCode
        if ($TimedOut) { throw "Command timed out: $Label. See retained evidence." }
        if ($Stdout.Length -gt 8MB -or $Stderr.Length -gt 8MB) { throw "Command output exceeded the evidence limit: $Label." }
        if ($Process.ExitCode -ne 0) { throw "Command failed: $Label. See retained evidence." }
        return [pscustomobject]@{ Out = $Stdout; Error = $Stderr; ExitCode = $Process.ExitCode }
    } finally {
        $Entry.finished_utc = [DateTime]::UtcNow.ToString('o')
        $Process.Dispose()
    }
}

function Invoke-LabAdb {
    param([string[]]$Command, [string]$Label, [int]$TimeoutSeconds = 30)
    $AdbArguments = @('-H', '127.0.0.1', '-P', [string]$AdbServerPort, '-s', $EmulatorSerial) + $Command
    return Invoke-BoundedNative -Executable $AdbPath -Arguments $AdbArguments -Label $Label -TimeoutSeconds $TimeoutSeconds
}

function Confirm-LabAvd {
    param([string]$Label = 'confirm-avd')
    $Result = Invoke-LabAdb -Command @('emu', 'avd', 'name') -Label $Label
    $Lines = @($Result.Out -split '\r?\n' | Where-Object { $_.Trim() -ne '' -and $_.Trim() -ne 'OK' })
    if ($Lines.Count -ne 1 -or $Lines[0].Trim() -cne $AvdName) { throw 'The selected emulator is not the dedicated lab AVD.' }
}

function Confirm-OfflineApk {
    param([string]$Path, [string]$ExpectedPackage, [string]$Label, [bool]$IsTest)
    $Badging = Invoke-BoundedNative -Executable $AaptPath -Arguments @('dump', 'badging', $Path) -Label "$Label-badging"
    $PackageMatches = [regex]::Matches($Badging.Out, "(?m)^package: name='([^']+)'")
    if ($PackageMatches.Count -ne 1 -or $PackageMatches[0].Groups[1].Value -cne $ExpectedPackage) {
        throw "Unexpected APK package: $Label."
    }
    $Permissions = Invoke-BoundedNative -Executable $AaptPath -Arguments @('dump', 'permissions', $Path) -Label "$Label-permissions"
    $Manifest = Invoke-BoundedNative -Executable $AaptPath -Arguments @('dump', 'xmltree', $Path, 'AndroidManifest.xml') -Label "$Label-manifest"
    if ($Permissions.Out.Contains('android.permission.INTERNET') -or $Manifest.Out.Contains('android.permission.INTERNET')) {
        throw "INTERNET remains in the $Label APK; installation refused."
    }
    if ($Manifest.Out.Contains('android:sharedUserId')) { throw "Shared UID is not permitted for the $Label APK." }
    $Instrumentations = [regex]::Matches($Manifest.Out, '(?s)E: instrumentation\b(?<body>.*?)(?=\r?\n\s*E:|\z)')
    if ($IsTest) {
        if ($Instrumentations.Count -ne 1) { throw 'The test APK must contain exactly one instrumentation.' }
        $Block = $Instrumentations[0].Groups['body'].Value
        $Target = [regex]::Match($Block, 'A:\s+android:targetPackage[^\r\n]*="([^"\r\n]+)"')
        $Name = [regex]::Match($Block, 'A:\s+android:name[^\r\n]*="([^"\r\n]+)"')
        if (-not $Target.Success -or $Target.Groups[1].Value -cne $LabPackage -or
            -not $Name.Success -or $Name.Groups[1].Value -cne $Runner) {
            throw 'The instrumentation target or runner is not the dedicated lab.'
        }
    } elseif ($Instrumentations.Count -ne 0) { throw 'The lab application APK unexpectedly declares instrumentation.' }
    return [ordered]@{ path = $Path; package = $ExpectedPackage; bytes = (Get-Item -LiteralPath $Path).Length;
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant(); internet_declared = $false }
}

function Get-RequiredLabChecks {
    param([ValidateSet('setup', 'verify')][string]$Phase)
    $Required = @(
        'lab_target_package', 'target_internet_permission_denied', 'test_internet_permission_denied',
        'lab_only_application', 'emulator_hardware', 'webview_network_loads_blocked_before_dialog'
    )
    if ($Phase -eq 'setup') {
        return $Required + @(
            'tokenstore_filters_sso_material', 'tokenstore_new_instance_restores_group',
            'tokenstore_identical_cookie_new_partition', 'tokenstore_rejects_sso_only_without_replacing_session',
            'encrypted_preferences_no_plaintext_cookie', 'cold_restore_marker_committed'
        )
    }
    return $Required + @(
        'cold_process_marker_matches', 'tokenstore_cold_process_restore', 'encrypted_preferences_cold_no_plaintext',
        'tokenstore_logout_revokes_active_pointer', 'tokenstore_counter_survives_logout',
        'webview_local_storage_seeded_offline', 'webview_cookie_path_and_sso_filtering',
        'webview_cookie_cleaner_completes', 'webview_dom_storage_removed',
        'dialog_network_still_blocked', 'dialog_secure_window_is_independent', 'dialog_webview_security_settings',
        'dialog_rejects_full_and_partial_obscured_touch', 'dialog_overlay_window_flag_dump',
        'room-lab-internet-permission-absent', 'room-lab-real-token-store-adopts-academic-cookie-only',
        'room-lab-real-room-retains-legacy-a-b-with-disjoint-primary-keys',
        'room-lab-production-today-reader-shows-only-current-b',
        'room-lab-old-a-snapshot-cannot-read-or-publish-under-b',
        'room-lab-null-profile-never-falls-back-to-legacy',
        'room-lab-encrypted-restore-keeps-b-partition-and-revokes-old-snapshot',
        'room-lab-logout-revokes-current-view-and-preserves-real-room-history',
        'room-lab-login-after-logout-does-not-reuse-cached-namespace', 'room-lab-zero-school-transport-calls'
    )
}

function Assert-LabReport {
    param([object]$Report, [string]$Phase)
    if ($Report.phase -cne $Phase -or $Report.target_package -cne $LabPackage -or
        $Report.test_package -cne $TestPackage -or $Report.passed -isnot [bool] -or -not $Report.passed -or
        $Report.format_version -ne 1 -or $Report.sdk_int -ne 31 -or $Report.hardware -cnotin @('ranchu', 'goldfish') -or
        $Report.pid -isnot [ValueType] -or $Report.pid -is [bool] -or [long]$Report.pid -le 0 -or
        [long]$Report.pid -ne $Report.pid) {
        throw "The $Phase report does not confirm a passing lab phase."
    }
    $Checks = @($Report.checks)
    $Required = @(Get-RequiredLabChecks -Phase $Phase)
    if ($Checks.Count -ne $Required.Count -or @($Checks | Where-Object { $_.passed -isnot [bool] -or -not $_.passed }).Count -ne 0) {
        throw "The $Phase report contains missing or failed checks."
    }
    $Names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($Check in $Checks) {
        if ($Check.name -isnot [string] -or $Check.name -cnotin $Required -or -not $Names.Add($Check.name)) {
            throw "The $Phase report contains an unknown or duplicate check."
        }
    }
}

function Read-PrivateEvidence {
    param([ValidateSet('offline-security-setup.json', 'offline-security-verify.json', 'offline-security-window-dump.txt')][string]$Name)
    $Result = Invoke-LabAdb -Command @('exec-out', 'run-as', $LabPackage, 'cat', "files/$Name") -Label ('export-' + $Name.Replace('.', '-'))
    if ([string]::IsNullOrWhiteSpace($Result.Out)) { throw 'An expected private lab evidence file is empty.' }
    Write-EvidenceText $Name $Result.Out
    return $Result.Out
}

function Invoke-LabPhase {
    param([ValidateSet('setup', 'verify')][string]$Phase)
    Confirm-LabAvd -Label "$Phase-confirm-avd"
    $Result = Invoke-LabAdb -Command @('shell', 'am', 'instrument', '-w', '-r', '-e', 'phase', $Phase,
        '-e', 'runId', $RunId, "$TestPackage/$Runner") -Label "$Phase-instrumentation" -TimeoutSeconds $PhaseTimeoutSeconds
    $ReportLines = [regex]::Matches($Result.Out, '(?m)^INSTRUMENTATION_RESULT: lab_report=(.+)\r?$')
    $PassLines = [regex]::Matches($Result.Out, '(?m)^INSTRUMENTATION_RESULT: lab_passed=(true|false)\s*$')
    $CodeLines = [regex]::Matches($Result.Out, '(?m)^INSTRUMENTATION_CODE: (-?\d+)\s*$')
    if ($ReportLines.Count -ne 1 -or $PassLines.Count -ne 1 -or $CodeLines.Count -ne 1) {
        throw "The $Phase instrumentation did not return exactly one structured result."
    }
    $Report = ConvertFrom-Json -InputObject $ReportLines[0].Groups[1].Value
    Write-EvidenceJson "$Phase-instrumentation-report.json" $Report
    $Summary.phases[$Phase] = [ordered]@{ passed = $Report.passed; pid = $Report.pid; check_count = @($Report.checks).Count }
    # Export even a failed report before rejecting it. Never trust the returned file path.
    $PrivateText = Read-PrivateEvidence -Name "offline-security-$Phase.json"
    $PrivateReport = ConvertFrom-Json -InputObject $PrivateText
    if ((ConvertTo-Json -InputObject $Report -Depth 100 -Compress) -cne
        (ConvertTo-Json -InputObject $PrivateReport -Depth 100 -Compress)) {
        throw "The $Phase returned and privately saved reports differ."
    }
    if ($Phase -eq 'verify' -and @($Report.checks | Where-Object { $_.name -ceq 'dialog_overlay_window_flag_dump' }).Count -eq 1) {
        [void](Read-PrivateEvidence -Name 'offline-security-window-dump.txt')
    }
    if ($PassLines[0].Groups[1].Value -cne 'true' -or $CodeLines[0].Groups[1].Value -ne '-1' -or
        $Result.Out.Contains('lab_report_write_error=')) {
        throw "The $Phase instrumentation reported failure."
    }
    Assert-LabReport -Report $Report -Phase $Phase
    return $Report
}

$ExitCode = 1
try {
    if (Test-Path -LiteralPath $RunDirectory) { throw 'This run ID already has evidence; choose a new run ID.' }
    [void][IO.Directory]::CreateDirectory($RunDirectory)
    $RunDirectoryCreated = $true
    if ($AdbServerPort -eq 5037) { throw 'Use a dedicated ADB server port; the default shared port 5037 is refused.' }
    $ConsolePort = [int]$EmulatorSerial.Substring('emulator-'.Length)
    if ($ConsolePort -lt 5554 -or $ConsolePort -gt 5682 -or $ConsolePort % 2 -ne 0) { throw 'Use a valid even emulator console port.' }
    $AdbPath = Resolve-InputFile $AdbPath '.security-tools/sdk/platform-tools/adb.exe'
    $AaptPath = Resolve-InputFile $AaptPath '.security-tools/sdk/build-tools/35.0.0/aapt.exe'
    $LabApk = Resolve-InputFile $LabApk 'app/build/outputs/apk/securityLab/app-securityLab.apk'
    $TestApk = Resolve-InputFile $TestApk 'app/build/outputs/apk/androidTest/securityLab/app-securityLab-androidTest.apk'
    Confirm-LabAvd
    $IdentityConfirmed = $true
    if ((Invoke-LabAdb -Command @('get-state') -Label 'device-state').Out.Trim() -cne 'device') { throw 'The selected emulator is not available.' }
    if ((Invoke-LabAdb -Command @('shell', 'getprop', 'sys.boot_completed') -Label 'boot-state').Out.Trim() -ne '1') {
        throw 'The lab AVD is not booted; this script does not start or wait for an emulator.'
    }
    foreach ($Path in @($LabApk, $TestApk)) {
        # Allow aapt/adb readers but deny replacement or modification between verification and installation.
        [void]$ApkLocks.Add([IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read))
    }
    $Summary.apks = @((Confirm-OfflineApk $LabApk $LabPackage 'lab' $false), (Confirm-OfflineApk $TestApk $TestPackage 'test' $true))
    $Summary.tools = [ordered]@{ adb = $AdbPath; aapt = $AaptPath }
    $Os = [ordered]@{}
    foreach ($Property in @('ro.build.version.sdk', 'ro.build.version.release', 'ro.build.fingerprint', 'ro.hardware', 'ro.product.cpu.abi')) {
        $Os[$Property] = (Invoke-LabAdb -Command @('shell', 'getprop', $Property) -Label ($Property.Replace('.', '-'))).Out.Trim()
    }
    $Summary.os = $Os
    if ($Os['ro.build.version.sdk'] -ne '31' -or $Os['ro.hardware'] -notin @('ranchu', 'goldfish')) { throw 'The expected API 31 emulator hardware was not observed.' }
    [void](Invoke-LabAdb -Command @('shell', 'dumpsys', 'webviewupdate') -Label 'webview-provider')
    Confirm-LabAvd -Label 'install-confirm-avd'
    $Installed = Invoke-LabAdb -Command @('install', '-r', '--no-streaming', $LabApk) -Label 'install-lab' -TimeoutSeconds 120
    if ($Installed.Out -notmatch '(?m)^Success\s*$') { throw 'Lab APK installation did not confirm success.' }
    $LabInstalled = $true
    $Installed = Invoke-LabAdb -Command @('install', '-r', '-t', '--no-streaming', $TestApk) -Label 'install-test' -TimeoutSeconds 120
    if ($Installed.Out -notmatch '(?m)^Success\s*$') { throw 'Test APK installation did not confirm success.' }
    $InstalledPackages = [ordered]@{}
    foreach ($Package in @($LabPackage, $TestPackage)) {
        $Label = if ($Package -eq $LabPackage) { 'lab' } else { 'test' }
        $Uid = Invoke-LabAdb -Command @('shell', 'cmd', 'package', 'list', 'packages', '-U', $Package) -Label "$Label-installed-uid"
        $UidMatch = [regex]::Match($Uid.Out, '(?m)^package:' + [regex]::Escape($Package) + '\s+uid:(\d+)\s*$')
        if (-not $UidMatch.Success) { throw 'An installed lab package UID is missing.' }
        $PackageDump = Invoke-LabAdb -Command @('shell', 'dumpsys', 'package', $Package) -Label "$Label-installed-package"
        if ($PackageDump.Out.Contains('android.permission.INTERNET')) { throw 'INTERNET unexpectedly appears in an installed lab package record.' }
        $InstalledPackages[$Package] = [ordered]@{ uid = [int]$UidMatch.Groups[1].Value; internet_declared = $false;
            internet_permission_denial = 'Pending the in-process PackageManager checks in both phases.' }
    }
    $Summary.installed_packages = $InstalledPackages
    $Setup = Invoke-LabPhase -Phase 'setup'
    Confirm-LabAvd -Label 'cold-stop-confirm-avd'
    [void](Invoke-LabAdb -Command @('shell', 'am', 'force-stop', $LabPackage) -Label 'cold-force-stop-lab')
    $Verify = Invoke-LabPhase -Phase 'verify'
    if ([int]$Setup.pid -eq [int]$Verify.pid) { throw 'Setup and verify did not execute in separate processes.' }
    if (@($Verify.checks | Where-Object { $_.name -ceq 'cold_process_marker_matches' -and $_.passed -eq $true }).Count -ne 1) {
        throw 'The verify report does not establish the same-run cold-process marker.'
    }
    if (-not [IO.File]::Exists((Join-Path $RunDirectory 'offline-security-window-dump.txt'))) { throw 'The current verification phase did not produce a window dump.' }
    foreach ($Package in @($LabPackage, $TestPackage)) {
        $InstalledPackages[$Package].internet_permission_denial = 'Confirmed by PackageManager checks in both passing instrumentation phases.'
    }
    $Summary.passed = $true
    $ExitCode = 0
} catch {
    $Summary.error = $_.Exception.Message
    # A timed-out local adb client may leave instrumentation running. Stop only this
    # fixed lab application after rechecking the AVD identity, without any login retry.
    if ($IdentityConfirmed -and $LabInstalled) {
        try {
            Confirm-LabAvd -Label 'failure-cleanup-confirm-avd'
            [void](Invoke-LabAdb -Command @('shell', 'am', 'force-stop', $LabPackage) -Label 'failure-force-stop-lab')
        } catch { $Summary.cleanup_error = 'Could not confirm and stop the dedicated lab application; inspect command evidence.' }
    }
} finally {
    foreach ($Lock in $ApkLocks) { $Lock.Dispose() }
    $Summary.finished_utc = [DateTime]::UtcNow.ToString('o')
    if ($RunDirectoryCreated -and [IO.Directory]::Exists($RunDirectory)) {
        $Summary.evidence_files = @(Get-ChildItem -LiteralPath $RunDirectory -File | ForEach-Object {
            [ordered]@{ name = $_.Name; bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
        })
        Write-EvidenceJson 'run-summary.json' $Summary
    }
}

if ($ExitCode -eq 0) { Write-Host "Offline Android lab passed. Evidence: $RunDirectory" }
else { Write-Error -Message "Offline Android lab did not pass. Evidence: $RunDirectory" -ErrorAction Continue }
exit $ExitCode
