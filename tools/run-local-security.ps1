param([switch]$AllowDependencyDownload)
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    python tools/security_static_check.py
    if ($LASTEXITCODE -ne 0) { throw 'Static security guardrails failed' }
    $gradleArgs = @('testDebugUnitTest', 'assembleDebug', 'lintDebug', 'assembleRelease',
        '--console=plain', '--no-daemon', '--max-workers=1',
        '-Pkotlin.compiler.execution.strategy=in-process', '-Dorg.gradle.jvmargs=-Xmx2048m -Dfile.encoding=UTF-8')
    if (-not $AllowDependencyDownload) { $gradleArgs += '--offline' }
    # No app launch, school credentials, DNS, port scans or external stress targets.
    & ./gradlew.bat @gradleArgs
    if ($LASTEXITCODE -ne 0) { throw 'Build or security regression checks failed' }
} finally {
    Pop-Location
}
