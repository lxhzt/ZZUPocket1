"""Pure local fixtures: no ADB, Gradle, emulator, network or file mutations.

Run: python tools/test_offline_security_guards.py
PowerShell 7 FullLanguage is required only for parsing and in-memory report fixtures.
"""
import ast
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    guard_path = root / 'tools/security_static_check.py'
    source = guard_path.read_text(encoding='utf-8-sig')
    parsed = ast.parse(source, filename=str(guard_path))
    definitions = [node for node in parsed.body if isinstance(node, ast.FunctionDef) and node.name == 'restricted_release_signing']
    if len(definitions) != 1:
        raise RuntimeError('Signing guard must have exactly one definition')
    namespace = {'re': re}
    # Execute the pure guard definition, not the static checker's top-level workflow.
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(guard_path), 'exec'), namespace)
    guard = namespace['restricted_release_signing']
    gradle = (root / 'app/build.gradle.kts').read_text(encoding='utf-8-sig')
    cases = []

    def case(name, candidate, expected):
        actual = bool(guard(candidate))
        cases.append({'name': name, 'expected_acceptance': expected, 'accepted': actual, 'passed': actual == expected})

    def insert_before_compile(extra):
        return gradle.replace('    compileOptions {', extra + '\n    compileOptions {', 1)

    def append_release(extra):
        marker = '    // Instrumentation belongs only'
        boundary = gradle.index(marker)
        # The first closing brace before this marker closes buildTypes; the preceding
        # eight-space brace closes release. Insert inside release immediately before it.
        end = gradle.rfind('        }', 0, boundary)
        return gradle[:end] + extra + '\n' + gradle[end:]

    case('current-owner-or-unsigned-release-and-one-lab-exemption', gradle, True)
    case('formatting-does-not-widen-exemption', gradle.replace('signingConfig =', 'signingConfig\n ='), True)
    case('commented-braces-and-debug-text-are-inert', gradle + '\n// release { signingConfig = signingConfigs.getByName("debug") }\n', True)
    case('quoted-braces-are-inert', gradle + '\nval fixtureText = "release { signingConfig = debug }"\n', True)
    case('external-release-override', insert_before_compile('    buildTypes.named("release") { signingConfig = signingConfigs.getByName("debug") }'), False)
    case('external-release-index-override', insert_before_compile('    buildTypes["release"].signingConfig = signingConfigs["debug"]'), False)
    case('external-release-configuration-even-without-assignment', insert_before_compile('    buildTypes.named("release") { isMinifyEnabled = false }'), False)
    case('final-release-debug-index-assignment', append_release('            signingConfig = signingConfigs["debug"]'), False)
    case('final-release-debug-spaced-lookup', append_release('            signingConfig = signingConfigs.findByName( "debug" )'), False)
    case('final-release-initwith-debug', append_release('            initWith(getByName("debug"))'), False)
    case('debug-alias-access-outside-lab', insert_before_compile('    val extraSigning = signingConfigs.getByName("debug")'), False)
    case('debug-setter-outside-lab', insert_before_compile('    buildTypes.getByName("release").setSigningConfig(signingConfigs.getByName("debug"))'), False)
    case('owner-branch-replaced-with-debug', gradle.replace('signingConfigs.getByName("zzupocket")', 'signingConfigs.getByName("debug")'), False)
    case('unsigned-branch-replaced-with-debug', gradle.replace('signingConfig = null', 'signingConfig = signingConfigs.getByName("debug")'), False)
    case('missing-reviewed-release', gradle.replace('        release {', '        unexpectedRelease {', 1), False)
    case('lab-name-cannot-expand-exemption', gradle.replace('create("securityLab")', 'create("anotherLab")', 1), False)
    case('lab-cannot-export-signing-alias', gradle.replace('            applicationIdSuffix = ".securitylab"', '            val exported = signingConfigs.getByName("debug")\n            applicationIdSuffix = ".securitylab"'), False)
    case('second-lab-assignment', gradle.replace('            signingConfig = signingConfigs.getByName("debug")', '            signingConfig = signingConfigs.getByName("debug")\n            signingConfig = signingConfigs.getByName("debug")', 1), False)
    case('dynamic-signing-property-outside-lab', insert_before_compile('    setProperty("signingConfig", signingConfigs.getByName("debug"))'), False)
    case('unreviewed-kotlin-template-fails-closed', gradle + '\nval fixtureTemplate = "${1}"\n', False)
    case('unbalanced-build-script-fails-closed', gradle + '\n}', False)

    powershell = shutil.which('pwsh') or shutil.which('pwsh.exe')
    if not powershell:
        raise RuntimeError('PowerShell 7 is required for the in-memory report fixtures')
    completed = subprocess.run(
        [powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(root / 'tools/test-offline-android-report-guards.ps1')],
        cwd=root, capture_output=True, text=True, encoding='utf-8', timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError('Report fixtures failed: ' + (completed.stderr or completed.stdout)[-4000:])
    report_fixtures = json.loads(completed.stdout)
    passed = all(item['passed'] for item in cases) and report_fixtures['passed']
    result = {
        'format_version': 1, 'passed': passed,
        'tests': len(cases) + report_fixtures['tests'],
        'network_requests': 0, 'device_commands': 0,
        'signing_guard': {'tests': len(cases), 'passed': all(item['passed'] for item in cases), 'cases': cases},
        'report_guard': report_fixtures,
        'limits': ['Source regression fixtures do not interpret arbitrary Kotlin or replace APK signature verification.',
                   'Mock reports test acceptance rules, not actual emulator behavior.'],
    }
    print(json.dumps(result, indent=2))
    return 0 if passed else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({'passed': False, 'infrastructure_error': str(error), 'network_requests': 0, 'device_commands': 0}))
        sys.exit(1)
