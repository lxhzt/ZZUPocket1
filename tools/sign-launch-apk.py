"""Sign a previously reviewed release APK using a persistent, local-only launch key.

No network operations. No debug signing fallback. Never prints key passwords.
The whole .security-tools/launch-signing directory must be backed up privately.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / '.security-tools/jdk/jdk17.0.21_0/bin/java.exe'
KEYTOOL = JAVA.with_name('keytool.exe')
BUILD_TOOLS = ROOT / '.security-tools/sdk/build-tools/35.0.0'
KEY_DIR = ROOT / '.security-tools/launch-signing'
KEY = KEY_DIR / 'launch.p12'
PASSWORD = KEY_DIR / 'password.txt'
INPUT = ROOT / 'app/build/outputs/apk/release/app-release-unsigned.apk'
OUT_DIR = ROOT / 'dist'
NAME = 'ZZUPocket-0.33.0-launch.1.apk'
OUTPUT = OUT_DIR / NAME
EVIDENCE = ROOT / 'docs/security-evidence/launch-20261028.json'


def run(args):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True,
                            encoding='utf-8', errors='replace', timeout=180)
    if result.returncode:
        # Arguments never contain the password itself; keytool uses a local file.
        raise RuntimeError(f'{Path(str(args[0])).name} failed: {result.stdout}\n{result.stderr}')
    return result.stdout + result.stderr


def main():
    if not INPUT.is_file():
        raise RuntimeError('Build the unsigned release first')
    if OUTPUT.exists():
        raise RuntimeError('Refusing to overwrite a previously signed launch artifact')
    ignored = subprocess.run(['git', 'check-ignore', str(KEY), str(PASSWORD)],
                             cwd=ROOT, capture_output=True, timeout=15)
    if ignored.returncode:
        raise RuntimeError('Signing material must be excluded from Git')
    KEY_DIR.mkdir(exist_ok=True)
    # Limit this dedicated directory to the current Windows account and SYSTEM.
    identity = run(['whoami']).strip()
    if identity.rsplit('\\', 1)[-1].lower() != 'hkli':
        raise RuntimeError('Signing must run as the workspace owner hkli, not a temporary tool account')
    run(['icacls', KEY_DIR, '/inheritance:r', '/grant:r', identity + ':(OI)(CI)F',
         '*S-1-5-18:(OI)(CI)F'])
    if KEY.exists() != PASSWORD.exists():
        raise RuntimeError('Incomplete signing material: recover the private backup; do not rotate silently')
    if not KEY.exists():
        with PASSWORD.open('x', encoding='ascii') as stream:
            stream.write(secrets.token_urlsafe(48) + '\n')
        run([KEYTOOL, '-genkeypair', '-keystore', KEY, '-storetype', 'PKCS12',
             '-alias', 'zzupocket-launch', '-keyalg', 'RSA', '-keysize', '3072',
             '-sigalg', 'SHA256withRSA', '-validity', '10000',
             '-dname', 'CN=ZZUPocket Launch, OU=Development, O=ZZUPocket, C=CN',
             '-storepass:file', PASSWORD, '-keypass:file', PASSWORD])
    OUT_DIR.mkdir(exist_ok=True)
    aligned = ROOT / '.security-tools/launch-aligned.apk'
    run([BUILD_TOOLS / 'zipalign.exe', '-f', '-P', '16', '4', INPUT, aligned])
    signer = [JAVA, '-jar', BUILD_TOOLS / 'lib/apksigner.jar']
    run(signer + ['sign', '--ks', KEY, '--ks-key-alias', 'zzupocket-launch',
                  '--ks-pass', 'file:' + str(PASSWORD),
                  '--v1-signing-enabled', 'false', '--v2-signing-enabled', 'true',
                  '--v3-signing-enabled', 'true', '--v4-signing-enabled', 'false',
                  '--out', OUTPUT, aligned])
    signature = run(signer + ['verify', '--verbose', '--print-certs', OUTPUT])
    # On minSdk 31, the default verifier selects v3 and does not report v2 as verified.
    # Separately force the v2 verification range; this does not change APK minSdk.
    signature_v2 = run(signer + ['verify', '--min-sdk-version', '24', '--max-sdk-version', '27', '--verbose', OUTPUT])
    if 'Verified using v2 scheme (APK Signature Scheme v2): true' not in signature_v2 or \
            'Verified using v3 scheme (APK Signature Scheme v3): true' not in signature:
        raise RuntimeError('APK v2/v3 signature verification failed')
    run([BUILD_TOOLS / 'zipalign.exe', '-c', '-P', '16', '4', OUTPUT])
    badging = run([BUILD_TOOLS / 'aapt2.exe', 'dump', 'badging', OUTPUT])
    if not re.search(r"package: name='com\.zzupocket\.app\.secure' versionCode='90' versionName='0\.33\.0-launch\.1'", badging):
        raise RuntimeError('Unexpected launch package identity')
    if not re.search(r"(?:minSdkVersion|sdkVersion):'31'", badging) or 'application-debuggable' in badging:
        raise RuntimeError('Unexpected Android compatibility or debuggable release')
    if 'securitylab' in badging.lower():
        raise RuntimeError('Offline lab component leaked into release manifest')
    if "application-label:'ZZUPocket 安全测试版'" not in badging:
        raise RuntimeError('The launcher must distinguish this prerelease from the upstream app')
    with zipfile.ZipFile(OUTPUT) as archive:
        dex = b''.join(archive.read(name) for name in archive.namelist()
                       if re.fullmatch(r'classes\d*\.dex', name))
        if any(name in dex for name in (b'OfflineHarnessActivity', b'OfflineSecurityInstrumentation', b'OfflineSecurityApplication')):
            raise RuntimeError('Offline lab classes leaked into the release APK')
        if '学校统一凭据的权限范围仍在核实，本测试版尚未完成资金安全验收。'.encode('utf-8') not in dex:
            raise RuntimeError('Current launch status text is missing from the compiled APK')
    manifest = run([BUILD_TOOLS / 'aapt2.exe', 'dump', 'xmltree', OUTPUT, '--file', 'AndroidManifest.xml'])
    for attr in ('allowBackup', 'usesCleartextTraffic'):
        if not re.search(r'android:' + attr + r'\([^\n]*\)=false', manifest):
            raise RuntimeError('Missing release restriction: ' + attr)
    certificate = re.search(r'Signer #1 certificate SHA-256 digest: ([a-f0-9]+)', signature)
    if not certificate:
        raise RuntimeError('Signing certificate digest not found')
    checksum = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
    (OUT_DIR / 'SHA256SUMS.txt').write_text(checksum + '  ' + NAME + '\n', encoding='ascii')
    evidence = {
        'date': '2026-10-28', 'version_name': '0.33.0-launch.1', 'version_code': 90,
        'package': 'com.zzupocket.app.secure', 'min_sdk': 31, 'target_sdk': 36,
        'apk_name': NAME, 'apk_bytes': OUTPUT.stat().st_size, 'apk_sha256': checksum,
        'certificate_sha256': certificate.group(1), 'signature_v2_verified': True,
        'signature_v3_verified': True, 'zip_alignment_verified': True,
        'debuggable': False, 'backup_enabled': False, 'cleartext_enabled': False,
        'launcher_label': 'ZZUPocket 安全测试版', 'lab_components_in_release': False,
        'android_runtime_assertions_executed': 0, 'school_authenticated_tests': 0,
        'funds_isolation_server_side_proved': False, 'prerelease': True,
        'signing_material_uploaded': False,
    }
    EVIDENCE.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    (ROOT / '.security-tools/launch-signature-verification.txt').write_text(signature + '\nSeparate v2 verification (not an installation support claim):\n' + signature_v2, encoding='utf-8')
    (ROOT / '.security-tools/launch-manifest.txt').write_text(manifest, encoding='utf-8')
    print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    main()
