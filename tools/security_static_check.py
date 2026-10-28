"""Offline release guardrails. No network, credentials, subprocesses or file mutations."""
from pathlib import Path
import json
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'app/src/main/java/com/zzupocket/app'
ANDROID = '{http://schemas.android.com/apk/res/android}'
results = []

def check(name, condition):
    results.append({'check': name, 'passed': bool(condition)})

def text(path):
    return (ROOT / path).read_text(encoding='utf-8-sig')


def restricted_release_signing(source):
    """Fail closed on signing DSL changes; exempt only the exact separate lab block.

    This is a source regression gate, not a Kotlin interpreter or APK signature check.
    Comments and quoted braces do not affect block boundaries. New signing syntax
    requires an explicit gate review rather than silently widening this exemption.
    """
    def tokens(value):
        pattern = r'\s+|//[^\n]*|/\*.*?\*/|""".*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_][A-Za-z_0-9]*|.'
        parts = []
        for match in re.finditer(pattern, value, re.S):
            item = match.group()
            if item.isspace() or item.startswith('//') or item.startswith('/*'):
                continue
            # Expressions inside Kotlin string templates need semantic review.
            if item.startswith('"') and '${' in item:
                return None
            parts.append(item)
        return parts

    items = tokens(source)
    if items is None:
        return False
    depth = []
    level = 0
    for item in items:
        depth.append(level)
        if item == '{':
            level += 1
        elif item == '}':
            level -= 1
        if level < 0:
            return False
    if level:
        return False

    def block(prefix):
        prefix = tokens(prefix)
        starts = [i + len(prefix) - 1 for i in range(len(items) - len(prefix) + 1)
                  if items[i:i + len(prefix)] == prefix]
        if len(starts) != 1:
            return None
        start = starts[0]
        for end in range(start + 1, len(items)):
            if items[end] == '}' and depth[end] == depth[start] + 1:
                return start, end
        return None

    android = block('android {')
    build_types = block('buildTypes {')
    signing = block('signingConfigs {')
    lab = block('create("securityLab") {')
    release = block('release {')
    if any(part is None for part in (android, build_types, signing, lab, release)):
        return False
    if not (android[0] < build_types[0] < build_types[1] < android[1] and
            android[0] < signing[0] < signing[1] < android[1] and
            build_types[0] < lab[0] < lab[1] < build_types[1] and
            build_types[0] < release[0] < release[1] < build_types[1] and
            depth[build_types[0]] == depth[android[0]] + 1 and
            depth[signing[0]] == depth[android[0]] + 1 and
            depth[lab[0]] == depth[build_types[0]] + 1 and
            depth[release[0]] == depth[build_types[0]] + 1):
        return False
    expected_lab = tokens('''
        initWith(getByName("debug"))
        applicationIdSuffix = ".securitylab"
        versionNameSuffix = "-offline-lab"
        matchingFallbacks += listOf("debug")
        signingConfig = signingConfigs.getByName("debug")
    ''')
    expected_owner = tokens('''
        if (hasReleaseSigning) {
            create("zzupocket") {
                storeFile = releaseStoreFile
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    ''')
    expected_release = tokens('''
        if (hasReleaseSigning) {
            signingConfig = signingConfigs.getByName("zzupocket")
        } else {
            signingConfig = null
        }
    ''')
    body = items[release[0] + 1:release[1]]
    if (items[lab[0] + 1:lab[1]] != expected_lab or
            items[signing[0] + 1:signing[1]] != expected_owner or
            sum(body[i:i + len(expected_release)] == expected_release
                for i in range(len(body) - len(expected_release) + 1)) != 1):
        return False
    # The approved lab assignment and owner/null release branch account for every
    # signing access. An override outside the release block cannot escape this check.
    counts = {'buildTypes': 1, 'release': 1, 'signingConfigs': 3, 'signingConfig': 3,
              'initWith': 1, 'setSigningConfig': 0, '"debug"': 3, '"release"': 0,
              '"signingConfig"': 0, '"signingConfigs"': 0}
    return all(items.count(name) == count for name, count in counts.items())


policy = (SRC / 'core/security/SecurityPolicy.kt').read_text(encoding='utf-8')
for flag in ['FINANCIAL_NETWORK_ENABLED', 'LIBRARY_ENABLED', 'NETWORK_DIAGNOSTICS_ENABLED']:
    check(flag + ' disabled', bool(re.search(r'const val ' + flag + r'\s*=\s*false', policy)))
manifest = ET.fromstring(text('app/src/main/AndroidManifest.xml'))
app = manifest.find('application')
check('backup disabled', app.get(ANDROID + 'allowBackup') == 'false')
check('cleartext disabled in manifest', app.get(ANDROID + 'usesCleartextTraffic') == 'false')
config = ET.fromstring(text('app/src/main/res/xml/network_security_config.xml'))
check('no cleartext exceptions', all(n.get('cleartextTrafficPermitted') != 'true' for n in config.iter()))
check('system certificate trust only', [n.get('src') for n in config.iter('certificates')] == ['system'])
for name in ['backup_rules.xml', 'data_extraction_rules.xml']:
    tree = ET.fromstring(text('app/src/main/res/xml/' + name))
    groups = [tree] if tree.tag == 'full-backup-content' else list(tree)
    check(name + ' excludes private files and WebView data', all(
        {'root', 'file', 'database', 'sharedpref', 'external'} <=
        {n.get('domain') for n in group.findall('exclude') if n.get('path') == '.'}
        for group in groups))
check('only launcher activity exported', all(
    n.tag == 'activity' and n.get(ANDROID + 'name') == '.MainActivity'
    for n in app if n.get(ANDROID + 'exported') == 'true'))
permissions = {n.get(ANDROID + 'name') for n in manifest.findall('uses-permission')}
check('no added sensitive device permissions', permissions <= {
    'android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE', 'android.permission.HIDE_OVERLAY_WINDOWS',
    'android.permission.POST_NOTIFICATIONS', 'android.permission.FOREGROUND_SERVICE',
    'android.permission.FOREGROUND_SERVICE_SPECIAL_USE', 'android.permission.VIBRATE'})
ecard = (SRC / 'data/ecard/EcardClient.kt').read_text(encoding='utf-8')
check('all ecard request sites guarded', 'client.newCall(' not in ecard and
      ecard.count('financialClient().newCall(') == 7 and 'SecurityPolicy.requireFinancialNetwork()' in ecard)
gms = (SRC / 'data/gms/GmsClient.kt').read_text(encoding='utf-8')
check('native GMS redirects disabled and policy installed', '.followRedirects(false)' in gms and
      '.followSslRedirects(false)' in gms and '.addInterceptor(SchoolNetworkInterceptor(SchoolService.GMS))' in gms)
check('release has no debug signing fallback', restricted_release_signing(text('app/build.gradle.kts')))
check('fork has separate application data', 'applicationId = "com.zzupocket.app.secure"' in text('app/build.gradle.kts'))
check('Gradle distribution integrity pinned', bool(re.search(r'^distributionSha256Sum=[a-f0-9]{64}$',
      text('gradle/wrapper/gradle-wrapper.properties'), re.M)))
check('no SSL error bypass or native JS bridge', all('handler.proceed(' not in p.read_text(encoding='utf-8-sig') and
      'addJavascriptInterface(' not in p.read_text(encoding='utf-8-sig') for p in SRC.rglob('*.kt')))
http = (SRC / 'core/net/HttpClients.kt').read_text(encoding='utf-8')
check('each native factory has an explicit capability profile', all(
    'builder(SchoolService.' + service in http for service in ['CAS', 'EAS', 'FINANCE_DISABLED']) and
    'SchoolNetworkInterceptor(SchoolService.GMS)' in gms)
auth = (SRC / 'data/auth/AuthRepository.kt').read_text(encoding='utf-8')
check('unused CAS refresh credential is not persisted', 'store.casRefreshToken = result.refreshToken' not in auth and
      'store.casRefreshToken = null' in auth)
activity = (SRC / 'MainActivity.kt').read_text(encoding='utf-8')
check('overlay hiding and obscured touch filtering enabled',
      'android.permission.HIDE_OVERLAY_WINDOWS' in permissions and 'setHideOverlayWindows(true)' in activity and
      'FLAG_WINDOW_IS_PARTIALLY_OBSCURED' in activity)
eas = (SRC / 'data/eas/EasClient.kt').read_text(encoding='utf-8')
check('general EAS diagnostic transport disabled',
      'com.zzupocket.app.core.security.SecurityPolicy.requireDiagnostics()' in eas)
verification_path = ROOT / 'gradle/verification-metadata.xml'
verification_ok = False
if verification_path.exists():
    verification = ET.parse(verification_path).getroot()
    artifacts = verification.findall('.//{*}artifact')
    verification_ok = (
        verification.findtext('.//{*}verify-metadata') == 'true' and bool(artifacts) and
        not verification.findall('.//{*}trusted-artifacts/{*}trust') and
        all(any(re.fullmatch(r'[a-f0-9]{64}', n.get('value', ''))
                for n in artifact.findall('{*}sha256')) for artifact in artifacts)
    )
check('resolved dependency artifacts and metadata have SHA256 pins without broad exemptions', verification_ok)
check('local verification workflow enforces strict dependency verification',
      "'--dependency-verification', 'strict'" in text('tools/run-local-security.ps1'))
print(json.dumps({'network_requests': 0, 'checks': results, 'passed': all(r['passed'] for r in results)}, indent=2))
raise SystemExit(0 if all(r['passed'] for r in results) else 1)
