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
    'android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE',
    'android.permission.POST_NOTIFICATIONS', 'android.permission.FOREGROUND_SERVICE',
    'android.permission.FOREGROUND_SERVICE_SPECIAL_USE', 'android.permission.VIBRATE'})
ecard = (SRC / 'data/ecard/EcardClient.kt').read_text(encoding='utf-8')
check('all ecard request sites guarded', 'client.newCall(' not in ecard and
      ecard.count('financialClient().newCall(') == 7 and 'SecurityPolicy.requireFinancialNetwork()' in ecard)
gms = (SRC / 'data/gms/GmsClient.kt').read_text(encoding='utf-8')
check('native GMS redirects disabled and policy installed', '.followRedirects(false)' in gms and
      '.followSslRedirects(false)' in gms and '.addInterceptor(SchoolNetworkInterceptor())' in gms)
check('release has no debug signing fallback', 'signingConfig = signingConfigs.getByName("debug")' not in text('app/build.gradle.kts'))
check('fork has separate application data', 'applicationId = "com.zzupocket.app.secure"' in text('app/build.gradle.kts'))
check('Gradle distribution integrity pinned', bool(re.search(r'^distributionSha256Sum=[a-f0-9]{64}$',
      text('gradle/wrapper/gradle-wrapper.properties'), re.M)))
check('no SSL error bypass or native JS bridge', all('handler.proceed(' not in p.read_text(encoding='utf-8-sig') and
      'addJavascriptInterface(' not in p.read_text(encoding='utf-8-sig') for p in SRC.rglob('*.kt')))
print(json.dumps({'network_requests': 0, 'checks': results, 'passed': all(r['passed'] for r in results)}, indent=2))
raise SystemExit(0 if all(r['passed'] for r in results) else 1)
