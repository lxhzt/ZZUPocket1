"""Exercise Gradle verification using only an isolated synthetic local Maven repository."""
import hashlib
import json
import os
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / '.security-tools/dependency-verification-fixture'
FIXTURE.mkdir(parents=True, exist_ok=True)
repo = FIXTURE / 'repo/local/audit/probe/1.0'
repo.mkdir(parents=True, exist_ok=True)
jar = repo / 'probe-1.0.jar'
with zipfile.ZipFile(jar, 'w') as archive:
    archive.writestr('synthetic.txt', 'No executable code or real credentials.\n')
pom = repo / 'probe-1.0.pom'
pom.write_text('<project><modelVersion>4.0.0</modelVersion><groupId>local.audit</groupId><artifactId>probe</artifactId><version>1.0</version></project>', encoding='utf-8')
(FIXTURE / 'settings.gradle').write_text("rootProject.name='local-verification-fixture'\n", encoding='utf-8')
(FIXTURE / 'build.gradle').write_text("repositories { maven { url = uri('repo') } }\nconfigurations { audit }\ndependencies { audit 'local.audit:probe:1.0' }\ntasks.register('verifyProbe') { doLast { assert configurations.audit.files.size() == 1 } }\n",encoding='utf-8')
metadata = FIXTURE / 'gradle/verification-metadata.xml'
metadata.parent.mkdir(exist_ok=True)
def write_metadata(jar_hash):
    metadata.write_text('''<?xml version="1.0" encoding="UTF-8"?>
<verification-metadata xmlns="https://schema.gradle.org/dependency-verification">
<configuration><verify-metadata>true</verify-metadata><verify-signatures>false</verify-signatures></configuration>
<components><component group="local.audit" name="probe" version="1.0">
<artifact name="probe-1.0.jar"><sha256 value="%s"/></artifact>
<artifact name="probe-1.0.pom"><sha256 value="%s"/></artifact>
</component></components></verification-metadata>
''' % (jar_hash, hashlib.sha256(pom.read_bytes()).hexdigest()),encoding='utf-8')

env = dict(os.environ)
env['JAVA_HOME'] = str(next((ROOT / '.security-tools/jdk').iterdir()))
env['PATH'] = env['JAVA_HOME'] + '/bin;' + env['PATH']
env['GRADLE_USER_HOME'] = str(ROOT / '.gradle-local')
command = [str(ROOT / 'gradlew.bat'), '-p', str(FIXTURE), 'verifyProbe', '--offline', '--dependency-verification', 'strict', '--console=plain', '--no-daemon', '--max-workers=1', '-Dorg.gradle.jvmargs=-Xmx384m -Dfile.encoding=UTF-8']
results=[]
for label, digest, success in [('matching', hashlib.sha256(jar.read_bytes()).hexdigest(), True), ('mismatch', '0'*64, False)]:
    write_metadata(digest)
    process = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
    output = process.stdout.decode('utf-8',errors='replace')
    (FIXTURE / (label+'.log')).write_text(output,encoding='utf-8')
    rejected_checksum = 'verification failed' in output.lower() and ('checksum' in output.lower() or 'probe-1.0.jar' in output)
    assert (process.returncode == 0) if success else (process.returncode != 0 and rejected_checksum), output[-2500:]
    results.append({'case':label,'exit_code':process.returncode,'checksum_rejected':rejected_checksum,'log_sha256':hashlib.sha256(process.stdout).hexdigest()})
write_metadata(hashlib.sha256(jar.read_bytes()).hexdigest())
evidence={'date':'2026-10-27','scope':'isolated synthetic local Maven fixture only','external_network_requests':0,'results':results}
(FIXTURE / 'result.json').write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
print(json.dumps(evidence))
