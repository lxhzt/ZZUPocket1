import contextlib
import hashlib
import importlib.util
import io
import json
import os
import urllib.error
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('publisher', 'tools/publish-launch-release.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
APK = b'synthetic-signed-artifact-for-publisher-control-flow-only'
DIGEST = hashlib.sha256(APK).hexdigest()
META = {'apk_name': p.APK_NAME, 'apk_sha256': DIGEST, 'apk_bytes': len(APK),
        'prerelease': True, 'debuggable': False, 'signature_v2_verified': True,
        'signature_v3_verified': True}


class Body:
    def __init__(self, data): self.data = data
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, limit): return self.data[:limit]


def case(mode):
    calls = []
    class Opener:
        def open(self, req, timeout):
            url = req.full_url
            calls.append((req.method, url))
            if 'raw.githubusercontent.com' in url:
                assert req.get_header('Authorization') is None
                if url.endswith('.apk'): data = APK
                elif url.endswith('SHA256SUMS.txt'):
                    data = ((DIGEST if mode != 'bad-digest' else '0' * 64) + '  ' + p.APK_NAME).encode()
                elif url.endswith('.json'): data = json.dumps(META).encode()
                else: data = b'Prerelease notes'
                return Body(data)
            assert req.get_header('Authorization') == 'Bearer synthetic-fixture-token'
            if '/tags/' in url:
                if mode == 'existing': return Body(b'{}')
                raise urllib.error.HTTPError(url, 404, 'not found', {}, None)
            if req.method == 'POST' and '/assets?' not in url:
                payload = json.loads(req.data)
                assert payload['draft'] is True and payload['prerelease'] is True
                data = {'id': 123, 'upload_url': 'https://uploads.github.com/repos/lxhzt/ZZUPocket1/releases/123/assets{?name,label}'}
            elif '/assets?' in url:
                data = {'state': 'uploaded', 'size': len(req.data), 'digest': 'sha256:' + hashlib.sha256(req.data).hexdigest()}
            elif req.method == 'PATCH':
                assert len([x for x in calls if '/assets?' in x[1]]) == 3
                data = {'draft': False, 'prerelease': True, 'html_url': 'https://github.com/lxhzt/ZZUPocket1/releases/tag/' + p.TAG}
            else: raise AssertionError('Unexpected request')
            return Body(json.dumps(data).encode())
    env = {'GITHUB_SHA': 'a' * 40, 'GITHUB_REPOSITORY': p.REPOSITORY,
           'GITHUB_TOKEN': 'synthetic-fixture-token'}
    with patch.dict(os.environ, env, clear=True), patch.object(p.urllib.request, 'build_opener', return_value=Opener()), contextlib.redirect_stdout(io.StringIO()):
        try:
            p.main()
        except RuntimeError:
            assert mode in ('existing', 'bad-digest')
            assert not any(method != 'GET' for method, url in calls)
        else:
            assert mode == 'success'
            assert calls[-1][0] == 'PATCH'


for mode in ('success', 'existing', 'bad-digest'):
    case(mode)
print(json.dumps({'publisher_control_flow_cases': 3, 'passed': True, 'actual_network_requests': 0,
                  'note': 'Mocked publisher flow is not APK signature or GitHub permission verification.'}))
