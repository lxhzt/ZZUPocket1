"""GitHub Actions publisher for the already signed launch APK; never rebuilds or signs.

Only the immutable triggering commit of lxhzt/ZZUPocket1 is read. The temporary
Actions token is sent only to GitHub's API/upload hosts and is never printed.
Existing releases are never replaced, edited or deleted by a repeated run.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = 'lxhzt/ZZUPocket1'
TAG = 'v0.33.0-launch.1'
APK_NAME = 'ZZUPocket-0.33.0-launch.1.apk'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    sha = os.environ.get('GITHUB_SHA', '')
    if os.environ.get('GITHUB_REPOSITORY') != REPOSITORY or not re.fullmatch('[a-f0-9]{40}', sha):
        raise RuntimeError('This publisher is restricted to the reviewed repository and immutable commit')
    token = os.environ['GITHUB_TOKEN']
    opener = urllib.request.build_opener(NoRedirect())

    def request(url, method='GET', data=None, content_type='application/json', authenticated=False):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or parsed.port not in (None, 443) or parsed.username or parsed.password:
            raise RuntimeError('Invalid GitHub transport')
        headers = {'User-Agent': 'ZZUPocket-launch-publisher', 'Content-Type': content_type}
        if authenticated:
            if parsed.hostname not in ('api.github.com', 'uploads.github.com'):
                raise RuntimeError('Refusing to send authorization outside the GitHub API')
            if not parsed.path.startswith('/repos/' + REPOSITORY + '/'):
                raise RuntimeError('Refusing another repository')
            headers.update({'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                            'X-GitHub-Api-Version': '2022-11-28'})
        elif parsed.hostname != 'raw.githubusercontent.com' or not parsed.path.startswith('/' + REPOSITORY + '/' + sha + '/'):
            raise RuntimeError('Only this immutable commit may supply release files')
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with opener.open(req, timeout=90) as response:
            body = response.read(16 * 1024 * 1024 + 1)
            if len(body) > 16 * 1024 * 1024:
                raise RuntimeError('Release response too large')
            return body

    api = 'https://api.github.com/repos/' + REPOSITORY + '/releases'
    try:
        request(api + '/tags/' + TAG, authenticated=True)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    else:
        raise RuntimeError('This release already exists; inspect it instead of replacing any artifact')

    def raw(path):
        return request('https://raw.githubusercontent.com/' + REPOSITORY + '/' + sha + '/' + path)

    apk = raw('downloads/' + APK_NAME)
    checksums = raw('downloads/SHA256SUMS.txt')
    metadata_bytes = raw('docs/security-evidence/launch-20261028.json')
    metadata = json.loads(metadata_bytes)
    digest = hashlib.sha256(apk).hexdigest()
    if metadata['apk_name'] != APK_NAME or metadata['apk_sha256'] != digest or metadata['apk_bytes'] != len(apk):
        raise RuntimeError('APK metadata mismatch')
    if checksums.decode('ascii').strip() != digest + '  ' + APK_NAME:
        raise RuntimeError('APK checksum mismatch')
    if not metadata['prerelease'] or metadata['debuggable'] or not metadata['signature_v2_verified'] or not metadata['signature_v3_verified']:
        raise RuntimeError('Launch publication gate failed')
    notes = raw('docs/launch-0.33.0-launch.1.md').decode('utf-8')
    payload = {'tag_name': TAG, 'target_commitish': sha, 'name': 'ZZUPocket 0.33.0-launch.1 · 首个侧载测试版',
               'body': notes + '\n\nSource commit: `' + sha + '`\n', 'draft': True,
               'prerelease': True, 'make_latest': 'false'}
    release = json.loads(request(api, method='POST', data=json.dumps(payload).encode(), authenticated=True))
    upload = release['upload_url'].split('{', 1)[0]
    assets = [(APK_NAME, apk, 'application/vnd.android.package-archive'),
              ('SHA256SUMS.txt', checksums, 'text/plain'),
              ('launch-20261028.json', metadata_bytes, 'application/json')]
    for name, body, mime in assets:
        result = json.loads(request(upload + '?name=' + urllib.parse.quote(name), method='POST',
                                    data=body, content_type=mime, authenticated=True))
        if result.get('state') != 'uploaded' or result.get('size') != len(body):
            raise RuntimeError('Uploaded release asset does not match: ' + name)
        if result.get('digest') and result['digest'] != 'sha256:' + hashlib.sha256(body).hexdigest():
            raise RuntimeError('GitHub release asset digest mismatch: ' + name)
    final = json.loads(request(api + '/' + str(release['id']), method='PATCH',
                              data=json.dumps({'draft': False, 'prerelease': True, 'make_latest': 'false'}).encode(),
                              authenticated=True))
    if final['draft'] or not final['prerelease']:
        raise RuntimeError('Unexpected published release state')
    print(final['html_url'])
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        Path(os.environ['GITHUB_STEP_SUMMARY']).write_text('Published prerelease: ' + final['html_url'] + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
