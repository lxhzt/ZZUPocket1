"""Bounded public-resource GET review; no login, cookie replay, redirects or crawling."""
import argparse
import hashlib
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APPROVED = {
    'https://cas.s.zzu.edu.cn/token/jwt/publicKey',
    'https://cas.s.zzu.edu.cn/cas/a/login?service=https%3A%2F%2Fjwxt.zzu.edu.cn%2Fstudent%2Fsso%2Flogin',
    'https://jwxt.zzu.edu.cn/uniapp/index.html',
    'https://gmsstu.zzu.edu.cn/stu/',
    'https://ecard.v.zzu.edu.cn/',
    # Explicit script tags observed in the corresponding public HTML on 2026-10-28.
    'https://jwxt.zzu.edu.cn/uniapp/static/js/index.fb0cf6d5.js',
    'https://ecard.v.zzu.edu.cn/static/js/index.c1a092dd.js',
    # Official open-platform application instructions found through the network centre.
    'https://www5.zzu.edu.cn/net/info/1096/2774.htm',
    'https://open.s.zzu.edu.cn/',
    'https://open.s.zzu.edu.cn/dev-portal/',
    'https://www5.zzu.edu.cn/net/zhengzhoudaxuekaifangpingtaishiyongshenpibiao.pdf',
    'https://www5.zzu.edu.cn/system/_content/download.jsp?owner=1327566538&urltype=news.DownloadAttachUrl&wbfileid=15019196',
    'https://open.s.zzu.edu.cn/dev-portal/static/js/app.75e4b850.js',
    'https://open.s.zzu.edu.cn/dev-portal/serverConfig.json',
    # Documentation destinations constructed explicitly by the public portal script/config.
    'https://open.s.zzu.edu.cn/docs/index.html',
    'https://poa.s.zzu.edu.cn/_docs/authz/v1/latest/',
    'https://poa.s.zzu.edu.cn/_docs/idToken/v1/latest/',
    'https://poa.s.zzu.edu.cn/_docs/authz/v1/latest/authz-v1-2025_03_08_01_27_38.yaml',
    'https://poa.s.zzu.edu.cn/_docs/idToken/v1/latest/idToken-v1-2025_03_25_13_28_26.yaml',
    'https://open.s.zzu.edu.cn/docs/newguide/3.technology.md',
    'https://open.s.zzu.edu.cn/docs/newguide/5.access.md',
    'https://open.s.zzu.edu.cn/docs/newguide/1.introduce.md',
    'https://open.s.zzu.edu.cn/docs/newguide/6.openAPI.md',
    'https://poa.s.zzu.edu.cn/_docs',
    'https://poa.s.zzu.edu.cn/_docs/',
    'https://poa.s.zzu.edu.cn/_docs/dataMarket/v1/latest/',
    'https://poa.s.zzu.edu.cn/_docs/date/v1/latest/',
    'https://poa.s.zzu.edu.cn/_docs/dataMarket/v1/latest/dataMarket-v1-2025_02_13_14_13_52.yaml',
    'https://poa.s.zzu.edu.cn/_docs/date/v3/latest/',
    'https://poa.s.zzu.edu.cn/_docs/date/v3/latest/date-v3-2023_05_17_17_02_37.yaml',
}
MAX_BODY = 3 * 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_REQUESTS = 8


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ScriptLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sources = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'script':
            src = dict(attrs).get('src')
            if src:
                self.sources.append(src)


def cookie_attributes(raw):
    parts = raw.split(';')
    attributes = {}
    for part in parts[1:]:
        key, _, value = part.strip().partition('=')
        attributes[key.lower()] = value
    return {'name': parts[0].split('=', 1)[0].strip(),
            'secure': 'secure' in attributes, 'http_only': 'httponly' in attributes,
            'same_site': attributes.get('samesite'), 'domain': attributes.get('domain'),
            'path': attributes.get('path')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('urls', nargs='+')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', args.run_id):
        parser.error('Invalid run ID')
    for url in args.urls:
        parsed = urllib.parse.urlsplit(url)
        if url not in APPROVED or parsed.scheme != 'https' or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment:
            parser.error('Only individually reviewed exact HTTPS resources are allowed')
    out = ROOT / '.security-tools' / 'credential-review-20261028' / args.run_id
    out.mkdir(parents=True, exist_ok=True)
    ledger = out / 'requests.json'
    records = json.loads(ledger.read_text(encoding='utf-8')) if ledger.exists() else []
    if len(records) + len(args.urls) > MAX_REQUESTS:
        parser.error('Per-run request budget exceeded')
    if any(record.get('error') for record in records):
        parser.error('This run already stopped on an error')
    if len({*args.urls}) != len(args.urls) or any(row['url'] in args.urls for row in records):
        parser.error('No duplicate fetches or automatic retries')
    total = sum(row.get('bytes', 0) for row in records)
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    for url in args.urls:
        time.sleep(1)
        record = {'url': url, 'method': 'GET', 'at_utc': datetime.now(timezone.utc).isoformat()}
        started = time.monotonic()
        try:
            request = urllib.request.Request(url, headers={
                'User-Agent': 'ZZUPocket-Public-Credential-Review/1.0',
                'Accept': 'text/html,application/javascript,text/plain;q=0.8,*/*;q=0.1',
                'Accept-Encoding': 'identity',
            }, method='GET')
            try:
                response = opener.open(request, timeout=12)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                record['status'] = response.code
                record['headers'] = {key: value for key, value in response.headers.items()
                                     if key.lower() in {'content-type', 'content-length', 'location', 'cache-control',
                                                        'strict-transport-security', 'x-content-type-options', 'x-frame-options'}}
                record['set_cookie_attributes'] = [cookie_attributes(value) for value in response.headers.get_all('Set-Cookie', [])]
                data = bytearray()
                if not 300 <= response.code < 400:
                    while True:
                        if time.monotonic() - started > 20:
                            raise TimeoutError('Per-response time budget exceeded')
                        chunk = response.read(min(65536, MAX_BODY + 1 - len(data), MAX_TOTAL + 1 - total - len(data)))
                        if not chunk:
                            break
                        data.extend(chunk)
                        if len(data) > MAX_BODY or total + len(data) > MAX_TOTAL:
                            raise ValueError('Response byte budget exceeded')
                record['bytes'] = len(data)
                total += len(data)
                record['sha256'] = hashlib.sha256(data).hexdigest()
                filename = hashlib.sha256(url.encode()).hexdigest()[:16] + '.body'
                (out / filename).write_bytes(data)
                record['local_file'] = filename
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' in content_type:
                    links = ScriptLinks()
                    links.feed(data.decode('utf-8', errors='replace'))
                    record['script_sources_not_fetched'] = [urllib.parse.urljoin(url, src) for src in links.sources]
                record['contains_public_pem_marker'] = b'-----BEGIN PUBLIC KEY-----' in data or b'-----BEGIN RSA PUBLIC KEY-----' in data
                if response.code >= 400:
                    record['error'] = 'HTTP error; run stopped without retry'
        except Exception as error:
            record['error'] = type(error).__name__ + ': ' + str(error)
        record['elapsed_seconds'] = round(time.monotonic() - started, 3)
        records.append(record)
        ledger.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding='utf-8')
        print(json.dumps(record, ensure_ascii=True), flush=True)
        if 'error' in record:
            return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
