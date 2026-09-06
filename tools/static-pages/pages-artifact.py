"""Bounded packaging and read-only verification for the two approved demo sites."""
import hashlib, json, os, pathlib, re, sys, tarfile, time, urllib.request, urllib.parse
from html.parser import HTMLParser
REPOS = ('AK_WeatherApp', 'ScheiberVueAppAbgabe')
CONFIG = b'const CONFIG = {"OPENWEATHER_API_KEY": "", "GOOGLE_MAPS_API_KEY": ""};\nwindow.CONFIG = CONFIG;\n'
NOTICE = '<aside id="deployment-mode-notice" role="status" style="padding:0.75rem;text-align:center;background:#fff3cd;color:#332701">Demo: Keine Live-Wetterdaten. Wetterdienste sind nicht eingerichtet.</aside>'
MAX_FILES, MAX_BYTES = 64, 10_000_000

def identity(repo, revision):
    if repo not in REPOS or not re.fullmatch('[a-f0-9]{40}', revision):
        raise RuntimeError('Unapproved deployment identity')

def safe_path(name):
    if name.startswith('./'): name = name[2:]
    if not re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*(?:/[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)?', name):
        raise RuntimeError('Unsafe artifact path')
    parts = name.split('/')
    if parts[0] not in ['index.html', 'script.js', 'style.css', 'config.js', 'images', 'assets']:
        raise RuntimeError('Unexpected artifact path')
    if len(parts) == 2 and parts[0] not in ['images', 'assets']:
        raise RuntimeError('Unexpected nested artifact path')
    return name

class Assets(HTMLParser):
    def __init__(self): super().__init__(); self.refs = []
    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        # These two fixed demo profiles use ordinary local asset references.
        # Base elements change browser URL resolution; responsive sources need
        # their own complete parser before this profile can admit them.
        if tag == 'base' or any(name in attrs for name in ['srcset', 'imagesrcset']):
            raise RuntimeError('Unreviewed asset URL resolution')
        if tag in ['script', 'link', 'img']:
            if len(attrs) != len(attributes):
                raise RuntimeError('Ambiguous duplicate asset attribute')
            ref = attrs.get('href' if tag == 'link' else 'src')
            if ref: self.refs.append(ref)

def validate_references(files):
    parser = Assets(); parser.feed(files.get('index.html', b'').decode('utf-8'))
    normalized = [safe_path(ref) for ref in parser.refs]
    if 'config.js' not in normalized or any(ref not in files for ref in normalized):
        raise RuntimeError('Unverified application reference')

def package(archive_path, destination, repo, revision):
    identity(repo, revision)
    source = pathlib.Path(archive_path)
    if source.stat().st_size > 11_000_000: raise RuntimeError('Archive exceeds bound')
    target = pathlib.Path(destination)
    if target.exists(): raise RuntimeError('Output must be fresh')
    files, seen, total = {}, set(), 0
    with tarfile.open(source, 'r:') as archive:
        for index, member in enumerate(archive):
            if index >= MAX_FILES or member.size < 0: raise RuntimeError('Artifact bounds exceeded')
            if member.name in ['.', './'] and member.isdir(): continue
            name = safe_path(member.name.rstrip('/') if member.isdir() else member.name)
            if name in seen: raise RuntimeError('Duplicate artifact entry')
            seen.add(name)
            if member.isdir():
                if name not in ['images', 'assets'] or member.size != 0: raise RuntimeError('Invalid directory')
                continue
            if not member.isfile(): raise RuntimeError('Links and special files forbidden')
            total += member.size
            if member.size > 2_000_000 or total > MAX_BYTES: raise RuntimeError('Artifact bounds exceeded')
            content = archive.extractfile(member).read(member.size + 1)
            if len(content) != member.size: raise RuntimeError('Incomplete archive member')
            files[name] = content
    if not {'index.html', 'script.js', 'style.css'} <= files.keys(): raise RuntimeError('Required file missing')
    html = files['index.html'].decode('utf-8')
    if html.count('<body>') != 1 or 'deployment-mode-notice' in html: raise RuntimeError('Unexpected page body')
    files['index.html'] = html.replace('<body>', '<body>' + NOTICE).encode()
    files['config.js'] = CONFIG
    validate_references(files)
    if len(files) > MAX_FILES or sum(map(len, files.values())) > MAX_BYTES: raise RuntimeError('Packaged bounds exceeded')
    metadata = {'schema': 1, 'mode': 'unconfigured-demo', 'head': revision, 'basePath': '/' + repo + '/', 'liveWeather': False,
                'files': {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, data in sorted(files.items())}}
    target.mkdir()
    for name, content in files.items():
        filename = target / name; filename.parent.mkdir(exist_ok=True); filename.write_bytes(content)
    (target / 'deployment.json').write_text(json.dumps(metadata, sort_keys=True))
    return metadata

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('Redirect forbidden')

def smoke(repo, revision, opener=None):
    identity(repo, revision)
    origin = 'https://t-scheiber.github.io/' + repo + '/'
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    total, count = 0, 0
    deadline = time.monotonic() + 120
    def get(name):
        nonlocal total, count
        if name != 'deployment.json': safe_path(name)
        count += 1
        if count > MAX_FILES + 1: raise RuntimeError('Request count bound exceeded')
        request = urllib.request.Request(origin + name, headers={'Cache-Control': 'no-cache'})
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise RuntimeError('Smoke deadline exceeded')
        with opener.open(request, timeout=min(10, remaining)) as response:
            if response.status != 200 or response.url != origin + name: raise RuntimeError('Unexpected response identity')
            body = response.read(2_000_001)
            total += len(body)
            if len(body) > 2_000_000 or total > MAX_BYTES + 100_000: raise RuntimeError('Response bounds exceeded')
            return body
    metadata = json.loads(get('deployment.json'))
    if set(metadata) != {'schema','mode','head','basePath','liveWeather','files'} or metadata['schema'] != 1 or metadata['mode'] != 'unconfigured-demo' or metadata['head'] != revision or metadata['basePath'] != '/' + repo + '/' or metadata['liveWeather'] is not False:
        raise RuntimeError('Deployment identity or mode differs')
    records = metadata['files']
    if not isinstance(records, dict) or not 4 <= len(records) <= MAX_FILES: raise RuntimeError('Invalid file manifest')
    files = {}
    for name, record in records.items():
        safe_path(name)
        if not isinstance(record, dict) or set(record) != {'bytes','sha256'} or type(record['bytes']) is not int or not 0 <= record['bytes'] <= 2_000_000 or not isinstance(record['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', record['sha256']): raise RuntimeError('Invalid file identity')
        data = get(name)
        if len(data) != record['bytes'] or hashlib.sha256(data).hexdigest() != record['sha256']: raise RuntimeError('Mixed or modified deployment')
        files[name] = data
    if files.get('config.js') != CONFIG: raise RuntimeError('Configuration must remain empty')
    html = files.get('index.html', b'').decode()
    if NOTICE not in html: raise RuntimeError('Visible demo notice missing')
    validate_references(files)
    return {'passed': True, 'repository': repo, 'revision': revision, 'mode': 'unconfigured-demo', 'filesVerified': len(files), 'redirectsAllowed': False, 'configContentsLogged': False}

if __name__ == '__main__':
    if sys.argv[1] == 'package': package(sys.argv[2], sys.argv[3], os.environ['PAGES_REPOSITORY'], os.environ['EXPECTED_SHA'])
    elif sys.argv[1] == 'smoke': print(json.dumps(smoke(os.environ['PAGES_REPOSITORY'], os.environ['EXPECTED_SHA'])))
    else: raise RuntimeError('Unknown operation')
