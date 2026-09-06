# SPDX-License-Identifier: MIT
"""Anonymous fixed-repository asset transport, with no inference or execution."""
import hashlib
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
# -I -S excludes cwd/environment imports; only this reviewed sibling directory is
# explicitly added for our dependency-free transport module.
import pathlib
import sys
if __name__ == '__main__':
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from bundle_transport import require, entries, trusted_parent, Rejected

REPOSITORY = 't-scheiber/maintenance-workflows'
TIMEOUT_SECONDS = 120


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def open_http(url, timeout):
    # No netrc, cookies, authorization header or inherited proxy credentials.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, headers={
        'Accept': 'application/octet-stream',
        'User-Agent': 'personal-maintenance-bundle/1',
        'X-GitHub-Api-Version': '2026-03-10',
    })
    try:
        return opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        return error


def redirect_url(value):
    require(type(value) is str and len(value) <= 8192 and not any(ord(c) < 33 or ord(c) == 127 for c in value), 'DOWNLOAD_REDIRECT')
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == 'https' and parsed.netloc == 'release-assets.githubusercontent.com' and parsed.hostname == 'release-assets.githubusercontent.com' and not parsed.username and not parsed.password and not parsed.fragment and parsed.path.startswith('/'), 'DOWNLOAD_REDIRECT')
    return value


def source_url(asset_id, source):
    require(type(asset_id) is int and 1 <= asset_id < 2**63, 'ASSET_ID')
    if source is None:
        return f'https://api.github.com/repos/{REPOSITORY}/releases/assets/{asset_id}'
    require(type(source) is dict and set(source) == {'tag', 'name'}, 'DOWNLOAD_SOURCE')
    for value in source.values():
        require(type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,199}', value) is not None and '..' not in value, 'DOWNLOAD_SOURCE')
    return f"https://github.com/{REPOSITORY}/releases/download/{source['tag']}/{source['name']}"


def download(asset_id, manifest, destination, *, source=None, transport=open_http, now=time.monotonic):
    """Protected policy supplies the immutable asset tuple and manifest, never a URL."""
    entries(manifest)
    url = source_url(asset_id, source)
    started = now()

    def remaining():
        value = TIMEOUT_SECONDS - (now() - started)
        require(value > 0, 'DOWNLOAD_TIMEOUT')
        return min(30, value)

    parent = output = None
    response = None
    try:
        response = transport(url, remaining())
        remaining()
        if response.status == 302:
            next_url = redirect_url(response.headers.get('Location'))
            response.close()
            response = None
            response = transport(next_url, remaining())
            remaining()
        require(response.status == 200, 'DOWNLOAD_HTTP_STATUS')
        content_length = response.headers.get('Content-Length')
        if content_length is not None:
            require(content_length.isascii() and content_length.isdecimal() and int(content_length) == manifest['archiveBytes'], 'DOWNLOAD_LENGTH')
        require(response.headers.get('Content-Encoding', 'identity') == 'identity', 'DOWNLOAD_ENCODING')
        parent, leaf = trusted_parent(destination)
        output = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        hasher, count = hashlib.sha256(), 0
        while True:
            remaining()
            block = response.read(min(1024 * 1024, manifest['archiveBytes'] - count + 1))
            remaining()
            if not block:
                break
            count += len(block)
            require(count <= manifest['archiveBytes'], 'DOWNLOAD_BOUNDS')
            hasher.update(block)
            view = memoryview(block)
            while view:
                written = os.write(output, view)
                require(written > 0, 'DOWNLOAD_WRITE')
                view = view[written:]
        require(count == manifest['archiveBytes'] and hasher.hexdigest() == manifest['archiveSha256'], 'DOWNLOAD_CHECKSUM')
        return {'version': 1, 'status': 'DOWNLOAD_VERIFIED_ONLY', 'repository': REPOSITORY, 'assetId': asset_id, 'bytes': count, 'sha256': hasher.hexdigest(), 'authenticated': False, 'nativeAdmissionRequired': True}
    finally:
        if response is not None:
            response.close()
        if output is not None:
            os.close(output)
        if parent is not None:
            os.close(parent)


def run_bounded_worker(command, payload, timeout=TIMEOUT_SECONDS):
    """Internal primitive. The production command below is fixed trusted code."""
    import subprocess
    import json
    require(type(payload) is bytes and len(payload) <= 2_000_000, 'WORKER_INPUT_BOUNDS')
    try:
        result = subprocess.run(command, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
    except subprocess.TimeoutExpired:
        # subprocess.run kills and waits for the child before raising. The worker
        # creates no child processes and cannot survive to finish a timed-out file.
        raise Rejected('DOWNLOAD_TIMEOUT') from None
    require(len(result.stdout) <= 4096 and not result.stderr, 'WORKER_OUTPUT_BOUNDS')
    try:
        record = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise Rejected('WORKER_OUTPUT_INVALID') from None
    require(type(record) is dict, 'WORKER_OUTPUT_INVALID')
    if result.returncode:
        code = record.get('code')
        require(type(code) is str and __import__('re').fullmatch('[A-Z_]{1,60}', code), 'WORKER_OUTPUT_INVALID')
        raise Rejected(code)
    return record


def download_with_deadline(asset_id, manifest, destination, *, source=None):
    """Production entry: parent enforces wall time even for a trickling server."""
    import json
    import pathlib
    import sys
    entries(manifest)
    source_url(asset_id, source)
    payload = json.dumps({'assetId': asset_id, 'manifest': manifest, 'destination': destination, 'source': source}, separators=(',', ':')).encode('utf8')
    result = run_bounded_worker([sys.executable, '-I', '-S', str(pathlib.Path(__file__).resolve()), '--worker'], payload)
    expected = {'version': 1, 'status': 'DOWNLOAD_VERIFIED_ONLY', 'repository': REPOSITORY,
                'assetId': asset_id, 'bytes': manifest['archiveBytes'], 'sha256': manifest['archiveSha256'],
                'authenticated': False, 'nativeAdmissionRequired': True}
    require(result == expected, 'WORKER_RECEIPT_MISMATCH')
    return result


def worker_main():
    import json
    import re
    import sys
    try:
        require(sys.argv[1:] == ['--worker'], 'WORKER_ARGUMENTS')
        payload = sys.stdin.buffer.read(2_000_001)
        require(len(payload) <= 2_000_000, 'WORKER_INPUT_BOUNDS')
        item = json.loads(payload)
        require(type(item) is dict and set(item) in ({'assetId', 'manifest', 'destination'}, {'assetId', 'manifest', 'destination', 'source'}), 'WORKER_ARGUMENTS')
        result = download(item['assetId'], item['manifest'], item['destination'], source=item.get('source'))
        sys.stdout.write(json.dumps(result, separators=(',', ':')) + '\n')
        return 0
    except BaseException as error:
        code = str(error) if isinstance(error, Rejected) and re.fullmatch('[A-Z_]{1,60}', str(error)) else 'DOWNLOAD_TRANSPORT_FAILURE'
        sys.stdout.write(json.dumps({'status': 'BLOCK', 'code': code}) + '\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(worker_main())
