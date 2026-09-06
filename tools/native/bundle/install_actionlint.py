"""Anonymous exact public artifact transport. This does not authorize execution."""
import json
import os
from pathlib import Path
import sys
from bundle_transport import extract, require
from download_bundle import download_with_deadline
from verify import admission, read_file, digest

CONTROL = Path(__file__).resolve().parents[1]

def install(env=os.environ, download=download_with_deadline):
    admission(env)
    release = json.loads(read_file(CONTROL / 'policy/actionlint-release.json', 100000))
    require(release['state'] == 'published' and type(release['assetId']) is int and release['assetId'] == 547382486 and type(release['releaseId']) is int and release['releaseId'] == 383640029 and release.get('immutable') is True, 'ACTIONLINT_PUBLICATION_PENDING')
    require(release['repository'] == 't-scheiber/maintenance-workflows' and release['tag'] == 'actionlint-2026-09-06-r1' and release['name'] == 'actionlint-1.7.12-maintenance.1-linux-amd64.tar.gz', 'ACTIONLINT_RELEASE')
    manifest_path = CONTROL / 'policy/actionlint-transport.json'
    require(digest(manifest_path) == release['transportManifestSha256'], 'ACTIONLINT_MANIFEST')
    manifest = json.loads(read_file(manifest_path, 100000))
    root = Path(env['RUNNER_TEMP']) / 'actionlint'
    root.mkdir(mode=0o700)
    archive = root / 'bundle.tar.gz'
    download(release['assetId'], manifest, str(archive), source={'tag':release['tag'], 'name':release['name']})
    extract(archive, manifest, root / 'bundle')
    return root

if __name__ == '__main__':
    try:
        if len(sys.argv) != 1:
            raise ValueError()
        install()
    except Exception:
        print('Actionlint transport rejected', file=sys.stderr)
        sys.exit(1)
