# SPDX-License-Identifier: MIT
"""Fixed public source-free verification. Pending evidence never authorizes source scanning."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import subprocess
import sys
import uuid

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent))
from bundle_transport import extract, require, Rejected, trusted_parent
from download_bundle import download_with_deadline

CONTROL = Path(__file__).resolve().parents[1]
TOOLS = ('gitleaks', 'osv-scanner', 'trivy')
SCANNER_SHA = 'd60fd11532d37ffcfd73b71de9cd09159f337aaaf6ad7d28a0d9c8870d4657fc'
IMAGE = 'ghcr.io/t-scheiber/maintenance-node22@sha256:d1b5969e9da2c6e33e31bef573f545b295141cfe472014671266fae60d57df1a'
CONFIG = 'sha256:ca49327eeb7f23030ed01514f29e08f2bb6b9d54eaef2cd34d2ab7f61e65aefd'
DB_LIMIT = 2_000_000_000


def open_input(path):
    # The scanner may create cache children. Do not follow a replaced parent
    # directory when the host later binds DB bytes or reads a report.
    parent, leaf = trusted_parent(str(path))
    try:
        return os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)


def read_file(path, limit):
    fd = open_input(path)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit, 'FILE_BOUNDS')
        parts, count = [], 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, limit - count + 1))
            if not chunk:
                break
            count += len(chunk)
            require(count <= limit, 'FILE_BOUNDS')
            parts.append(chunk)
        after = os.fstat(fd)
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns) and count == before.st_size, 'FILE_CHANGED')
        return b''.join(parts)
    finally:
        os.close(fd)


def digest(path, limit=400_000_000):
    fd = open_input(path)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit, 'FILE_BOUNDS')
        total, result = 0, hashlib.sha256()
        while True:
            chunk = os.read(fd, min(1024 * 1024, limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            require(total <= limit, 'FILE_BOUNDS')
            result.update(chunk)
        after = os.fstat(fd)
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns) and total == before.st_size, 'FILE_CHANGED')
        return result.hexdigest()
    finally:
        os.close(fd)


def make_runtime_archive_readable(path):
    # The host runner and the non-root scanner use different UIDs. The archive
    # contains public source-free runtime bytes and has already passed identity.
    fd = open_input(path)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 1_500_000_000, 'RUNTIME_ARCHIVE_TYPE')
        os.fchmod(fd, 0o444)
        require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o444, 'RUNTIME_ARCHIVE_MODE')
    finally:
        os.close(fd)


def write_json(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def admission(env):
    repositories = {'t-scheiber/AK_WeatherApp':'755321462', 't-scheiber/ScheiberVueAppAbgabe':'755319788', 't-scheiber/maintenance-workflows':'1359178236'}
    repo = env.get('GITHUB_REPOSITORY')
    require(env.get('GITHUB_ACTIONS') == 'true' and repo in repositories and env.get('GITHUB_REPOSITORY_ID') == repositories[repo] and env.get('GITHUB_REPOSITORY_OWNER_ID') == '66697291' and env.get('PUBLIC_REPOSITORY_PRIVATE') == 'false', 'WORKFLOW_ADMISSION')
    require(all(re.fullmatch('[a-f0-9]{40}', env.get(key,'')) for key in ('GITHUB_SHA','PUBLIC_TOOLS_REF')), 'REVISION')
    require(all(re.fullmatch('[1-9][0-9]{0,19}', env.get(key,'')) for key in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT')), 'RUN_ID')
    if repo == 't-scheiber/maintenance-workflows':
        require(env.get('GITHUB_EVENT_NAME') in ('push','pull_request'), 'PUBLIC_CONTROL_EVENT')
        if env['GITHUB_EVENT_NAME'] == 'pull_request':
            require(env.get('PUBLIC_HEAD_REPOSITORY_ID') == repositories[repo], 'PUBLIC_CONTROL_HEAD')
    else:
        require(env.get('GITHUB_REF') == 'refs/heads/main' and env.get('PUBLIC_DEFAULT_BRANCH') == 'main' and env.get('STATIC_PAGES_ENABLED') == 'true', 'PUBLIC_CALLER_BRANCH')
        require(env.get('GITHUB_EVENT_NAME') == 'push' or (env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and env.get('GITHUB_ACTOR') == env.get('GITHUB_TRIGGERING_ACTOR') == 't-scheiber'), 'PUBLIC_CALLER_EVENT')
    require(not any(env.get(k) for k in ('GH_TOKEN', 'GITHUB_TOKEN', 'OPENROUTER_API_KEY', 'MAINTENANCE_APP_PRIVATE_KEY', 'ACTIONS_RUNTIME_TOKEN')), 'CREDENTIAL_ENVIRONMENT')
    base = Path(env.get('RUNNER_TEMP', ''))
    require(base.is_absolute() and base.is_dir() and not base.is_symlink(), 'RUNNER_DIRECTORY')
    fd, _ = trusted_parent(str(base / 'native-bundle-verification'))
    os.close(fd)
    return base / 'native-bundle-verification'


def checked_release():
    item = json.loads(read_file(CONTROL / 'policy/native-bundle-release.json', 100000))
    require(item.get('version') == 1 and item.get('repository') == 't-scheiber/maintenance-workflows', 'RELEASE_IDENTITY')
    require(type(item.get('assetId')) is int and item['assetId'] == 547257811, 'ASSET_ID')
    require(item.get('releaseId') == 383603888 and item.get('immutable') is True and item.get('source') == {'tag':'native-scanners-2026-09-06-r1','name':'native-scanners-20260906-linux-amd64.tar.gz'}, 'RELEASE_SOURCE')
    require(item.get('image') == IMAGE and item.get('imageConfig') == CONFIG, 'TRANSPORT_IMAGE')
    require(item.get('scanner') == {'version': '0.74.0+maintenance.1', 'sha256': SCANNER_SHA}, 'SCANNER_IDENTITY')
    raw = read_file(CONTROL / 'policy/native-bundle-transport.json', 2000000)
    require(hashlib.sha256(raw).hexdigest() == item.get('transportManifestSha256'), 'TRANSPORT_MANIFEST')
    return item, json.loads(raw)


def process(command, env, stdout, stderr, timeout, file_limit=32_000_000):
    require(file_limit in (32_000_000, 2_000_000_000), 'PROCESS_FILE_LIMIT')
    # Captured files are operator-owned, never paths in a scanner/source mount.
    with stdout.open('xb') as out, stderr.open('xb') as err:
        try:
            result = subprocess.run(command, env=env, stdout=out, stderr=err, timeout=timeout,
                                    preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit)))
            return result.returncode
        except subprocess.TimeoutExpired:
            raise Rejected('PROCESS_TIMEOUT') from None


def prepare_command_path(directory):
    require(directory.is_dir() and not directory.is_symlink() and not any(directory.iterdir()), 'COMMAND_DIRECTORY')
    for name in ('docker', 'tar'):
        target = Path('/usr/bin') / name
        require(target.is_file(), 'TRUSTED_EXECUTABLE')
        (directory / name).symlink_to(target)


def container_args(image, scanner, cache, name, network='none', mounts=()):
    require(image == IMAGE and network in ('none', 'bridge'), 'CONTAINER_IDENTITY')
    args = ['docker', 'run', '--rm', '--name', name, '--platform', 'linux/amd64',
            '--network', network, '--ulimit', f'fsize={DB_LIMIT}:{DB_LIMIT}', '--read-only', '--user', '1000:1000', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--cpus', '2', '--memory', '2g', '--pids-limit', '128',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m', '--workdir', '/tmp', '--env', 'HOME=/tmp',
            '--mount', f'type=bind,src={scanner},dst=/scanner,readonly',
            '--mount', f'type=bind,src={cache},dst=/cache' + (',readonly' if network == 'none' else '')]
    for source, destination in mounts:
        require(destination in ('/input', '/runtime.tar.gz', '/config'), 'MOUNT_DESTINATION')
        args += ['--mount', f'type=bind,src={source},dst={destination},readonly']
    return args + ['--entrypoint', '/scanner', image]


def vulnerability_args(mode):
    """Only image archives or source-free binary rootfs inputs are admitted."""
    require(mode in ('runtime', 'native'), 'SCAN_MODE')
    common = ['--skip-db-update', '--offline-scan', '--no-progress', '--config', '/config/trivy.yaml',
              '--ignorefile', '/config/ignore', '--cache-dir', '/cache', '--cache-backend', 'memory',
              '--scanners', 'vuln', '--list-all-pkgs', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
              '--exit-code', '0', '--format', 'json']
    return ['image', '--input', '/runtime.tar.gz', *common] if mode == 'runtime' else ['rootfs', *common, '/input']


def verify():
    root = admission(os.environ)
    root.mkdir(mode=0o700)
    artifacts = root / 'artifacts'
    artifacts.mkdir()
    write_json(artifacts / 'initial.json', {'status': 'BLOCK', 'reason': 'VERIFICATION_NOT_COMPLETED'})
    state = {'version': 1, 'status': 'BLOCK', 'stage': 'release', 'adoption': False,
             'sourceRevision': os.environ['GITHUB_SHA'], 'runId': os.environ['GITHUB_RUN_ID'], 'runAttempt': int(os.environ['GITHUB_RUN_ATTEMPT']), 'toolsRevision': os.environ['PUBLIC_TOOLS_REF']}
    try:
        release, manifest = checked_release()
        archive = root / 'bundle.tar.gz'
        state['stage'] = 'download'
        write_json(artifacts / 'download.json', download_with_deadline(release['assetId'], manifest, str(archive), source=release['source']))
        state['stage'] = 'extract'
        observations = root / 'observations'
        write_json(artifacts / 'transport.json', extract(str(archive), manifest, str(observations)))
        scanner = observations / 'evidence/trivy/binary'
        require(digest(scanner) == SCANNER_SHA, 'SCANNER_BYTES')
        # Preserve all original scanner observations as immutable files. License and
        # binary bytes were verified by transport but are not uploaded redundantly.
        shutil.copytree(observations / 'evidence', artifacts / 'original', ignore=shutil.ignore_patterns('binary'))
        state['stage'] = 'transport-image'
        docker_bin, docker_config = root / 'docker-bin', root / 'docker-config'
        docker_bin.mkdir(); docker_config.mkdir()
        prepare_command_path(docker_bin)
        env = {'PATH': str(docker_bin), 'DOCKER_CONFIG': str(docker_config), 'LANG': 'C.UTF-8'}
        def host(args, label, timeout=120):
            code = process(args, env, root / (label + '.stdout'), root / (label + '.stderr'), timeout, 2_000_000_000 if label == 'archive' else 32_000_000)
            require(code == 0, 'HOST_COMMAND')
            return read_file(root / (label + '.stdout'), 2000000)
        host(['docker', 'pull', '--platform', 'linux/amd64', IMAGE], 'pull', 180)
        inspection = json.loads(host(['docker', 'image', 'inspect', IMAGE], 'inspect'))
        require(len(inspection) == 1 and inspection[0]['Architecture'] == 'amd64' and inspection[0]['Os'] == 'linux', 'IMAGE_IDENTITY')
        execution_image = inspection[0]['Id']
        require(re.fullmatch('sha256:[a-f0-9]{64}', execution_image) is not None, 'IMAGE_IDENTITY')
        node = os.environ.get('NODE_EXECUTABLE', '')
        require(Path(node).is_absolute() and Path(node).is_file(), 'NODE_EXECUTABLE')
        node_helper = str(CONTROL / 'native-hosted.mjs')
        runtime_archive = root / 'runtime.tar.gz'
        archive_record = json.loads(host([node, node_helper, 'save', execution_image, str(runtime_archive)], 'archive', 240))
        require(archive_record['imageId'] == CONFIG, 'IMAGE_CONFIG')
        make_runtime_archive_readable(runtime_archive)
        write_json(artifacts / 'runtime-archive.json', archive_record)
        cache = root / 'database'
        cache.mkdir(mode=0o777); cache.chmod(0o777)
        scan_config = root / 'scan-config'
        scan_config.mkdir()
        (scan_config / 'trivy.yaml').write_text('{}\n')
        (scan_config / 'ignore').write_text('')
        def scan(arguments, label, network='none', mounts=()):
            name = 'maintenance-native-' + uuid.uuid4().hex
            command = container_args(IMAGE, scanner, cache, name, network, (*mounts, (scan_config, '/config'))) + arguments
            try:
                return process(command, env, root / (label + '.stdout'), root / (label + '.stderr'), 600)
            finally:
                subprocess.run(['docker', 'rm', '-f', name], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        state['stage'] = 'database'
        require(scan(['image', '--config', '/config/trivy.yaml', '--ignorefile', '/config/ignore', '--cache-dir', '/cache', '--download-db-only'], 'database-download', 'bridge') == 0, 'DATABASE_DOWNLOAD')
        database = json.loads(read_file(cache / 'db/metadata.json', 100000))
        database['sha256'] = digest(cache / 'db/trivy.db', DB_LIMIT)
        database['bytes'] = (cache / 'db/trivy.db').stat().st_size
        write_json(artifacts / 'database.json', database)
        state['stage'] = 'runtime-scan'
        code = scan(vulnerability_args('runtime'), 'runtime-scan', mounts=((runtime_archive, '/runtime.tar.gz'),))
        shutil.copyfile(root / 'runtime-scan.stdout', artifacts / 'runtime-report.json')
        shutil.copyfile(root / 'runtime-scan.stderr', artifacts / 'runtime-stderr.log')
        coverage = json.loads(host([node, node_helper, 'runtime', str(root / 'runtime-scan.stdout'), str(root / 'runtime-scan.stderr'), str(code), str(scanner)], 'runtime-validation'))
        write_json(artifacts / 'runtime-coverage.json', coverage)
        state['stage'] = 'native-scans'
        pending = []
        controls = root / 'controls'
        (controls / 'maintenance').mkdir(parents=True)
        (controls / 'maintenance/policy').mkdir()
        for filename in ('native-cli.mjs', 'native-admission.mjs', 'native-evidence.mjs'):
            shutil.copyfile(CONTROL / filename, controls / 'maintenance' / filename)
        shutil.copyfile(CONTROL / 'policy/native-scanners.pending.json', controls / 'maintenance/policy/native-scanners.pending.json')
        for tool in TOOLS:
            fresh = root / 'fresh' / tool
            fresh.mkdir(parents=True)
            for name in ('graph.jsonl', 'manifest.json', 'build-info.txt', 'pclntab.json', 'advisory.json', 'provenance.json'):
                shutil.copyfile(observations / 'evidence' / tool / name, fresh / name)
            binary = observations / 'evidence' / tool / 'binary'
            os.link(binary, fresh / 'binary')
            inputs = root / ('input-' + tool)
            inputs.mkdir(); os.link(binary, inputs / tool)
            started = datetime.datetime.now(datetime.timezone.utc).isoformat()
            code = scan(vulnerability_args('native'), tool, mounts=((inputs, '/input'),))
            finished = datetime.datetime.now(datetime.timezone.utc).isoformat()
            shutil.copyfile(root / (tool + '.stdout'), fresh / 'report.json')
            shutil.copyfile(root / (tool + '.stderr'), fresh / 'stderr.log')
            require(digest(cache / 'db/trivy.db', DB_LIMIT) == database['sha256'], 'DATABASE_CHANGED')
            write_json(fresh / 'execution.json', {'status': code, 'platform': 'linux/amd64', 'binarySha256': digest(binary),
                       'scannerSha256': SCANNER_SHA, 'runtimeConfig': CONFIG, 'reportSha256': digest(fresh / 'report.json'),
                       'stderrSha256': digest(fresh / 'stderr.log'), 'sourceMounted': False, 'credentialsPassed': False,
                       'network': 'none', 'repository': os.environ['GITHUB_REPOSITORY'], 'runId': os.environ['GITHUB_RUN_ID'], 'runAttempt': int(os.environ['GITHUB_RUN_ATTEMPT']), 'sourceRevision': os.environ['GITHUB_SHA'], 'toolsRevision': os.environ['PUBLIC_TOOLS_REF'], 'startedAt': started, 'finishedAt': finished, 'database': database})
            # The protected CLI runs in the admitted Node22 image, with only
            # protected helper files and public binary evidence mounted read-only.
            name = 'maintenance-native-cli-' + uuid.uuid4().hex
            args = ['docker', 'run', '--rm', '--name', name, '--platform', 'linux/amd64', '--network', 'none', '--read-only',
                    '--user', '1000:1000', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--cpus', '1', '--memory', '1g', '--pids-limit', '64',
                    '--mount', f'type=bind,src={controls}/maintenance,dst=/control/maintenance,readonly',
                    '--mount', f'type=bind,src={fresh},dst=/evidence,readonly', '--entrypoint', 'node', IMAGE,
                    '/control/maintenance/native-cli.mjs', '--tool', tool, '--evidence-root', '/evidence']
            try:
                cli_code = process(args, env, root / (tool + '-cli.stdout'), root / (tool + '-cli.stderr'), 120)
            finally:
                subprocess.run(['docker', 'rm', '-f', name], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            result = json.loads(host([node, node_helper, 'pending', str(cli_code), str(root / (tool + '-cli.stdout')), str(root / (tool + '-cli.stderr')), tool], tool + '-pending'))
            write_json(fresh / 'pending.json', result)
            pending.append({'tool': tool, 'status': result['status'], 'reason': result['reason'], 'binarySha256': result['binarySha256'], 'recordSha256': result['recordSha256']})
        state.update(status='VERIFIED_PENDING_ONLY', stage='complete', tools=pending,
                     artifactIdentity=manifest['archiveSha256'], assetId=release['assetId'], databaseSha256=database['sha256'], runtimeConfig=CONFIG, executionImage=execution_image, transportManifestSha256=release['transportManifestSha256'], pendingRegistrySha256=digest(CONTROL / 'policy/native-scanners.pending.json'))
    except BaseException as error:
        state['error'] = str(error) if isinstance(error, Rejected) and re.fullmatch('[A-Z_]{1,60}', str(error)) else 'VERIFICATION_FAILED'
        raise
    finally:
        if (root / 'fresh').is_dir():
            shutil.copytree(root / 'fresh', artifacts / 'fresh', ignore=shutil.ignore_patterns('binary'))
        logs = artifacts / 'operations'
        logs.mkdir()
        for path in root.iterdir():
            if path.name.endswith(('.stdout', '.stderr')) and path.is_file() and not path.is_symlink() and path.stat().st_size <= 32000000:
                shutil.copyfile(path, logs / path.name)
        write_json(artifacts / 'summary.json', state)
    return state


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 1, 'ARGUMENTS')
        result = verify()
        print(json.dumps({'status': result['status'], 'adoption': False}))
    except BaseException:
        print('Native bundle verification stopped; inspect bounded diagnostic artifacts.', file=sys.stderr)
        raise SystemExit(1)
