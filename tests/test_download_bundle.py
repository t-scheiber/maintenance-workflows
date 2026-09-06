import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools/native/bundle'))
# SPDX-License-Identifier: MIT
import io
import hashlib
from pathlib import Path
import tempfile
import unittest
from bundle_transport import Rejected
from download_bundle import download, redirect_url, run_bounded_worker, download_with_deadline
from test_bundle_transport import bundle
import tarfile


class Response:
    def __init__(self, body=b'', status=200, headers=None):
        self.body, self.status, self.headers = io.BytesIO(body), status, headers or {}
        self.closed = False

    def read(self, size):
        return self.body.read(size)

    def close(self):
        self.closed = True


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.destination = str(Path(self.temp.name).resolve() / 'bundle.gz')
        self.data, self.manifest = bundle([('binary', b'abc', tarfile.REGTYPE)])

    def test_direct_binary_download_is_anonymous_and_bounded(self):
        seen = []
        def transport(url, timeout):
            seen.append((url, timeout))
            return Response(self.data, headers={'Content-Length': str(len(self.data))})
        result = download(123, self.manifest, self.destination, transport=transport)
        self.assertEqual(seen[0][0], 'https://api.github.com/repos/t-scheiber/maintenance-workflows/releases/assets/123')
        self.assertLessEqual(seen[0][1], 30)
        self.assertFalse(result['authenticated'])
        self.assertTrue(result['nativeAdmissionRequired'])
        self.assertEqual(Path(self.destination).read_bytes(), self.data)

    def test_expected_single_redirect(self):
        calls = []
        first = Response(status=302, headers={'Location': 'https://release-assets.githubusercontent.com/release?signature=public'})
        second = Response(self.data)
        def transport(url, timeout):
            calls.append(url)
            return first if len(calls) == 1 else second
        download(123, self.manifest, self.destination, transport=transport)
        self.assertEqual(len(calls), 2)
        self.assertTrue(first.closed and second.closed)

    def test_fixed_immutable_release_source(self):
        calls = []
        def transport(url, timeout):
            calls.append(url)
            return Response(self.data)
        download(123, self.manifest, self.destination, source={'tag': 'native-scanners-2026-09-06-r1', 'name': 'bundle.tar.gz'}, transport=transport)
        self.assertEqual(calls, ['https://github.com/t-scheiber/maintenance-workflows/releases/download/native-scanners-2026-09-06-r1/bundle.tar.gz'])

    def test_release_source_cannot_change_repository_or_escape_path(self):
        for value in ['', '.', '..', '../a', 'a/b', 'a?x', 'a#x', 'a%2fb', 'https://evil.example', 'a\\b', 'a\n', 'é', 'a' * 201]:
            for key in ['tag', 'name']:
                source = {'tag': 'v1', 'name': 'bundle.tar.gz', key: value}
                with self.assertRaisesRegex(Rejected, 'DOWNLOAD_SOURCE'):
                    download(123, self.manifest, self.destination, source=source, transport=lambda *args: self.fail('request prohibited'))
        for source in [{}, {'tag': 'v1'}, {'tag': 'v1', 'name': 'a', 'repository': 'evil/other'}, 'v1']:
            with self.assertRaisesRegex(Rejected, 'DOWNLOAD_SOURCE'):
                download(123, self.manifest, self.destination, source=source, transport=lambda *args: self.fail('request prohibited'))

    def test_parent_forwards_protected_source_to_worker(self):
        import json
        from unittest.mock import patch
        source = {'tag': 'v1', 'name': 'bundle.tar.gz'}
        def worker(command, payload):
            self.assertEqual(json.loads(payload)['source'], source)
            return {'version': 1, 'status': 'DOWNLOAD_VERIFIED_ONLY', 'repository': 't-scheiber/maintenance-workflows', 'assetId': 123, 'bytes': self.manifest['archiveBytes'], 'sha256': self.manifest['archiveSha256'], 'authenticated': False, 'nativeAdmissionRequired': True}
        with patch('download_bundle.run_bounded_worker', worker):
            download_with_deadline(123, self.manifest, self.destination, source=source)

    def test_redirect_host_protocol_user_port_and_controls(self):
        for url in ['http://release-assets.githubusercontent.com/a', 'https://evil.example/a', 'https://release-assets.githubusercontent.com.evil.example/a', 'https://u@release-assets.githubusercontent.com/a', 'https://release-assets.githubusercontent.com:443/a', 'https://release-assets.githubusercontent.com/a#x', 'https://release-assets.githubusercontent.com/a\n', '//release-assets.githubusercontent.com/a']:
            with self.assertRaises(Rejected, msg=url): redirect_url(url)

    def test_second_redirect_stops(self):
        response = Response(status=302, headers={'Location': 'https://release-assets.githubusercontent.com/a'})
        with self.assertRaisesRegex(Rejected, 'DOWNLOAD_HTTP_STATUS'):
            download(123, self.manifest, self.destination, transport=lambda *args: response)
        self.assertFalse(Path(self.destination).exists())

    def test_nonbinary_or_tampered_payload_rejects(self):
        with self.assertRaisesRegex(Rejected, 'DOWNLOAD_CHECKSUM'):
            download(123, self.manifest, self.destination, transport=lambda *args: Response(b'{}'))

    def test_oversized_stream_rejects(self):
        with self.assertRaisesRegex(Rejected, 'DOWNLOAD_BOUNDS'):
            download(123, self.manifest, self.destination, transport=lambda *args: Response(self.data+b'excess'))

    def test_mismatched_length_or_encoded_payload_rejects_before_file(self):
        for headers in [{'Content-Length': '1'}, {'Content-Encoding': 'gzip'}, {'Content-Length': '-1'}]:
            with self.assertRaises(Rejected): download(123, self.manifest, self.destination, transport=lambda *args: Response(self.data, headers=headers))
            self.assertFalse(Path(self.destination).exists())

    def test_timeout_after_metadata_never_writes(self):
        clock = [0]
        def transport(*args):
            clock[0] = 121
            return Response(self.data)
        with self.assertRaisesRegex(Rejected, 'DOWNLOAD_TIMEOUT'):
            download(123, self.manifest, self.destination, transport=transport, now=lambda: clock[0])
        self.assertFalse(Path(self.destination).exists())

    def test_rate_limit_has_no_retry_and_keeps_existing_file(self):
        Path(self.destination).write_text('preserve')
        calls = []
        def transport(*args):
            calls.append(1)
            return Response(b'private provider body', 429)
        with self.assertRaisesRegex(Rejected, 'DOWNLOAD_HTTP_STATUS'):
            download(123, self.manifest, self.destination, transport=transport)
        self.assertEqual(len(calls), 1)
        self.assertEqual(Path(self.destination).read_text(), 'preserve')

    def test_invalid_asset_id_never_requests(self):
        for value in [True, 0, -1, '123', '../bad']:
            with self.assertRaises(Rejected):
                download(value, self.manifest, self.destination, transport=lambda *args: self.fail('request prohibited'))


    def test_parent_deadline_kills_blocked_worker(self):
        import sys, time
        started = time.monotonic()
        with self.assertRaisesRegex(Rejected, 'DOWNLOAD_TIMEOUT'):
            run_bounded_worker([sys.executable, '-I', '-S', '-c', 'import time;time.sleep(60)'], b'{}', timeout=0.15)
        self.assertLess(time.monotonic() - started, 2)

    def test_parent_deadline_kills_trickling_worker_and_stops_writes(self):
        import sys, time
        target = Path(self.destination)
        code = 'import sys,time;f=open(sys.argv[1],"wb",buffering=0)\nwhile True:f.write(b"x");time.sleep(.01)'
        with self.assertRaisesRegex(Rejected, 'DOWNLOAD_TIMEOUT'):
            run_bounded_worker([sys.executable, '-I', '-S', '-c', code, str(target)], b'{}', timeout=0.15)
        size = target.stat().st_size
        time.sleep(0.05)
        self.assertEqual(target.stat().st_size, size)

    def test_worker_has_no_inherited_secret_environment(self):
        import sys, os
        from unittest.mock import patch
        with patch.dict(os.environ, {'OPENROUTER_API_KEY': 'synthetic-test-only'}):
            result = run_bounded_worker([sys.executable, '-I', '-S', '-c', 'import os,json;print(json.dumps({"hasKey":"OPENROUTER_API_KEY" in os.environ}))'], b'{}')
        self.assertEqual(result, {'hasKey': False})

    def test_worker_rejects_invalid_asset_without_network(self):
        import sys, json
        worker = str((Path(__file__).resolve().parents[1]/'tools/native/bundle/download_bundle.py'))
        payload = json.dumps({'assetId': 0, 'manifest': self.manifest, 'destination': self.destination}).encode()
        with self.assertRaisesRegex(Rejected, 'ASSET_ID'):
            run_bounded_worker([sys.executable, '-I', '-S', worker, '--worker'], payload)
        self.assertFalse(Path(self.destination).exists())

    def test_worker_error_body_is_not_exposed_by_parent(self):
        import sys
        with self.assertRaisesRegex(Rejected, 'WORKER_OUTPUT_BOUNDS'):
            run_bounded_worker([sys.executable, '-I', '-S', '-c', 'import sys;sys.stderr.write("untrusted response");sys.exit(1)'], b'{}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
