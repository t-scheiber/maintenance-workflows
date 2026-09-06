import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools/native/bundle'))
# SPDX-License-Identifier: MIT
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from bundle_transport import extract, entries, pack, Rejected


def bundle(items, *, archive_format=tarfile.USTAR_FORMAT, trailing=b''):
    raw = io.BytesIO()
    rows = []
    with tarfile.open(fileobj=raw, mode='w', format=archive_format) as tar:
        for name, data, kind in items:
            member = tarfile.TarInfo(name)
            member.mode = 0o755 if name.endswith('/binary') else 0o644
            member.size = len(data)
            member.type = kind
            if kind == tarfile.SYMTYPE:
                member.linkname = '/outside'
            tar.addfile(member, io.BytesIO(data))
            rows.append({'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'mode': member.mode})
    data = gzip.compress(raw.getvalue() + trailing, mtime=0)
    return data, {'version': 1, 'archiveBytes': len(data), 'archiveSha256': hashlib.sha256(data).hexdigest(), 'files': rows}


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.archive = self.root / 'bundle.tar.gz'
        self.destination = self.root / 'output'
        self.data, self.manifest = bundle([('trivy/binary', b'not-an-executable', tarfile.REGTYPE), ('trivy/provenance.json', b'{}', tarfile.REGTYPE)])
        self.archive.write_bytes(self.data)

    def run_extract(self):
        return extract(str(self.archive), self.manifest, str(self.destination))

    def test_valid_transport_never_claims_admission(self):
        result = self.run_extract()
        self.assertEqual(result['status'], 'TRANSPORT_VERIFIED_ONLY')
        self.assertTrue(result['nativeAdmissionRequired'])
        self.assertEqual((self.destination / 'trivy/binary').read_bytes(), b'not-an-executable')
        self.assertEqual((self.destination / 'trivy/binary').stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)

    def test_archive_checksum_swap_leaves_no_output(self):
        self.archive.write_bytes(self.data[:-1] + bytes([self.data[-1] ^ 1]))
        with self.assertRaises(Rejected): self.run_extract()
        self.assertFalse(self.destination.exists())

    def test_symlink_input(self):
        real = self.root / 'real'
        self.archive.rename(real)
        self.archive.symlink_to(real)
        with self.assertRaises(OSError): self.run_extract()

    def test_fifo_input_returns_without_hanging(self):
        self.archive.unlink()
        os.mkfifo(self.archive)
        source = 'import sys,json;from bundle_transport import extract;extract(sys.argv[1],json.loads(sys.argv[2]),sys.argv[3])'
        run = subprocess.run([sys.executable, '-c', source, str(self.archive), json.dumps(self.manifest), str(self.destination)], capture_output=True, timeout=3, cwd=Path(__file__).resolve().parents[1]/'tools/native/bundle')
        self.assertNotEqual(run.returncode, 0)
        self.assertIn(b'NOT_REGULAR', run.stderr)

    def test_existing_destination_is_untouched(self):
        self.destination.mkdir()
        marker = self.destination / 'user-file'
        marker.write_text('preserve')
        with self.assertRaises(FileExistsError): self.run_extract()
        self.assertEqual(marker.read_text(), 'preserve')

    def test_symlink_parent_is_rejected(self):
        link = self.root / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        self.destination = link / 'output'
        with self.assertRaises(OSError): self.run_extract()
        self.assertFalse((self.root / 'output').exists())

    def test_manifest_traversal_absolute_empty_and_duplicate(self):
        for path in ['../outside', '/outside', 'a/../outside', 'a//b', 'a/./b', 'a\\b', 'a\nname']:
            m = json.loads(json.dumps(self.manifest))
            m['files'][0]['path'] = path
            with self.assertRaises(Rejected, msg=path): entries(m)
        self.manifest['files'].append(self.manifest['files'][0])
        with self.assertRaises(Rejected): self.run_extract()

    def test_file_directory_conflict(self):
        self.manifest['files'][0]['path'] = 'trivy'
        with self.assertRaisesRegex(Rejected, 'FILE_DIRECTORY_CONFLICT'): self.run_extract()

    def test_bad_file_digest_never_makes_binary_executable(self):
        self.manifest['files'][1]['sha256'] = 'a' * 64
        with self.assertRaisesRegex(Rejected, 'FILE_HASH_MISMATCH'): self.run_extract()
        self.assertEqual((self.destination / 'trivy/binary').stat().st_mode & 0o777, 0o600)

    def test_manifest_extra_entry(self):
        self.manifest['files'].append({'path': 'absent', 'bytes': 1, 'sha256': 'a' * 64, 'mode': 0o644})
        with self.assertRaisesRegex(Rejected, 'ARCHIVE_ENTRY_SET'): self.run_extract()

    def test_archive_extra_entry(self):
        self.manifest['files'].pop()
        with self.assertRaisesRegex(Rejected, 'ARCHIVE_ENTRY_SET'): self.run_extract()

    def test_archive_duplicate_entry(self):
        data, manifest = bundle([('binary', b'abc', tarfile.REGTYPE), ('binary', b'abc', tarfile.REGTYPE)])
        manifest['files'].pop()
        self.archive.write_bytes(data)
        self.manifest = manifest
        with self.assertRaisesRegex(Rejected, 'ARCHIVE_ENTRY_SET'): self.run_extract()

    def test_nonregular_member(self):
        data, manifest = bundle([('binary', b'abc', tarfile.SYMTYPE)])
        self.archive.write_bytes(data)
        self.manifest = manifest
        with self.assertRaisesRegex(Rejected, 'ARCHIVE_ENTRY_TYPE'): self.run_extract()

    def test_metadata_mode_change(self):
        self.manifest['files'][0]['mode'] = 0o644
        with self.assertRaisesRegex(Rejected, 'ARCHIVE_ENTRY_METADATA'): self.run_extract()

    def test_zero_and_boolean_sizes(self):
        for size in [0, True, -1, 400_000_001]:
            self.manifest['files'][0]['bytes'] = size
            with self.assertRaises(Rejected): self.run_extract()

    def test_decompression_bomb_is_bounded(self):
        data, manifest = bundle([('binary', b'abc', tarfile.REGTYPE)], trailing=b'\0' * 100000)
        self.archive.write_bytes(data)
        self.manifest = manifest
        with self.assertRaisesRegex(Rejected, 'EXPANDED_BOUNDS'): self.run_extract()

    def test_nonzero_trailing_data(self):
        data, manifest = bundle([('binary', b'abc', tarfile.REGTYPE)], trailing=b'extra')
        self.archive.write_bytes(data)
        self.manifest = manifest
        with self.assertRaisesRegex(Rejected, 'TRAILING_ARCHIVE_DATA'): self.run_extract()

    def test_concatenated_gzip_member_is_not_hidden(self):
        data = self.data + gzip.compress(b'hidden', mtime=0)
        self.archive.write_bytes(data)
        self.manifest.update(archiveBytes=len(data), archiveSha256=hashlib.sha256(data).hexdigest())
        with self.assertRaisesRegex(Rejected, 'TRAILING_ARCHIVE_DATA'): self.run_extract()

    def test_truncated_archive(self):
        data = self.data[:-20]
        self.archive.write_bytes(data)
        self.manifest.update(archiveBytes=len(data), archiveSha256=hashlib.sha256(data).hexdigest())
        with self.assertRaises((EOFError, tarfile.TarError, Rejected)): self.run_extract()


    def test_packer_round_trip_and_deterministic_bytes(self):
        self.run_extract()
        a, b = self.root / 'one.gz', self.root / 'two.gz'
        first = pack(str(self.destination), self.manifest['files'], str(a))
        second = pack(str(self.destination), self.manifest['files'], str(b))
        self.assertEqual(first, second)
        self.assertEqual(a.read_bytes(), b.read_bytes())
        out = self.root / 'roundtrip'
        result = extract(str(a), first, str(out))
        self.assertEqual(result['files'], 2)
        self.assertEqual((out / 'trivy/binary').read_bytes(), b'not-an-executable')

    def test_packer_rejects_source_replacement(self):
        self.run_extract()
        binary = self.destination / 'trivy/binary'
        binary.write_bytes(b'changed bytes')
        with self.assertRaisesRegex(Rejected, 'PACK_FILE_IDENTITY'):
            pack(str(self.destination), self.manifest['files'], str(self.root / 'packed.gz'))

    def test_packer_rejects_source_directory_symlink(self):
        self.run_extract()
        (self.destination / 'trivy').rename(self.root / 'real-trivy')
        (self.destination / 'trivy').symlink_to(self.root / 'real-trivy', target_is_directory=True)
        with self.assertRaises(OSError):
            pack(str(self.destination), self.manifest['files'], str(self.root / 'packed.gz'))

    def test_packer_never_overwrites_archive(self):
        self.run_extract()
        before = self.archive.read_bytes()
        with self.assertRaises(FileExistsError):
            pack(str(self.destination), self.manifest['files'], str(self.archive))
        self.assertEqual(self.archive.read_bytes(), before)

    def test_extended_tar_headers_are_rejected(self):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT) as tar:
            member = tarfile.TarInfo('binary')
            member.mode, member.size = 0o644, 3
            member.pax_headers = {'comment': 'extension'}
            tar.addfile(member, io.BytesIO(b'abc'))
        data = gzip.compress(raw.getvalue(), mtime=0)
        self.archive.write_bytes(data)
        self.manifest = {'version': 1, 'archiveBytes': len(data), 'archiveSha256': hashlib.sha256(data).hexdigest(), 'files': [{'path': 'binary', 'bytes': 3, 'sha256': hashlib.sha256(b'abc').hexdigest(), 'mode': 0o644}]}
        with self.assertRaisesRegex(Rejected, 'ARCHIVE_EXTENSION'):
            self.run_extract()


if __name__ == '__main__':
    unittest.main(verbosity=2)
