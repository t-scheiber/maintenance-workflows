# SPDX-License-Identifier: MIT
"""Byte transport only. A successful extraction never admits or executes a scanner.

The caller must supply the manifest from protected control code, not from the
bundle. Output is a new private directory. Native admission remains mandatory.
"""
import gzip
import hashlib
import io
import json
import os
import re
import stat
import tarfile

MAX_FILES = 4096
MAX_ARCHIVE = 400_000_000
MAX_EXPANDED = 800_000_000
MAX_FILE = 400_000_000


class Rejected(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise Rejected(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def entries(manifest):
    require(type(manifest) is dict and set(manifest) == {'version', 'archiveBytes', 'archiveSha256', 'files'}, 'MANIFEST_SCHEMA')
    require(manifest['version'] == 1 and type(manifest['version']) is int, 'MANIFEST_VERSION')
    require(type(manifest['archiveBytes']) is int and 1 <= manifest['archiveBytes'] <= MAX_ARCHIVE, 'ARCHIVE_BOUNDS')
    require(type(manifest['archiveSha256']) is str and re.fullmatch('[a-f0-9]{64}', manifest['archiveSha256']), 'ARCHIVE_HASH')
    require(type(manifest['files']) is list and 1 <= len(manifest['files']) <= MAX_FILES, 'FILE_COUNT')
    result = {}
    total = 0
    for item in manifest['files']:
        require(type(item) is dict and set(item) == {'path', 'bytes', 'sha256', 'mode'}, 'FILE_SCHEMA')
        name = item['path']
        require(type(name) is str and len(name) <= 100 and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._/-]*', name), 'FILE_PATH')
        require(all(x not in ('', '.', '..') for x in name.split('/')) and name not in result, 'FILE_PATH')
        require(type(item['bytes']) is int and 1 <= item['bytes'] <= MAX_FILE, 'FILE_BOUNDS')
        require(type(item['mode']) is int and item['mode'] in (0o644, 0o755), 'FILE_MODE')
        require(type(item['sha256']) is str and re.fullmatch('[a-f0-9]{64}', item['sha256']), 'FILE_HASH')
        total += item['bytes']
        require(total <= MAX_EXPANDED, 'EXPANDED_BOUNDS')
        result[name] = item
    names = set(result)
    require(all('/'.join(n.split('/')[:i]) not in names for n in names for i in range(1, len(n.split('/')))), 'FILE_DIRECTORY_CONFLICT')
    return result


def open_regular(path, expected=None):
    # NONBLOCK prevents a regular-file-to-FIFO race from hanging the caller.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), 'NOT_REGULAR')
        require(1 <= info.st_size <= MAX_ARCHIVE, 'FILE_BOUNDS')
        if expected is not None:
            require(info.st_size == expected, 'FILE_SIZE')
        return fd, info
    except BaseException:
        os.close(fd)
        raise


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_mtime_ns, info.st_ctime_ns)


class LimitedReader:
    def __init__(self, stream, limit):
        self.stream, self.remaining = stream, limit

    def read(self, size=-1):
        size = min(size if size >= 0 else self.remaining + 1, self.remaining + 1)
        data = self.stream.read(size)
        self.remaining -= len(data)
        require(self.remaining >= 0, 'EXPANDED_BOUNDS')
        return data


def trusted_parent(destination):
    require(os.path.isabs(destination), 'ABSOLUTE_DESTINATION_REQUIRED')
    parent, leaf = os.path.split(destination)
    require(leaf and leaf not in ('.', '..'), 'DESTINATION_NAME')
    # Resolve each directory by fd without following symlinks, retaining the final
    # parent fd so replacement of its pathname cannot redirect our writes.
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parent.split('/')[1:]:
            require(part not in ('', '.', '..'), 'DESTINATION_PARENT')
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd, leaf
    except BaseException:
        os.close(fd)
        raise


def make_parents(root, name):
    fd = os.dup(root)
    try:
        for part in name.split('/')[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def extract(archive, manifest, destination):
    approved = entries(manifest)
    fd, original = open_regular(archive, manifest['archiveBytes'])
    parent = root = None
    try:
        with os.fdopen(os.dup(fd), 'rb') as source:
            hasher = hashlib.sha256()
            remaining = original.st_size
            while remaining:
                block = source.read(min(1024 * 1024, remaining))
                require(bool(block), 'ARCHIVE_CHANGED')
                remaining -= len(block)
                hasher.update(block)
            require(not source.read(1), 'ARCHIVE_CHANGED')
            digest = hasher.hexdigest()
        require(digest == manifest['archiveSha256'], 'ARCHIVE_HASH_MISMATCH')
        require(identity(original) == identity(os.fstat(fd)), 'ARCHIVE_CHANGED')
        os.lseek(fd, 0, os.SEEK_SET)
        parent, leaf = trusted_parent(destination)
        os.mkdir(leaf, 0o700, dir_fd=parent)  # Never replace an existing path.
        root = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        seen = set()
        expected_offset = 0
        # Bound decompressed bytes including tar headers and all trailing data.
        # This also prevents hidden trailing gzip members from being overlooked.
        expanded_limit = sum((r['bytes'] + 511) // 512 * 512 + 512 for r in approved.values()) + 10240
        with os.fdopen(os.dup(fd), 'rb') as raw, gzip.GzipFile(fileobj=raw, mode='rb') as gz:
            bounded = LimitedReader(gz, expanded_limit)
            with tarfile.open(fileobj=bounded, mode='r|', bufsize=512) as tar:
                for member in tar:
                    require(member.offset == expected_offset and member.offset_data == member.offset + 512, 'ARCHIVE_EXTENSION')
                    expected_offset = member.offset_data + ((member.size + 511) // 512 * 512)
                    require(member.type == tarfile.REGTYPE and not member.pax_headers and not member.linkname, 'ARCHIVE_ENTRY_TYPE')
                    require(member.name in approved and member.name not in seen, 'ARCHIVE_ENTRY_SET')
                    item = approved[member.name]
                    require(member.size == item['bytes'] and member.mode == item['mode'], 'ARCHIVE_ENTRY_METADATA')
                    require(member.uid == 0 and member.gid == 0 and member.uname == '' and member.gname == '' and member.mtime == 0, 'ARCHIVE_ENTRY_METADATA')
                    out_parent = make_parents(root, member.name)
                    try:
                        out = os.open(member.name.split('/')[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=out_parent)
                        try:
                            digest = hashlib.sha256()
                            count = 0
                            with tar.extractfile(member) as data:
                                while block := data.read(1024 * 1024):
                                    count += len(block)
                                    require(count <= item['bytes'], 'FILE_BOUNDS')
                                    digest.update(block)
                                    view = memoryview(block)
                                    while view:
                                        written = os.write(out, view)
                                        require(written > 0, 'WRITE_FAILED')
                                        view = view[written:]
                            require(count == item['bytes'] and digest.hexdigest() == item['sha256'], 'FILE_HASH_MISMATCH')
                        finally:
                            os.close(out)
                    finally:
                        os.close(out_parent)
                    seen.add(member.name)
            require(seen == set(approved), 'ARCHIVE_ENTRY_SET')
            while tail := bounded.read(1024 * 1024):
                require(not any(tail), 'TRAILING_ARCHIVE_DATA')
        require(identity(original) == identity(os.fstat(fd)), 'ARCHIVE_CHANGED')
        # Delay executable permissions until every archived byte has passed.
        for name, item in approved.items():
            out_parent = make_parents(root, name)
            try:
                os.chmod(name.split('/')[-1], item['mode'], dir_fd=out_parent, follow_symlinks=False)
            finally:
                os.close(out_parent)
        return {'version': 1, 'status': 'TRANSPORT_VERIFIED_ONLY', 'archiveSha256': manifest['archiveSha256'], 'files': len(seen), 'nativeAdmissionRequired': True}
    finally:
        os.close(fd)
        if root is not None:
            os.close(root)
        if parent is not None:
            os.close(parent)


def pack(source_root, approved_files, archive):
    """Create deterministic bytes from an explicit, previously reviewed file list.

    Never discovers files. The caller owns license/provenance completeness and
    must independently inspect the final manifest before any public upload.
    """
    candidate = {'version': 1, 'archiveBytes': 1, 'archiveSha256': '0' * 64, 'files': approved_files}
    approved = entries(candidate)
    source_fd = os.open(source_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        out_fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except BaseException:
        os.close(source_fd)
        raise
    try:
        with os.fdopen(os.dup(out_fd), 'wb') as raw:
            with gzip.GzipFile(filename='', fileobj=raw, mode='wb', compresslevel=6, mtime=0) as gz:
                with tarfile.open(fileobj=gz, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
                    for name, item in sorted(approved.items()):
                        parent = os.dup(source_fd)
                        try:
                            parts = name.split('/')
                            for part in parts[:-1]:
                                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                                os.close(parent)
                                parent = next_fd
                            file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
                            try:
                                before = os.fstat(file_fd)
                                require(stat.S_ISREG(before.st_mode) and before.st_size == item['bytes'] and (before.st_mode & 0o777) == item['mode'], 'PACK_FILE_IDENTITY')
                                with os.fdopen(os.dup(file_fd), 'rb') as data:
                                    digest = hashlib.sha256()
                                    remaining = item['bytes']
                                    while remaining:
                                        block = data.read(min(1024 * 1024, remaining))
                                        require(bool(block), 'PACK_FILE_CHANGED')
                                        remaining -= len(block)
                                        digest.update(block)
                                    require(not data.read(1) and digest.hexdigest() == item['sha256'], 'PACK_FILE_HASH')
                                    data.seek(0)
                                    member = tarfile.TarInfo(name)
                                    member.mode, member.size = item['mode'], item['bytes']
                                    tar.addfile(member, data)
                                require(identity(before) == identity(os.fstat(file_fd)), 'PACK_FILE_CHANGED')
                            finally:
                                os.close(file_fd)
                        finally:
                            os.close(parent)
        require(os.fstat(out_fd).st_size <= MAX_ARCHIVE, 'ARCHIVE_BOUNDS')
    finally:
        os.close(source_fd)
        os.close(out_fd)
    fd, before = open_regular(archive)
    try:
        with os.fdopen(os.dup(fd), 'rb') as source:
            hasher = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                block = source.read(min(1024 * 1024, remaining))
                require(bool(block), 'ARCHIVE_CHANGED')
                remaining -= len(block)
                hasher.update(block)
            require(not source.read(1), 'ARCHIVE_CHANGED')
            digest = hasher.hexdigest()
        require(identity(before) == identity(os.fstat(fd)), 'ARCHIVE_CHANGED')
        candidate['archiveBytes'], candidate['archiveSha256'] = before.st_size, digest
        entries(candidate)
        return candidate
    finally:
        os.close(fd)
