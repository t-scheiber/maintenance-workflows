import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools/native/bundle'))
# SPDX-License-Identifier: MIT
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from verify import admission, container_args, vulnerability_args, digest, read_file, IMAGE, Rejected, process, checked_release, verify, make_runtime_archive_readable, prepare_command_path


class HostedVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.env = {'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':'t-scheiber/AK_WeatherApp','GITHUB_REPOSITORY_ID':'755321462','PUBLIC_REPOSITORY_PRIVATE':'false','PUBLIC_DEFAULT_BRANCH':'main','PUBLIC_TOOLS_REF':'b'*40,'STATIC_PAGES_ENABLED':'true',
                    'GITHUB_REPOSITORY_OWNER_ID':'66697291','GITHUB_REF':'refs/heads/main',
                    'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_ACTOR':'t-scheiber',
                    'GITHUB_TRIGGERING_ACTOR':'t-scheiber','GITHUB_RUN_ATTEMPT':'1',
                    'NATIVE_SCANNER_VERIFICATION_ENABLED':'true','GITHUB_SHA':'a'*40,
                    'VERIFIED_DEFAULT_SHA':'a'*40,'GITHUB_RUN_ID':'123','RUNNER_TEMP':str(self.root)}

    def test_exact_public_owner_default_paired_ref_and_component_switch(self):
        self.assertEqual(admission(self.env), self.root/'native-bundle-verification')
        self.assertEqual(admission({**self.env,'AUTOMATION_ENABLED':'false'}), self.root/'native-bundle-verification')
        for key, value in [('GITHUB_ACTIONS','false'),('GITHUB_REPOSITORY','other/repo'),('GITHUB_REPOSITORY_OWNER_ID','1'),
                           ('GITHUB_REF','refs/heads/feature'),('GITHUB_EVENT_NAME','pull_request'),('GITHUB_ACTOR','other'),
                           ('GITHUB_TRIGGERING_ACTOR','other'),('GITHUB_RUN_ATTEMPT','0'),('GITHUB_RUN_ID','0'),
                           ('GITHUB_SHA','invalid'),('PUBLIC_TOOLS_REF','main'),('PUBLIC_DEFAULT_BRANCH','other'),('STATIC_PAGES_ENABLED','false'),('GITHUB_REPOSITORY_ID','2'),('PUBLIC_REPOSITORY_PRIVATE','true')]:
            with self.subTest(key=key), self.assertRaises(Rejected):admission({**self.env,key:value})
        with self.assertRaises(Rejected):admission({k:v for k,v in self.env.items() if k!='STATIC_PAGES_ENABLED'})

    def test_no_credential_environment_or_symlink_runner_directory(self):
        for name in ('GH_TOKEN','GITHUB_TOKEN','OPENROUTER_API_KEY','MAINTENANCE_APP_PRIVATE_KEY','ACTIONS_RUNTIME_TOKEN'):
            with self.subTest(name=name), self.assertRaises(Rejected):admission({**self.env,name:'synthetic'})
        (self.root/'link').symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(Rejected):admission({**self.env,'RUNNER_TEMP':str(self.root/'link')})

    def test_bounded_regular_reads_never_follow_or_block_on_special_files(self):
        target=self.root/'data';target.write_bytes(b'abc')
        self.assertEqual(digest(target),hashlib.sha256(b'abc').hexdigest())
        self.assertEqual(read_file(target,3),b'abc')
        for fn in (read_file,digest):
            with self.assertRaises(Rejected):fn(target,2)
            with self.assertRaises(Rejected):fn(self.root,20)
        (self.root/'link').symlink_to(target)
        for fn in (read_file,digest):
            with self.assertRaises(OSError):fn(self.root/'link',20)
        directory=self.root/'directory';directory.mkdir();(directory/'data').write_bytes(b'abc')
        (self.root/'parent-link').symlink_to(directory,target_is_directory=True)
        for fn in (read_file,digest):
            with self.assertRaises(OSError):fn(self.root/'parent-link/data',20)
        if hasattr(os,'mkfifo'):
            os.mkfifo(self.root/'fifo')
            for fn in (read_file,digest):
                with self.assertRaises(Rejected):fn(self.root/'fifo',20)

    def test_source_free_scanner_mounts_and_no_network_by_default(self):
        args=container_args(IMAGE,'/fixed/scanner','/fixed/db','unique',mounts=(('/fixed/input','/input'),))
        for flag in ('--read-only','--cap-drop','--security-opt','--pids-limit','--memory','--cpus'):self.assertIn(flag,args)
        self.assertEqual(args[args.index('--network')+1],'none')
        self.assertEqual(args[args.index('--user')+1],'1000:1000')
        self.assertIn('type=bind,src=/fixed/db,dst=/cache,readonly',args)
        self.assertNotIn('/var/run/docker.sock',' '.join(args))
        self.assertNotIn('GITHUB_TOKEN',' '.join(args))
        self.assertEqual(args[-2:],[ '/scanner', IMAGE])
        with self.assertRaises(Rejected):container_args('mutable:latest','/s','/d','n')
        with self.assertRaises(Rejected):container_args(IMAGE,'/s','/d','n','host')
        with self.assertRaises(Rejected):container_args(IMAGE,'/s','/d','n',mounts=(('/repo','/repository'),))

    def test_unpublished_asset_fails_before_any_download(self):
        with patch('verify.read_file',return_value=b'{"version":1,"repository":"t-scheiber/maintenance-workflows","assetId":0}'):
            with self.assertRaises(Rejected):checked_release()

    def test_native_scan_uses_real_binary_inventory_mode_with_all_severities(self):
        self.assertEqual(vulnerability_args('native')[0],'rootfs')
        self.assertEqual(vulnerability_args('native')[-1],'/input')
        for mode in ('native','runtime'):
            args=vulnerability_args(mode)
            for flag in ('--list-all-pkgs','--skip-db-update','--offline-scan','--no-progress'):self.assertIn(flag,args)
            self.assertEqual(args[args.index('--severity')+1],'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL')
        self.assertEqual(vulnerability_args('runtime')[:3],['image','--input','/runtime.tar.gz'])
        for mode in ('fs','config','repository'):
            with self.assertRaises(Rejected):vulnerability_args(mode)

    def test_process_timeout_has_generic_bounded_failure(self):
        import subprocess
        with patch('verify.subprocess.run',side_effect=subprocess.TimeoutExpired('synthetic',1)):
            with self.assertRaisesRegex(Rejected,'PROCESS_TIMEOUT'):
                process(['never-executed'],{},self.root/'out',self.root/'err',1)

    def test_transport_failure_preserves_block_and_never_launches_docker(self):
        import json
        with patch.dict(os.environ,self.env,clear=True), patch('verify.checked_release',return_value=({'assetId':1,'source':{'tag':'synthetic','name':'synthetic'}},{})), \
             patch('verify.download_with_deadline',side_effect=Rejected('DOWNLOAD_CHECKSUM')), patch('verify.subprocess.run') as run:
            with self.assertRaises(Rejected):verify()
            run.assert_not_called()
        result=json.loads((self.root/'native-bundle-verification/artifacts/summary.json').read_text())
        self.assertEqual((result['status'],result['stage'],result['error']),('BLOCK','download','DOWNLOAD_CHECKSUM'))
        self.assertFalse(result['adoption'])

    def test_unexpected_exception_does_not_leak_response_or_retry(self):
        import json
        with patch.dict(os.environ,self.env,clear=True), patch('verify.checked_release',side_effect=ValueError('synthetic-private-body')), \
             patch('verify.download_with_deadline') as download, patch('verify.subprocess.run') as run:
            with self.assertRaises(ValueError):verify()
            download.assert_not_called();run.assert_not_called()
        result=(self.root/'native-bundle-verification/artifacts/summary.json').read_text()
        self.assertNotIn('synthetic-private-body',result)
        self.assertEqual(json.loads(result)['error'],'VERIFICATION_FAILED')

    def test_archive_subprocess_expanded_limit_and_exact_command_path(self):
        import resource
        import subprocess
        command=self.root/'commands';command.mkdir()
        with patch('verify.Path.is_file',return_value=True):prepare_command_path(command)
        self.assertEqual(sorted(x.name for x in command.iterdir()),['docker','tar'])
        self.assertEqual(os.readlink(command/'docker'),'/usr/bin/docker')
        self.assertEqual(os.readlink(command/'tar'),'/usr/bin/tar')
        with self.assertRaises(Rejected):prepare_command_path(command)
        with patch('verify.subprocess.run',return_value=subprocess.CompletedProcess([],0)) as launch:
            self.assertEqual(process(['synthetic'],{},self.root/'out2',self.root/'err2',1,2_000_000_000),0)
            with patch('verify.resource.setrlimit') as limits:
                launch.call_args.kwargs['preexec_fn']()
                limits.assert_called_once_with(resource.RLIMIT_FSIZE,(2_000_000_000,2_000_000_000))
        with self.assertRaises(Rejected):process([],{},self.root/'out3',self.root/'err3',1,2_000_000_001)

    def test_public_runtime_archive_readable_without_write_or_execute_permissions(self):
        archive=self.root/'runtime.tar.gz';archive.write_bytes(b'synthetic-public-runtime')
        archive.chmod(0o600)
        original=archive.read_bytes()
        make_runtime_archive_readable(archive)
        self.assertEqual(archive.stat().st_mode & 0o777,0o444)
        self.assertEqual(archive.read_bytes(),original)
        with self.assertRaises(Rejected):make_runtime_archive_readable(self.root)
        (self.root/'empty').touch()
        with self.assertRaises(Rejected):make_runtime_archive_readable(self.root/'empty')
        (self.root/'link').symlink_to(archive)
        with self.assertRaises(OSError):make_runtime_archive_readable(self.root/'link')
        if hasattr(os,'mkfifo'):
            os.mkfifo(self.root/'fifo')
            with self.assertRaises(Rejected):make_runtime_archive_readable(self.root/'fifo')

    def test_existing_run_directory_cannot_be_overwritten(self):
        folder=self.root/'native-bundle-verification';folder.mkdir();marker=folder/'existing';marker.write_text('preserve')
        with patch.dict(os.environ,self.env,clear=True), patch('verify.checked_release') as release:
            with self.assertRaises(FileExistsError):verify()
            release.assert_not_called()
        self.assertEqual(marker.read_text(),'preserve')


if __name__=='__main__':unittest.main()
