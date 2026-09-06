import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools/native/bundle'))
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
import install_actionlint as installer
import download_bundle as transport

class ActionlintInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.control=self.root/'control';(self.control/'policy').mkdir(parents=True)
        for name in ('actionlint-release.json','actionlint-transport.json'):
            (self.control/'policy'/name).write_bytes((installer.CONTROL/'policy'/name).read_bytes())
        self.env={'RUNNER_TEMP':str(self.root)}
    def change(self, **values):
        file=self.control/'policy/actionlint-release.json';value=json.loads(file.read_bytes());value.update(values);file.write_text(json.dumps(value))
    def call(self, downloader):
        with patch.object(installer,'CONTROL',self.control),patch.object(installer,'admission',return_value=self.root),patch.object(installer,'extract') as extract:
            result=installer.install(self.env,downloader)
            return result,extract
    def test_fixed_release_and_external_manifest(self):
        calls=[]
        result,extract=self.call(lambda *args,**kwargs:calls.append((args,kwargs)))
        self.assertEqual(calls[0][0][0],547382486)
        self.assertEqual(calls[0][1],{'source':{'tag':'actionlint-2026-09-06-r1','name':'actionlint-1.7.12-maintenance.1-linux-amd64.tar.gz'}})
        self.assertEqual(len(calls[0][0][1]['files']),47)
        self.assertEqual(extract.call_args.args[2],self.root/'actionlint/bundle')
    def test_pending_never_downloads(self):
        self.change(state='pending-publication',assetId=None)
        with self.assertRaisesRegex(Exception,'ACTIONLINT_PUBLICATION_PENDING'):
            self.call(lambda *_args,**_kwargs:self.fail('downloaded pending artifact'))
        self.assertFalse((self.root/'actionlint').exists())
    def test_wrong_manifest_never_downloads(self):
        (self.control/'policy/actionlint-transport.json').write_text('{}')
        with self.assertRaisesRegex(Exception,'ACTIONLINT_MANIFEST'):
            self.call(lambda *_args,**_kwargs:self.fail('downloaded unbound artifact'))
    def test_wrong_origin_never_downloads(self):
        self.change(repository='other/repository')
        with self.assertRaisesRegex(Exception,'ACTIONLINT_RELEASE'):
            self.call(lambda *_args,**_kwargs:self.fail('downloaded other origin'))
    def test_existing_destination_prevents_duplicate_install(self):
        (self.root/'actionlint').mkdir()
        with self.assertRaises(FileExistsError):
            self.call(lambda *_args,**_kwargs:self.fail('duplicate download'))

    def test_real_downloader_serializes_installer_destination_before_worker(self):
        captured=[]
        def worker(command,payload,**kwargs):
            data=json.loads(payload)
            captured.append(data)
            self.assertEqual(data['destination'],str(self.root/'actionlint/bundle.tar.gz'))
            self.assertEqual(data['assetId'],547382486)
            self.assertEqual(data['source'],{'tag':'actionlint-2026-09-06-r1','name':'actionlint-1.7.12-maintenance.1-linux-amd64.tar.gz'})
            manifest=data['manifest']
            return {'version':1,'status':'DOWNLOAD_VERIFIED_ONLY','repository':'t-scheiber/maintenance-workflows','assetId':data['assetId'],'bytes':manifest['archiveBytes'],'sha256':manifest['archiveSha256'],'authenticated':False,'nativeAdmissionRequired':True}
        with patch.object(transport,'run_bounded_worker',side_effect=worker):
            result,extract=self.call(installer.download_with_deadline)
        self.assertEqual(len(captured),1)
        self.assertEqual(result,self.root/'actionlint')
        self.assertEqual(extract.call_args.args[0],self.root/'actionlint/bundle.tar.gz')
