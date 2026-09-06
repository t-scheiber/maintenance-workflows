import hashlib, importlib.util, io, json, os, pathlib, subprocess, tarfile, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('artifact',ROOT/'tools/static-pages/pages-artifact.py');app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
SHA='a'*40
class Response:
 def __init__(self,url,data):self.url=url;self.data=data;self.status=200
 def __enter__(self):return self
 def __exit__(self,*args):pass
 def read(self,limit):return self.data[:limit]
class Opener:
 def __init__(self,files):self.files=files;self.calls=[]
 def open(self,request,timeout):
  self.calls.append(request.full_url);self.timeout=timeout
  name=request.full_url.removeprefix('https://t-scheiber.github.io/AK_WeatherApp/')
  return Response(request.full_url,self.files[name])
class Tests(unittest.TestCase):
 def package(self,extras=[],transform=None):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);root=pathlib.Path(self.tmp.name)
  entries=[('index.html',b'<html><body><script src="./config.js"></script><script src="./script.js"></script><link href="style.css"></body></html>'),('script.js',b'/* fixture */'),('style.css',b'body{}')]
  with tarfile.open(root/'input.tar','w') as archive:
   for name,data in entries:
    item=tarfile.TarInfo(name);item.size=len(data);archive.addfile(item,io.BytesIO(data))
   for item,data in extras:archive.addfile(item,io.BytesIO(data))
  if transform:transform(root/'input.tar')
  app.package(root/'input.tar',root/'pages','AK_WeatherApp',SHA)
  return {str(p.relative_to(root/'pages')):p.read_bytes() for p in (root/'pages').rglob('*') if p.is_file()}
 def test_complete_package_and_smoke(self):
  files=self.package();o=Opener(files);r=app.smoke('AK_WeatherApp',SHA,o);self.assertEqual(r['filesVerified'],4);self.assertEqual(len(o.calls),5)
 def test_symlink(self):
  m=tarfile.TarInfo('assets/x');m.type=tarfile.SYMTYPE;m.linkname='/tmp/a'
  with self.assertRaises(RuntimeError):self.package([(m,b'')])
 def test_hardlink(self):
  m=tarfile.TarInfo('assets/x');m.type=tarfile.LNKTYPE;m.linkname='script.js'
  with self.assertRaises(RuntimeError):self.package([(m,b'')])
 def test_duplicate(self):
  with self.assertRaises(RuntimeError):self.package([(tarfile.TarInfo('./script.js'),b'')])
 def test_traversal(self):
  with self.assertRaises(RuntimeError):self.package([(tarfile.TarInfo('../bad'),b'')])
 def test_absolute(self):
  with self.assertRaises(RuntimeError):self.package([(tarfile.TarInfo('/bad'),b'')])
 def test_control(self):
  with self.assertRaises(RuntimeError):self.package([(tarfile.TarInfo('.github/bad'),b'')])
 def test_special(self):
  m=tarfile.TarInfo('assets/x');m.type=tarfile.FIFOTYPE
  with self.assertRaises(RuntimeError):self.package([(m,b'')])
 def test_member_limit(self):
  with self.assertRaises(RuntimeError):self.package([(tarfile.TarInfo('assets/f'+str(i)),b'') for i in range(64)])
 def test_file_byte_limit(self):
  m=tarfile.TarInfo('assets/x');m.size=2_000_001
  with self.assertRaises(RuntimeError):self.package([(m,b'x'*m.size)])
 def test_compressed_archive_rejected(self):
  import gzip
  def compress(p):p.write_bytes(gzip.compress(p.read_bytes()))
  with self.assertRaises(tarfile.ReadError):self.package(transform=compress)
 def test_exact_head(self):
  with self.assertRaises(RuntimeError):app.smoke('AK_WeatherApp','b'*40,Opener(self.package()))
 def test_wrong_repo(self):
  with self.assertRaises(RuntimeError):app.smoke('other',SHA,Opener({}))
 def test_mixed_asset(self):
  files=self.package();files['script.js']=b'old-version'
  with self.assertRaises(RuntimeError):app.smoke('AK_WeatherApp',SHA,Opener(files))
 def test_nonempty_config_even_with_matching_manifest(self):
  files=self.package();files['config.js']=app.CONFIG.replace(b'""',b'"fixture"',1);m=json.loads(files['deployment.json']);m['files']['config.js']={'bytes':len(files['config.js']),'sha256':hashlib.sha256(files['config.js']).hexdigest()};files['deployment.json']=json.dumps(m).encode()
  with self.assertRaises(RuntimeError):app.smoke('AK_WeatherApp',SHA,Opener(files))
 def test_external_reference_even_with_matching_manifest(self):
  files=self.package();files['index.html']=files['index.html'].replace(b'./script.js',b'https://external.invalid/code.js');m=json.loads(files['deployment.json']);m['files']['index.html']={'bytes':len(files['index.html']),'sha256':hashlib.sha256(files['index.html']).hexdigest()};files['deployment.json']=json.dumps(m).encode()
  with self.assertRaises(RuntimeError):app.smoke('AK_WeatherApp',SHA,Opener(files))
 def test_redirect_never_followed(self):
  with self.assertRaises(RuntimeError):app.NoRedirect().redirect_request(None,None,302,'',{},'https://external.invalid/')
 def test_encoded_traversal(self):
  for value in ['assets/%2e%2e/x','//external','assets/a?b','assets/a#b','assets/a\\b','assets//x','assets/a/b','assets/x\n']:
   with self.assertRaises(RuntimeError):app.safe_path(value)
 def test_workflow_security_structure(self):
  text=(ROOT/'.github/workflows/static-pages.yml').read_text()
  for guard in ['fetch-depth: 0','--is-shallow-repository','persist-credentials: false','Require protected native source authority','prepare-runtime.mjs','EXPECTED_ARCHIVE_SHA256','needs: [admit, build, security]','github-pages','git/ref/heads/main']:
   self.assertIn(guard,text)
  self.assertNotIn('secrets.',text);self.assertNotIn('pull_request_target',text);self.assertNotIn('node .github/maintenance/',text)
  self.assertIn('working-directory: source',text);self.assertIn('controls/tools/static-pages/source-scanner.mjs',text)
 def test_base_and_responsive_references_are_rejected(self):
  for html in ['<base href="https://example.invalid/"><script src="config.js"></script>','<img src="config.js" srcset="other.png 2x"><script src="config.js"></script>','<link href="config.js" imagesrcset="other.png 2x">']:
   with self.assertRaises(RuntimeError):app.validate_references({'index.html':html.encode(),'config.js':b''})

if __name__=='__main__':unittest.main()
