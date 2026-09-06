import re
import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('contract',ROOT/'tools/static-pages/caller-contract.py');contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)
class CallerTests(unittest.TestCase):
 def scope(self,repository='t-scheiber/AK_WeatherApp'):
  return {'GITHUB_REPOSITORY':repository,'GITHUB_REPOSITORY_ID':contract.TARGETS[repository],'GITHUB_REPOSITORY_OWNER_ID':'66697291','REPOSITORY_PRIVATE':'false','DEFAULT_BRANCH':'main','TOOLS_REF':'a'*40,'GITHUB_SHA':'b'*40,'CALLER_WORKFLOW_SHA':'b'*40,'CALLER_WORKFLOW_REF':repository+'/.github/workflows/pages.yml@refs/heads/main','GITHUB_REF':'refs/heads/main','STATIC_PAGES_ENABLED':'true','GITHUB_EVENT_NAME':'push','GITHUB_ACTOR':'renovate[bot]','GITHUB_TRIGGERING_ACTOR':'renovate[bot]'}
 def test_exact_two_callers_pass(self):
  for repo in contract.TARGETS:
   env=self.scope(repo);text=contract.caller(repo,env['TOOLS_REF']);self.assertLess(len(text.encode()),1200);self.assertEqual(contract.admit(env,text,env['GITHUB_SHA'])['tools_ref'],env['TOOLS_REF'])
 def test_all_identity_fields_are_required(self):
  for field in ['GITHUB_REPOSITORY','GITHUB_REPOSITORY_ID','GITHUB_REPOSITORY_OWNER_ID','REPOSITORY_PRIVATE','DEFAULT_BRANCH','TOOLS_REF','GITHUB_SHA','CALLER_WORKFLOW_SHA','CALLER_WORKFLOW_REF','GITHUB_REF','STATIC_PAGES_ENABLED','GITHUB_EVENT_NAME']:
   env=self.scope();text=contract.caller(env['GITHUB_REPOSITORY'],env['TOOLS_REF']);env[field]='wrong'
   with self.subTest(field=field),self.assertRaises(RuntimeError):contract.admit(env,text,'b'*40)
 def test_tools_pin_cannot_be_changed_independently(self):
  env=self.scope();text=contract.caller(env['GITHUB_REPOSITORY'],env['TOOLS_REF'])
  for altered in [text.replace('tools_ref: '+"'"+'a'*40+"'",'tools_ref: '+"'"+'c'*40+"'"),text.replace('@'+'a'*40,'@'+'c'*40),text.replace('maintenance-workflows/','other/')]:
   with self.assertRaises(RuntimeError):contract.admit(env,altered,'b'*40)
 def test_placeholder_and_mutable_refs_never_admit(self):
  for ref in ['0'*40,'main','v1','a'*39,'a'*40+'\n','A'*40]:
   env=self.scope();env['TOOLS_REF']=ref
   with self.assertRaises(RuntimeError):contract.admit(env,'ignored','b'*40)
 def test_extra_jobs_permissions_secrets_and_events_rejected(self):
  env=self.scope();text=contract.caller(env['GITHUB_REPOSITORY'],env['TOOLS_REF'])
  for altered in [text+'  attacker:\n    runs-on: ubuntu-latest\n',text.replace('contents: read','contents: write'),text+'    secrets: inherit\n',text.replace('workflow_dispatch:','pull_request_target:'),text.replace('static-pages.yml','other.yml')]:
   with self.assertRaises(RuntimeError):contract.admit(env,altered,'b'*40)
 def test_manual_run_requires_owner_and_triggering_owner(self):
  env=self.scope();env.update(GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_ACTOR='t-scheiber',GITHUB_TRIGGERING_ACTOR='t-scheiber');text=contract.caller(env['GITHUB_REPOSITORY'],env['TOOLS_REF']);contract.admit(env,text,'b'*40)
  for key in ['GITHUB_ACTOR','GITHUB_TRIGGERING_ACTOR']:
   changed={**env,key:'other'}
   with self.assertRaises(RuntimeError):contract.admit(changed,text,'b'*40)
 def test_immutable_inline_guard_is_identical_to_tested_helper(self):
  text=(ROOT/'.github/workflows/static-pages.yml').read_text();block=text.split("          python3 - <<'PY'\n",1)[1].split('          PY\n',1)[0]
  self.assertEqual(''.join(line[10:]+'\n' for line in block.splitlines()),(ROOT/'tools/static-pages/caller-contract.py').read_text())
  self.assertLess(text.index('Verify caller and paired pins'),text.index('repository: t-scheiber/maintenance-workflows'))
 def test_only_deploy_job_receives_write_permissions(self):
  text=(ROOT/'.github/workflows/static-pages.yml').read_text();jobs=text.split('\njobs:\n',1)[1]
  import re
  parts=re.split(r'^  ([a-z]+):\n',jobs,flags=re.M)
  mapping=dict(zip(parts[1::2],parts[2::2]))
  self.assertEqual(set(mapping),{'admit','build','security','package','deploy','smoke'})
  for name,block in mapping.items():
   if name!='deploy':self.assertIsNone(re.search(r'^      (?:pages|id-token|contents): write$',block,re.M))
  self.assertIn('needs: [admit, build, security]',mapping['package']);self.assertIn('needs: [admit, package]',mapping['deploy']);self.assertIn('needs: [admit, deploy]',mapping['smoke'])
  self.assertNotIn('secrets: inherit',text);self.assertNotIn('pull_request_target',text)
 def test_fresh_complete_runtime_and_current_default_are_mandatory(self):
  text=(ROOT/'.github/workflows/static-pages.yml').read_text()
  preparation=(ROOT/'tools/static-pages/prepare-runtime.mjs').read_text()
  self.assertIn("'--list-all-pkgs','--severity','UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL'",preparation)
  self.assertIn("const stderr=Buffer.from(scan.stderr??'')",preparation)
  self.assertIn('${{ runner.temp }}/runtime-node22/stderr.log',text)
  self.assertIn('${{ runner.temp }}/runtime-coverage.json',text)
  for job in ['build','security']:
   block=dict(re.findall(r'^  ([a-z]+):\n(.*?)(?=^  [a-z]+:|\Z)',text,re.M|re.S))[job]
   self.assertLess(block.index('Verify immutable scanner bundle'),block.index('Check out source as data'))
   self.assertLess(block.index('Require protected native source authority'),block.index('Check out source as data'))
   self.assertLess(block.index('Prepare and fully scan fixed source-free runtime'),block.index('Check out source as data'))
  self.assertIn("--jq '.default_branch')\" = main",text)
  helper=(ROOT/'tools/static-pages/pages-build.mjs').read_text()
  self.assertLess(helper.index("const admitted=preparedScanner('project')"),helper.index('inspectSource(root);'))
  self.assertLess(helper.index("const admitted=preparedScanner('project')"),helper.index("run(['run'"))
  self.assertIn('runtimeCoverage:coverage',helper)
if __name__=='__main__':unittest.main()
