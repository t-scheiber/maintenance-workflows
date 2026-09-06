import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {preparationIdentity,prepareRuntime} from '../tools/static-pages/prepare-runtime.mjs';
import {admitSourceScanners} from '../tools/native/source-admission.mjs';
import {runtimePolicy} from '../tools/static-pages/runtime-contract.mjs';
const environment=()=>({GITHUB_REPOSITORY:'t-scheiber/maintenance-workflows',GITHUB_REPOSITORY_ID:'1359178236',GITHUB_REPOSITORY_OWNER_ID:'66697291',PUBLIC_REPOSITORY_PRIVATE:'false',GITHUB_RUN_ID:'123',GITHUB_RUN_ATTEMPT:'1',GITHUB_SHA:'a'.repeat(40),PUBLIC_TOOLS_REF:'b'.repeat(40)});
test('only the three exact public personal repositories admit a runtime preparation identity',()=>{
 assert.equal(preparationIdentity(environment()).repository,'t-scheiber/maintenance-workflows');
 for(const mutate of [e=>{e.GITHUB_REPOSITORY='other/maintenance-workflows';},e=>{e.GITHUB_REPOSITORY_ID='1';},e=>{e.GITHUB_REPOSITORY_OWNER_ID='2';},e=>{e.PUBLIC_REPOSITORY_PRIVATE='true';},e=>{e.PUBLIC_TOOLS_REF='main';},e=>{e.GH_TOKEN='synthetic';},e=>{e.GITHUB_RUN_ID='1\nother';}]){const e=environment();mutate(e);assert.throws(()=>preparationIdentity(e));}
});
test('missing same-run native evidence prevents image build, scanner execution and runtime directory creation',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'public-runtime-pending-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));let calls=0;
 for(const kind of ['node22','node24','semgrep'])await assert.rejects(prepareRuntime(kind,{env:{...environment(),RUNNER_TEMP:root},nativeAdmission:directory=>admitSourceScanners(directory,{env:environment()}),execute:()=>{calls++;throw Error('must not execute');}}),/FILE_|ENOENT/);
 assert.equal(calls,0);assert.deepEqual(fs.readdirSync(root),[]);
});
test('fixed source-free policies preserve exact coverage and reject arbitrary recipe classes',()=>{
 const base=runtimePolicy('node22'),node=runtimePolicy('node24'),semgrep=runtimePolicy('semgrep');
 assert.deepEqual(node.expectedCoverage,base.expectedCoverage);assert.equal(node.nodeVersion,'v24.20.0');assert.equal(semgrep.requiredPackages.find(p=>p.name==='semgrep').version,'1.176.0');assert.equal(semgrep.expectedCoverage.reduce((n,p)=>n+p.packages,0),130);
 assert.throws(()=>runtimePolicy('custom'));assert.throws(()=>runtimePolicy('../private'));
});

test('image scan reuses native DB read-only and offline with complete package coverage',async()=>{
 const {runtimeScanArguments}=await import('../tools/static-pages/prepare-runtime.mjs');
 const args=runtimeScanArguments({containerName:'synthetic',scanner:'/native/trivy',output:'/trusted/scan',archive:'/trusted/runtime.tar.gz',cache:'/native/database'});
 for(const [key,value]of [['--network','none'],['--cache-dir','/cache'],['--cache-backend','memory'],['--memory','4g'],['--severity','UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL']])assert.equal(args[args.indexOf(key)+1],value);
 for(const value of ['--skip-db-update','--offline-scan','--list-all-pkgs','--no-progress','--read-only','/tmp:rw,nosuid,nodev,size=2g','type=bind,src=/native/database,dst=/cache,readonly'])assert.ok(args.includes(value));
 assert.ok(!args.some(value=>value.includes('docker.sock')||value.includes('TOKEN')));
});
function scanFixture(t){const directory=fs.mkdtempSync(path.join(os.tmpdir(),'runtime-diagnostics-'));t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));const output=path.join(directory,'scan'),operations=path.join(directory,'operations');fs.mkdirSync(output);fs.mkdirSync(operations);return {directory,output,operations,containerName:'synthetic-container',args:['run','--name','synthetic-container'],childEnv:{PATH:'/synthetic'}};}
test('failed scanner keeps bounded raw diagnostics and report after exact container cleanup',async t=>{
 const {runRuntimeScan}=await import('../tools/static-pages/prepare-runtime.mjs'),fixture=scanFixture(t),calls=[];
 const result=runRuntimeScan({...fixture,execute(command,args){calls.push(args);if(args[0]==='run'){fs.writeFileSync(path.join(fixture.output,'report.json'),'{}');return {status:1,stderr:'FATAL synthetic scanner failure',stdout:'bounded diagnostic'};}return {status:0,stdout:'removed',stderr:''};}});
 assert.equal(result.scan.status,1);assert.deepEqual(calls[1],['rm','-f','synthetic-container']);assert.equal(fs.readFileSync(path.join(fixture.directory,'stderr.log'),'utf8'),'FATAL synthetic scanner failure');assert.equal(fs.readFileSync(path.join(fixture.directory,'report.json'),'utf8'),'{}');assert.equal(fs.readFileSync(path.join(fixture.operations,'cleanup.stdout'),'utf8'),'removed');
});
test('scanner timeout and cleanup failure cannot lose diagnostics or report success',async t=>{
 const {runRuntimeScan}=await import('../tools/static-pages/prepare-runtime.mjs'),fixture=scanFixture(t);
 fs.writeFileSync(path.join(fixture.output,'report.json'),'partial report from possibly running scanner');
 assert.throws(()=>runRuntimeScan({...fixture,execute(command,args){return args[0]==='run'?{status:null,error:Error('timeout'),stderr:'timeout evidence',stdout:''}:{status:1,stderr:'cleanup evidence'};}}),/cleanup failed/);
 assert.equal(fs.readFileSync(path.join(fixture.directory,'stderr.log'),'utf8'),'timeout evidence');assert.equal(fs.readFileSync(path.join(fixture.operations,'cleanup.stderr'),'utf8'),'cleanup evidence');
 assert.equal(fs.existsSync(path.join(fixture.directory,'report.json')),false);
});
test('untrusted report symlink rejects only after container cleanup has run',async t=>{
 const {runRuntimeScan}=await import('../tools/static-pages/prepare-runtime.mjs'),fixture=scanFixture(t);let cleaned=false;
 fs.writeFileSync(path.join(fixture.directory,'unmounted.txt'),'synthetic host data');
 assert.throws(()=>runRuntimeScan({...fixture,execute(command,args){if(args[0]==='run'){fs.symlinkSync(path.join(fixture.directory,'unmounted.txt'),path.join(fixture.output,'report.json'));return {status:0,stderr:'INFO',stdout:''};}cleaned=true;return {status:0};}}));
 assert.equal(cleaned,true);assert.equal(fs.existsSync(path.join(fixture.directory,'report.json')),false);
});
test('failed image operation records bounded stdout and stderr before rejecting',async t=>{
 const {checked}=await import('../tools/static-pages/prepare-runtime.mjs'),fixture=scanFixture(t),prefix=path.join(fixture.operations,'build');
 assert.throws(()=>checked(()=>({status:1,stdout:'build output',stderr:'build failure'}),['build'],{}, {},prefix),/operation failed/);
 assert.equal(fs.readFileSync(prefix+'.stdout','utf8'),'build output');assert.equal(fs.readFileSync(prefix+'.stderr','utf8'),'build failure');
});
test('every verification matrix job uploads fixed source-free runtime evidence even before source scanning',()=>{
 const workflow=fs.readFileSync(new URL('../.github/workflows/verification.yml',import.meta.url),'utf8');
 const diagnostics=workflow.slice(workflow.indexOf('- name: Preserve bounded source-free runtime and native diagnostics'),workflow.indexOf("if: always() && steps.scan.outputs.summary_path"));
 assert.match(diagnostics,/if: always\(\)/);assert.match(diagnostics,/name: shared-runtime-\$\{\{ matrix.scanner \}\}/);
 for(const kind of ['node24','semgrep'])for(const name of ['receipt.json','report.json','stderr.log','stdout.log','operations'])assert.ok(diagnostics.includes(`runtime-${kind}/${name}`));
 assert.ok(diagnostics.includes('native-bundle-verification/artifacts'));assert.ok(!diagnostics.includes('runtime.tar.gz'));assert.ok(!diagnostics.includes('/source'));
 const policy=workflow.slice(0,workflow.indexOf('\n  scanners:'));for(const name of ['report.json','stderr.log','stdout.log','operations'])assert.ok(policy.includes('runtime-node24/'+name));
});
