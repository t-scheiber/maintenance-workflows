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
