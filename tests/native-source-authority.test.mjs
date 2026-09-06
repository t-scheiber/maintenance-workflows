import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {fingerprint} from '../tools/native/native-admission.mjs';
import {validateSourceAuthority,validateSourceExecution,admitSourceTools,TOOLS} from '../tools/native/native-source-authority.mjs';
const pending=JSON.parse(fs.readFileSync(new URL('../tools/native/policy/native-scanners.pending.json',import.meta.url)));
const protectedPolicy=JSON.parse(fs.readFileSync(new URL('../tools/native/policy/source-authority.json',import.meta.url)));
const unconfigured={...structuredClone(protectedPolicy),state:'pending-hosted-proof',hostedProof:null,records:structuredClone(pending.records)};
// Entirely synthetic hosted provenance, in memory only. Never emitted as authority.
function fixture(){
 const value=structuredClone(unconfigured);value.state='protected-control-plane';
 value.hostedProof={sourceCommit:'a'.repeat(40),workflowPath:'.github/workflows/verify-native-bundle.yml',runId:'123',runAttempt:1,conclusion:'success',event:'workflow_dispatch',ref:'refs/heads/main',actor:'t-scheiber',triggeringActor:'t-scheiber',artifactId:'456',artifactDigest:'b'.repeat(64),artifactBytes:1234,summarySha256:'c'.repeat(64),verificationReceiptSha256:'d'.repeat(64)};
 for(const tool of TOOLS){const r=value.records[tool].record;r.state='protected';r.controlPlaneRepository='t-scheiber/renovate-config';r.controlPlaneCommit=value.hostedProof.sourceCommit;value.records[tool].recordSha256=fingerprint(r);}
 return value;
}
const run={repository:'t-scheiber/renovate-config',sourceRevision:'e'.repeat(40),toolsRevision:'f'.repeat(40),runId:'789',runAttempt:1,now:2000000};
const execution={repository:run.repository,network:'none',sourceMounted:false,credentialsPassed:false,sourceRevision:run.sourceRevision,toolsRevision:run.toolsRevision,runId:run.runId,runAttempt:1};
test('pending policy rejects before evidence IO and never emits production authority',()=>{
 assert.equal(unconfigured.hostedProof,null);
 assert.throws(()=>admitSourceTools('/does-not-exist',unconfigured,pending,run),{code:'SOURCE_AUTHORITY_PENDING'});
 assert.deepEqual(Object.values(unconfigured.records).map(x=>x.record.state),['pending','pending','pending']);
});
test('synthetic exact allowed transition validates in memory only',()=>{
 const receipt=validateSourceAuthority(fixture(),pending);assert.equal(receipt.hostedRunId,'123');assert.equal(receipt.authoritySha256.length,64);
});
for(const [name,mutation] of Object.entries({
 'missing hosted proof':a=>{a.hostedProof=null;},
 'failed real-run conclusion':a=>{a.hostedProof.conclusion='failure';},
 'replayed attempt':a=>{a.hostedProof.runAttempt=2;},
 'wrong actor':a=>{a.hostedProof.triggeringActor='someone-else';},
 'missing verification receipt':a=>{delete a.hostedProof.verificationReceiptSha256;},
 'wrong workflow':a=>{a.hostedProof.workflowPath='.github/workflows/untrusted.yml';},
 'unknown transport':a=>{a.transport.assetId++;},
 'missing tool':a=>{delete a.records.trivy;},
 'extra tool':a=>{a.records.extra=a.records.trivy;},
 'finding suppression':a=>{a.records.trivy.record.scan.findingSha256='0'.repeat(64);},
 'warning suppression':a=>{a.records.trivy.record.scan.vendorWarnings=0;},
 'stale-scan extension':a=>{a.records.trivy.record.scan.maxAgeMs*=2;},
 'different binary':a=>{a.records.trivy.record.binary.sha256='0'.repeat(64);},
 'modified source graph':a=>{a.records.trivy.record.evidence.graph='0'.repeat(64);},
 'different control commit':a=>{a.records.trivy.record.controlPlaneCommit='0'.repeat(40);},
 'injected permission':a=>{a.allowSource=true;}
}))test(`authority rejects ${name}`,()=>{const a=fixture();mutation(a);for(const v of Object.values(a.records))v.recordSha256=fingerprint(v.record);assert.throws(()=>validateSourceAuthority(a,pending));});
test('per-run fields bind paired source and tools revisions',()=>{
 assert.doesNotThrow(()=>validateSourceExecution(execution,run));
 for(const [key,value] of Object.entries({repository:'other/repo',network:'bridge',sourceMounted:true,credentialsPassed:true,sourceRevision:'a'.repeat(40),toolsRevision:'a'.repeat(40),runId:'123',runAttempt:2}))assert.throws(()=>validateSourceExecution({...execution,[key]:value},run),{code:'SOURCE_RUN_BINDING'});
 assert.throws(()=>validateSourceExecution(execution,{...run,repository:'other/repo'}),{code:'SOURCE_RUN'});
});
test('fixed public CLI cannot receive policy arguments, accept pending authority, or expose credential environment',()=>{
 const entry=fileURLToPath(new URL('../tools/native/source-admission.mjs',import.meta.url));
 const env={PATH:'/usr/bin:/bin',RUNNER_TEMP:'/absent',GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'t-scheiber/maintenance-workflows',GITHUB_REPOSITORY_ID:'1359178236',PUBLIC_REPOSITORY_PRIVATE:'false',GITHUB_REPOSITORY_OWNER_ID:'66697291',GITHUB_SHA:run.sourceRevision,PUBLIC_TOOLS_REF:run.toolsRevision,GITHUB_RUN_ID:run.runId,GITHUB_RUN_ATTEMPT:'1'};
 for(const [args,reason] of [[[],'FILE_|ENOENT'],[['--policy','/untrusted'],'Unexpected source admission arguments']]){
  const p=spawnSync(process.execPath,[entry,...args],{env,encoding:'utf8',timeout:3000});assert.equal(p.status,1);assert.equal(p.stdout,'');assert.match(p.stderr,new RegExp(reason));
 }
 const p=spawnSync(process.execPath,[entry],{env:{...env,GH_TOKEN:'synthetic-value-never-used'},encoding:'utf8',timeout:3000});assert.equal(p.status,1);assert.match(p.stderr,/credential-free environment/);assert.doesNotMatch(p.stderr,/synthetic-value/);
});
