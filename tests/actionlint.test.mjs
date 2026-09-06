import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {actionlintPolicy,requirePublished,validateActionlintScan,captureWorkflows,containerArguments,readBounded,runActionlint,projectLinterOutput} from '../tools/static-pages/actionlint.mjs';
const raw=fs.readFileSync(new URL('./fixtures/actionlint-report.json',import.meta.url));
const fixture=()=>({report:Buffer.from(raw),stderr:Buffer.from('2026-09-06T14:52:26Z\tINFO\t[vuln] Vulnerability scanning is enabled\n'),status:0,binarySha256:actionlintPolicy().binary.sha256,scannerSha256:actionlintPolicy().scan.scannerSha256,startedAt:'2026-09-06T14:52:25Z',finishedAt:'2026-09-06T14:52:27Z',database:{Version:2,UpdatedAt:'2026-09-06T07:00:00Z',NextUpdate:'2026-09-07T07:00:00Z',DownloadedAt:'2026-09-06T08:00:00Z',sha256:'a'.repeat(64)},now:Date.parse('2026-09-06T14:52:28Z')});
test('actual 13-package native report matches protected exact inventory without ignoring findings',()=>{const receipt=validateActionlintScan(fixture());assert.equal(receipt.packages,13);assert.equal(receipt.vulnerabilities,0);assert.equal(receipt.warnings,0);const f=fixture();f.stderr=Buffer.from('2026-09-06T14:52:26Z\tINFO\tLoaded\tfile_path="/config/trivy.yaml"\n');assert.doesNotThrow(()=>validateActionlintScan(f));});
for(const [name,mutate]of Object.entries({
 'missing package':r=>r.Results[0].Packages.pop(),
 'substituted package':r=>r.Results[0].Packages[0].Version='v0.0.0',
 'missing full inventory':r=>delete r.Results[0].Packages,
 'duplicate package':r=>r.Results[0].Packages[1]=r.Results[0].Packages[0],
 'wrong target':r=>r.Results[0].Target='other',
 'wrong scanner':r=>r.Trivy.Version='0.74.0',
 'wrong report mode':r=>r.ArtifactType='container_image',
 'old report':r=>r.CreatedAt='2026-09-05T14:52:26Z',
 'extra target':r=>r.Results.push({}),
 'error object':r=>r.Errors=[{message:'synthetic'}],
 'unknown vulnerability':r=>r.Results[0].Vulnerabilities=[{Severity:'UNKNOWN',VulnerabilityID:'SYNTHETIC'}],
 'low vulnerability retained and blocks':r=>r.Results[0].Vulnerabilities=[{Severity:'LOW',VulnerabilityID:'SYNTHETIC'}],
 'malformed finding':r=>r.Results[0].Vulnerabilities={},
}))test('fresh native scan rejects '+name,()=>{const f=fixture(),r=JSON.parse(f.report);mutate(r);f.report=Buffer.from(JSON.stringify(r));assert.throws(()=>validateActionlintScan(f));});
for(const [name,mutate]of Object.entries({
 'wrong binary':f=>f.binarySha256='0'.repeat(64),
 'wrong scanner bytes':f=>f.scannerSha256='0'.repeat(64),
 'scanner failure':f=>f.status=1,
 'stale execution':f=>f.now+=600000,
 'expired database':f=>f.database.NextUpdate='2026-09-06T14:00:00Z',
 'missing metadata':f=>delete f.database.DownloadedAt,
 'vendor warning':f=>f.stderr=Buffer.from('2026-09-06T14:52:26Z\tWARN\tUsing severities from other vendors\n'),
 'missing detail info':f=>f.stderr=Buffer.from('2026-09-06T14:52:26Z\tINFO\tMissing vulnerability details\n'),
 'unstructured stderr':f=>f.stderr=Buffer.from('unexpected diagnostic'),
}))test('fresh execution rejects '+name,()=>{const f=fixture();mutate(f);assert.throws(()=>validateActionlintScan(f));});
test('pending publication cannot reach installation and missing native authority stops earlier',()=>{
 assert.throws(()=>requirePublished({...actionlintPolicy(),state:'pending-publication',assetId:null}),/PUBLICATION_PENDING/);
 assert.throws(()=>requirePublished({...actionlintPolicy(),assetId:547382487}));assert.throws(()=>requirePublished({...actionlintPolicy(),immutable:false}));
 let calls=0;assert.throws(()=>runActionlint({admit:()=>{throw Error('fresh source authority unavailable');},execute:()=>calls++}),/fresh source authority unavailable/);assert.equal(calls,0);
});
test('scanner and linter boundaries are nonroot readonly offline with no inherited environment',()=>{for(const entry of ['/scanner','/actionlint']){const a=containerArguments('sha256:'+'a'.repeat(64),entry,[]);for(const [k,v]of [['--network','none'],['--user','1000:1000'],['--platform','linux/amd64'],['--entrypoint',entry]])assert.equal(a[a.indexOf(k)+1],v);assert.ok(a.includes('--read-only'));assert.ok(a.includes('--cap-drop'));assert.deepEqual(a.filter((_,i)=>a[i-1]==='--env'),['HOME=/tmp']);}assert.throws(()=>containerArguments('mutable:tag','/actionlint',[]));assert.throws(()=>containerArguments('sha256:'+'a'.repeat(64),'/bin/sh',[]));});
test('captures only YAML bytes; later source mutation cannot change the linter input',t=>{const root=fs.mkdtempSync(path.join(os.tmpdir(),'workflow-capture-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));const src=path.join(root,'source'),dir=path.join(src,'.github/workflows');fs.mkdirSync(dir,{recursive:true});fs.writeFileSync(path.join(dir,'ci.yml'),'name: reviewed\n');fs.writeFileSync(path.join(src,'private.txt'),'synthetic unrelated data');const dest=path.join(root,'captured'),files=captureWorkflows(src,dest);fs.writeFileSync(path.join(dir,'ci.yml'),'changed');assert.equal(files.length,1);assert.equal(fs.readFileSync(path.join(dest,'ci.yml'),'utf8'),'name: reviewed\n');assert.deepEqual(fs.readdirSync(dest),['ci.yml']);});
test('workflow symlinks and missing input reject before linter invocation',t=>{const root=fs.mkdtempSync(path.join(os.tmpdir(),'workflow-link-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));fs.mkdirSync(path.join(root,'.github/workflows'),{recursive:true});fs.symlinkSync('/nonexistent',path.join(root,'.github/workflows/bad.yml'));assert.throws(()=>captureWorkflows(root,path.join(root,'output')));assert.throws(()=>readBounded(path.join(root,'.github/workflows/bad.yml'),100));});

test('credential-like diagnostic content is withheld and cannot qualify as successful output',()=>{const secret='gh'+'p_synthetic';const result=projectLinterOutput('workflow '+secret,'');assert.equal(result.safe,false);assert.doesNotMatch(JSON.stringify(result),new RegExp(secret));assert.deepEqual(projectLinterOutput('ordinary error',''),{safe:true,stdout:'ordinary error',stderr:''});});
