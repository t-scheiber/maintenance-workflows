import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {nativeDatabase,sameDatabase,validateDatabaseMetadata,validateRuntimeExecution} from '../tools/static-pages/runtime-database.mjs';
const now=Date.parse('2026-09-06T16:00:00Z'),identity={repository:'t-scheiber/maintenance-workflows',run:'123',attempt:'1',source:'a'.repeat(40),tools:'b'.repeat(40)};
function fixture(t){
 const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'same-run-db-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 fs.mkdirSync(path.join(root,'database/db'),{recursive:true});fs.mkdirSync(path.join(root,'fresh/trivy'),{recursive:true});
 const bytes=Buffer.from('synthetic database bytes'),database={Version:2,UpdatedAt:'2026-09-06T13:00:00Z',NextUpdate:'2026-09-07T13:00:00Z',DownloadedAt:'2026-09-06T14:00:00Z'};
 fs.writeFileSync(path.join(root,'database/db/trivy.db'),bytes);fs.writeFileSync(path.join(root,'database/db/metadata.json'),JSON.stringify(database));
 const execution={status:0,network:'none',sourceMounted:false,credentialsPassed:false,repository:identity.repository,runId:identity.run,runAttempt:1,sourceRevision:identity.source,toolsRevision:identity.tools,database:{...database,sha256:createHash('sha256').update(bytes).digest('hex')}};
 fs.writeFileSync(path.join(root,'fresh/trivy/execution.json'),JSON.stringify(execution));return {root,execution,database};
}
test('same-run read-only cache must match exact admitted database bytes and metadata',t=>{
 const {root}=fixture(t),before=nativeDatabase(root,identity,{now});assert.equal(before.database.Version,2);assert.equal(sameDatabase(before,nativeDatabase(root,identity,{now})),true);
 fs.appendFileSync(path.join(root,'database/db/trivy.db'),'changed');assert.throws(()=>nativeDatabase(root,identity,{now}),/database binding/);
});
for(const [name,mutate]of Object.entries({repository:e=>e.repository='other/repo',run:e=>e.runId='124',attempt:e=>e.runAttempt=2,source:e=>e.sourceRevision='c'.repeat(40),tools:e=>e.toolsRevision='c'.repeat(40),network:e=>e.network='bridge',status:e=>e.status=1,sourceMounted:e=>e.sourceMounted=true,credentials:e=>e.credentialsPassed=true,database:e=>e.database.sha256='0'.repeat(64)}))test('database rejects changed '+name,t=>{
 const {root,execution}=fixture(t);mutate(execution);fs.writeFileSync(path.join(root,'fresh/trivy/execution.json'),JSON.stringify(execution));assert.throws(()=>nativeDatabase(root,identity,{now}));
});
test('expired database and changed metadata reject independently of inventory proof',t=>{
 const {root,database}=fixture(t);assert.throws(()=>nativeDatabase(root,identity,{now:now+86400000}));
 fs.writeFileSync(path.join(root,'database/db/metadata.json'),JSON.stringify({...database,DownloadedAt:'2026-09-06T15:00:00Z'}));assert.throws(()=>nativeDatabase(root,identity,{now}));
 assert.throws(()=>sameDatabase({sha256:'a'},{sha256:'b'}));
});
test('database and metadata symlinks or replaced parent directories reject',t=>{
 const {root}=fixture(t),db=path.join(root,'database/db/trivy.db');fs.renameSync(db,db+'.original');fs.symlinkSync(db+'.original',db);assert.throws(()=>nativeDatabase(root,identity,{now}));fs.unlinkSync(db);fs.renameSync(db+'.original',db);
 const dir=path.join(root,'database/db');fs.renameSync(dir,dir+'.original');fs.symlinkSync(dir+'.original',dir);assert.throws(()=>nativeDatabase(root,identity,{now}));
});
test('fresh scan receipt binds report creation time and retains database freshness checks',()=>{
 const database={Version:2,UpdatedAt:'2026-09-06T13:00:00Z',NextUpdate:'2026-09-07T13:00:00Z',DownloadedAt:'2026-09-06T14:00:00Z',sha256:'a'.repeat(64)};
 const scan={network:'none',cacheReadOnly:true,database,metadataSha256:'b'.repeat(64),startedAt:'2026-09-06T15:59:00Z',finishedAt:'2026-09-06T15:59:30Z'},report={CreatedAt:'2026-09-06T15:59:15Z'};
 assert.equal(validateRuntimeExecution(scan,report,{now}),true);
 for(const patch of [{network:'bridge'},{cacheReadOnly:false},{finishedAt:'2026-09-06T15:58:00Z'},{startedAt:'2026-09-06T15:30:00Z'},{metadataSha256:'bad'},{database:{...database,NextUpdate:'2026-09-06T15:00:00Z'}}])assert.throws(()=>validateRuntimeExecution({...scan,...patch},report,{now}));
 assert.throws(()=>validateRuntimeExecution(scan,{CreatedAt:'2026-09-05T15:59:15Z'},{now}));assert.throws(()=>validateRuntimeExecution(scan,report,{now:now+3600001}));
 assert.throws(()=>validateDatabaseMetadata({...database,UpdatedAt:'2026-09-06T17:00:00Z'},now));
});
